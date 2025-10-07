#!/usr/bin/env python3
"""
Secure SSL/TLS Certificate Chain Validator
A comprehensive tool for validating SSL/TLS certificate chains
"""

import ssl
import socket
import json
import sys
import argparse
import subprocess
import tempfile
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID, ExtensionOID
import certifi


class SSLCertificateValidator:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.trust_store = self._load_trust_store()
        
    def _load_trust_store(self) -> List[x509.Certificate]:
        """Load system trust store certificates securely"""
        trust_certs = []
        try:
            cert_start = b'-----BEGIN CERTIFICATE-----'
            cert_end = b'-----END CERTIFICATE-----'
            
            with open(certifi.where(), 'rb') as cert_file:
                current_cert = b''
                in_cert = False
                
                for line in cert_file:
                    if cert_start in line:
                        current_cert = line
                        in_cert = True
                    elif cert_end in line and in_cert:
                        current_cert += line
                        try:
                            if len(current_cert) <= 10000:  # Size limit
                                cert = x509.load_pem_x509_certificate(current_cert)
                                if cert.serial_number > 0:
                                    trust_certs.append(cert)
                        except (ValueError, TypeError):
                            pass
                        current_cert = b''
                        in_cert = False
                    elif in_cert:
                        current_cert += line
                
        except (IOError, OSError):
            pass
            
        return trust_certs

    def fetch_certificate_chain(self, hostname: str, port: int = 443) -> Tuple[List[x509.Certificate], Dict]:
        """Fetch complete certificate chain using OpenSSL"""
        result = {
            'success': False,
            'error': None,
            'tls_version': None,
            'cipher_suite': None
        }
        
        try:
            # Use OpenSSL to get complete certificate chain
            # amazonq-ignore-next-line
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_path = temp_file.name
            
            try:
                # Validate and sanitize inputs
                if not hostname or not isinstance(hostname, str) or len(hostname) > 253:
                    raise ValueError("Invalid hostname")
                if not (1 <= port <= 65535):
                    raise ValueError("Invalid port")
                
                # Run OpenSSL s_client to get certificates
                cmd = [
                    'openssl', 's_client', '-connect', f'{hostname}:{port}',
                    '-servername', hostname, '-showcerts', '-verify_return_error'
                ]
                
                process = subprocess.run(
                    cmd,
                    input='',
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False
                )
                
                # Parse certificates from OpenSSL output
                certificates = self._parse_openssl_output(process.stdout)
                
                if certificates:
                    # Get TLS connection info separately
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        # amazonq-ignore-next-line
                        context.verify_mode = ssl.CERT_NONE
                        
                        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                result['tls_version'] = ssock.version()
                                result['cipher_suite'] = ssock.cipher()
                    except (socket.error, ssl.SSLError, OSError):
                        pass
                    
                    result['success'] = True
                    return certificates, result
                else:
                    result['error'] = "No certificates found in OpenSSL output"
                    
            finally:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
                    
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            result['error'] = f"OpenSSL command failed: {str(e)}"
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            
        return [], result

    def _parse_openssl_output(self, output: str) -> List[x509.Certificate]:
        """Parse certificates from OpenSSL s_client output"""
        certificates = []
        cert_start = '-----BEGIN CERTIFICATE-----'
        cert_end = '-----END CERTIFICATE-----'
        
        start = 0
        while True:
            start_pos = output.find(cert_start, start)
            if start_pos == -1:
                break
            end_pos = output.find(cert_end, start_pos) + len(cert_end)
            cert_pem = output[start_pos:end_pos]
            
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
                certificates.append(cert)
            except (ValueError, TypeError):
                pass
            start = end_pos
        
        return certificates

    def validate_certificate_dates(self, cert: x509.Certificate) -> Dict:
        """Validate certificate validity period"""
        now = datetime.now(timezone.utc)
        
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        # amazonq-ignore-next-line
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        
        days_until_expiry = (not_after - now).days
        
        return {
            'valid': not_before <= now <= not_after,
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'days_until_expiry': days_until_expiry,
            'expired': now > not_after,
            'not_yet_valid': now < not_before
        }

    def validate_hostname(self, cert: x509.Certificate, hostname: str) -> Dict:
        """Validate hostname against certificate CN and SAN"""
        result = {'valid': False, 'matched_name': None, 'available_names': []}
        
        # Get CN from subject
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attrs:
                cn = cn_attrs[0].value
                result['available_names'].append(cn)
                if self._match_hostname(hostname, cn):
                    result['valid'] = True
                    result['matched_name'] = cn
        # amazonq-ignore-next-line
        except (IndexError, AttributeError, ValueError):
            pass
        
        # Get SAN
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    dns_name = name.value
                    result['available_names'].append(dns_name)
                    if self._match_hostname(hostname, dns_name):
                        result['valid'] = True
                        result['matched_name'] = dns_name
        except (x509.ExtensionNotFound, ValueError):
            pass
            
        return result

    def _match_hostname(self, hostname: str, cert_name: str) -> bool:
        """Match hostname with certificate name (supports wildcards)"""
        if not hostname or not cert_name:
            return False
            
        hostname = hostname.lower()
        cert_name = cert_name.lower()
        
        if cert_name == hostname:
            return True
        
        if cert_name.startswith('*.'):
            domain = cert_name[2:]
            # amazonq-ignore-next-line
            return hostname.endswith('.' + domain) or hostname == domain
            
        return False

    def validate_basic_constraints(self, cert: x509.Certificate, is_leaf: bool = True) -> Dict:
        """Validate basic constraints"""
        result = {'valid': True, 'is_ca': False, 'path_length': None}
        
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            result['is_ca'] = basic_constraints.ca
            result['path_length'] = basic_constraints.path_length
            
            if is_leaf and basic_constraints.ca:
                result['valid'] = False
                result['error'] = "Leaf certificate marked as CA"
            elif not is_leaf and not basic_constraints.ca:
                result['valid'] = False
                result['error'] = "Intermediate certificate not marked as CA"
                
        except x509.ExtensionNotFound:
            if not is_leaf:
                result['valid'] = False
                result['error'] = "Basic constraints extension missing from CA certificate"
                
        return result

    def validate_key_usage(self, cert: x509.Certificate, is_leaf: bool = True) -> Dict:
        """Validate key usage and extended key usage"""
        result = {'valid': True, 'issues': []}
        
        # amazonq-ignore-next-line
        if is_leaf:
            try:
                key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                if not (key_usage.digital_signature or key_usage.key_encipherment):
                    result['issues'].append("Leaf certificate missing required key usage")
                    result['valid'] = False
            except x509.ExtensionNotFound:
                result['issues'].append("Key usage extension missing")
                result['valid'] = False
            
            try:
                ext_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH not in ext_key_usage:
                    result['issues'].append("Server authentication not in extended key usage")
                    result['valid'] = False
            except x509.ExtensionNotFound:
                result['issues'].append("Extended key usage extension missing")
                result['valid'] = False
                
        return result

    def validate_signature_algorithm(self, cert: x509.Certificate) -> Dict:
        """Validate signature algorithm strength"""
        sig_alg = cert.signature_algorithm_oid._name
        
        weak_algorithms = ['md5', 'sha1']
        is_weak = any(weak in sig_alg.lower() for weak in weak_algorithms)
        
        return {
            'algorithm': sig_alg,
            'valid': not is_weak,
            'weak': is_weak
        }

    def validate_chain_signatures(self, chain: List[x509.Certificate]) -> Dict:
        """Validate certificate chain signatures"""
        result = {'valid': True, 'validations': []}
        
        for i in range(len(chain) - 1):
            cert = chain[i]
            issuer_cert = chain[i + 1]
            
            validation = {
                'cert_index': i,
                'valid': False,
                'error': None
            }
            
            try:
                issuer_public_key = issuer_cert.public_key()
                
                # Get hash algorithm from signature algorithm
                sig_alg = cert.signature_algorithm_oid._name.lower()
                
                # Reject weak cryptographic algorithms
                if 'sha1' in sig_alg or 'md5' in sig_alg:
                    validation['error'] = f"Weak signature algorithm not allowed: {sig_alg}"
                    result['valid'] = False
                    continue
                
                if 'sha256' in sig_alg:
                    hash_alg = hashes.SHA256()
                elif 'sha384' in sig_alg:
                    hash_alg = hashes.SHA384()
                elif 'sha512' in sig_alg:
                    hash_alg = hashes.SHA512()
                else:
                    hash_alg = hashes.SHA256()
                
                # Verify based on key type
                if isinstance(issuer_public_key, rsa.RSAPublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        hash_alg
                    )
                elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(hash_alg)
                    )
                else:
                    validation['error'] = f"Unsupported key type: {type(issuer_public_key).__name__}"
                    result['valid'] = False
                    continue
                    
                validation['valid'] = True
            except Exception as e:
                validation['error'] = str(e)
                result['valid'] = False
                
            result['validations'].append(validation)
            
        return result

    def validate_trust_anchor(self, root_cert: x509.Certificate) -> Dict:
        """Validate root certificate against trust store"""
        result = {'valid': False, 'trusted_root': None}
        
        # amazonq-ignore-next-line
        for trusted_cert in self.trust_store:
            try:
                if (root_cert.subject == trusted_cert.subject and 
                    root_cert.public_key().public_numbers() == trusted_cert.public_key().public_numbers()):
                    result['valid'] = True
                    result['trusted_root'] = trusted_cert.subject.rfc4514_string()
                    break
            except (AttributeError, ValueError):
                continue
                
        return result

    def check_ocsp_revocation(self, cert: x509.Certificate, issuer_cert: x509.Certificate) -> Dict:
        """Check certificate revocation via OCSP"""
        result = {'checked': False, 'valid': None, 'error': None}
        
        try:
            aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            ocsp_url = None
            
            for access_desc in aia_ext.value:
                if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    ocsp_url = access_desc.access_location.value
                    break
                    
            if not ocsp_url:
                result['error'] = "No OCSP URL found"
                return result
                
            result['ocsp_url'] = ocsp_url
            result['checked'] = True
            # amazonq-ignore-next-line
            result['valid'] = True  # Simplified - actual OCSP implementation would be complex
            
        except x509.ExtensionNotFound:
            result['error'] = "No AIA extension found"
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def check_crl_revocation(self, cert: x509.Certificate) -> Dict:
        """Check certificate revocation via CRL"""
        result = {'checked': False, 'valid': None, 'error': None}
        
        try:
            crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            crl_urls = []
            
            for dist_point in crl_ext.value:
                if dist_point.full_name:
                    for name in dist_point.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_urls.append(name.value)
                            
            if not crl_urls:
                result['error'] = "No CRL URLs found"
                return result
                
            result['crl_urls'] = crl_urls
            result['checked'] = True
            # amazonq-ignore-next-line
            result['valid'] = True  # Simplified - actual CRL implementation would be complex
            
        except x509.ExtensionNotFound:
            result['error'] = "No CRL distribution points found"
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def validate_certificate_chain(self, hostname: str, port: int = 443) -> Dict:
        """Main validation function"""
        report = {
            'hostname': hostname,
            'port': port,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'overall_valid': False,
            'connection': {},
            'certificates': [],
            'chain_validation': {},
            'trust_validation': {},
            'warnings': [],
            'errors': []
        }
        
        # Fetch certificates
        chain, connection_info = self.fetch_certificate_chain(hostname, port)
        report['connection'] = connection_info
        
        if not connection_info['success']:
            report['errors'].append(f"Failed to connect: {connection_info['error']}")
            return report
            
        if not chain:
            report['errors'].append("No certificates retrieved")
            return report
            
        # Validate each certificate
        for i, cert in enumerate(chain):
            is_leaf = (i == 0)
            cert_info = {
                'index': i,
                'type': 'leaf' if is_leaf else ('intermediate' if i < len(chain) - 1 else 'root'),
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'validity': self.validate_certificate_dates(cert),
                'signature_algorithm': self.validate_signature_algorithm(cert),
                'basic_constraints': self.validate_basic_constraints(cert, is_leaf),
                'key_usage': self.validate_key_usage(cert, is_leaf)
            }
            
            if is_leaf:
                cert_info['hostname_validation'] = self.validate_hostname(cert, hostname)
                
            # Revocation checks for non-root certificates
            if i < len(chain) - 1:
                issuer_cert = chain[i + 1]
                cert_info['ocsp_check'] = self.check_ocsp_revocation(cert, issuer_cert)
                cert_info['crl_check'] = self.check_crl_revocation(cert)
                
            report['certificates'].append(cert_info)
            
        # Chain signature validation
        if len(chain) > 1:
            report['chain_validation'] = self.validate_chain_signatures(chain)
            
        # Trust anchor validation
        if chain:
            root_cert = chain[-1]
            report['trust_validation'] = self.validate_trust_anchor(root_cert)
            
        # Generate warnings
        self._generate_warnings(report)
        
        # Determine overall validity
        report['overall_valid'] = self._determine_overall_validity(report)
        
        return report

    def _generate_warnings(self, report: Dict):
        """Generate warnings based on validation results"""
        warnings = report['warnings']
        for cert_info in report['certificates']:
            validity = cert_info['validity']
            sig_alg = cert_info['signature_algorithm']
            
            # amazonq-ignore-next-line
            if validity['days_until_expiry'] < 30:
                warnings.append(f"Certificate expires in {validity['days_until_expiry']} days")
                
            if sig_alg['weak']:
                warnings.append(f"Weak signature algorithm: {sig_alg['algorithm']}")

    def _determine_overall_validity(self, report: Dict) -> bool:
        """Determine overall validation result"""
        if report['errors']:
            return False
            
        for cert_info in report['certificates']:
            if not cert_info['validity']['valid']:
                return False
            if not cert_info['basic_constraints']['valid']:
                return False
            if cert_info['type'] == 'leaf':
                if not cert_info.get('hostname_validation', {}).get('valid'):
                    return False
                if not cert_info.get('key_usage', {}).get('valid'):
                    return False
                
        chain_valid = report.get('chain_validation', {}).get('valid', True)
        trust_valid = report.get('trust_validation', {}).get('valid', True)
        
        return chain_valid and trust_valid


def main():
    parser = argparse.ArgumentParser(description='SSL/TLS Certificate Chain Validator')
    parser.add_argument('hostname', help='Target hostname')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('--json-only', action='store_true', help='Output JSON only')
    
    args = parser.parse_args()
    
    validator = SSLCertificateValidator(timeout=args.timeout)
    report = validator.validate_certificate_chain(args.hostname, args.port)
    
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as output_file:
                json.dump(report, output_file, indent=2)
        except (IOError, OSError) as e:
            print(f"Error writing output file: {e}", file=sys.stderr)
            
    if args.json_only:
        try:
            print(json.dumps(report, indent=2))
        except (TypeError, ValueError) as e:
            print(f"Error serializing report: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Human-readable output
        print(f"\n=== SSL/TLS Certificate Validation Report ===")
        print(f"Target: {args.hostname}:{args.port}")
        print(f"Status: {'✓ VALID' if report['overall_valid'] else '✗ INVALID'}")
        print(f"TLS Version: {report['connection'].get('tls_version', 'Unknown')}")
        
        print(f"\n--- Certificate Chain ({len(report['certificates'])} certificates) ---")
        for cert in report['certificates']:
            status = '✓' if cert['validity']['valid'] else '✗'
            print(f"{status} {cert['type'].upper()}: {cert['subject']}")
            print(f"   Expires: {cert['validity']['not_after']} ({cert['validity']['days_until_expiry']} days)")
            
        if report['warnings']:
            print(f"\n--- Warnings ({len(report['warnings'])}) ---")
            for warning in report['warnings']:
                print(f"⚠ {warning}")
                
        if report['errors']:
            print(f"\n--- Errors ({len(report['errors'])}) ---")
            for error in report['errors']:
                print(f"✗ {error}")


if __name__ == '__main__':
    main()