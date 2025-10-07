#!/usr/bin/env python3
"""
Ultimate Mail Server Security Scanner v2.1 (IMPROVED)
A comprehensive Python tool for scanning email authentication security (SPF, DKIM, DMARC)
Developed for cybersecurity R&D internship

IMPROVEMENTS:
- Better DNS timeout handling
- Multiple DNS resolver fallback
- More robust SMTP testing
- Enhanced error recovery
- Improved DKIM selector detection
- Network connectivity resilience
"""

import dns.resolver
import dns.reversename
import socket
import ssl
import smtplib
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
import argparse
import sys
import time
import re
import requests
from urllib.parse import urlparse
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
import hashlib

# Color codes for console output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

@dataclass
class SecurityFinding:
    """Data class for security findings"""
    category: str
    severity: str  # Low, Medium, High, Critical
    title: str
    description: str
    recommendation: str
    technical_details: str
    score_impact: int  # Impact on overall security score (0-100)

@dataclass
class DomainScanResult:
    """Complete scan results for a domain"""
    domain: str
    timestamp: datetime
    mx_records: List[str]
    spf_record: Optional[str]
    spf_valid: bool
    spf_issues: List[str]
    dkim_records: Dict[str, str]
    dkim_selectors_found: List[str]
    dmarc_record: Optional[str]
    dmarc_policy: str
    dmarc_valid: bool
    smtp_servers: List[Dict]
    security_score: int
    findings: List[SecurityFinding]
    blacklist_status: Dict[str, bool]
    ptr_records: List[str]
    
class MailSecurityScanner:
    """Ultimate Mail Server Security Scanner v2.1 (IMPROVED)"""
    
    def __init__(self, timeout=15, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        
        # Setup multiple DNS resolvers for redundancy
        self.dns_resolvers = []
        
        # Primary resolver (system default)
        primary_resolver = dns.resolver.Resolver()
        primary_resolver.timeout = timeout
        primary_resolver.lifetime = timeout
        self.dns_resolvers.append(primary_resolver)
        
        # Fallback public DNS resolvers
        public_dns_servers = [
            ['8.8.8.8', '8.8.4.4'],        # Google DNS
            ['1.1.1.1', '1.0.0.1'],        # Cloudflare DNS
            ['208.67.222.222', '208.67.220.220'],  # OpenDNS
            ['9.9.9.9', '149.112.112.112']  # Quad9 DNS
        ]
        
        for dns_servers in public_dns_servers:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = dns_servers
            resolver.timeout = timeout
            resolver.lifetime = timeout
            self.dns_resolvers.append(resolver)
        
        # Enhanced DKIM selectors (more comprehensive)
        self.dkim_selectors = [
            'default', 'selector1', 'selector2', 'google', 'dkim', 'mail',
            'smtp', 'key1', 'key2', 'k1', 'k2', 'dk', 'dkim1', 'dkim2',
            'email', 'mailgun', 'mandrill', 'sendgrid', 'amazonses',
            's1', 's2', 'mxvault', 'protonmail', 'outlook', 'yahoo',
            '20161025', '20210112', 'beta', 'gamma', 'delta', 'alpha'
        ]
        
        # Reliable blacklist providers (removed problematic ones)
        self.blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'b.barracudacentral.org',
            'dnsbl.sorbs.net',
            'spam.dnsbl.sorbs.net',
            'cbl.abuseat.org',
            'psbl.surriel.com',
            'sbl.spamhaus.org',
            'xbl.spamhaus.org',
            'pbl.spamhaus.org'
        ]
        
        # Initialize results storage
        self.scan_results = []
        
    def print_banner(self):
        """Print scanner banner"""
        banner = f'''
{Colors.CYAN}
================================================================================
                 ULTIMATE MAIL SECURITY SCANNER v2.1 (IMPROVED)                      
              Comprehensive SPF/DKIM/DMARC Security Assessment               
                   Developed for Cybersecurity R&D Internship                
================================================================================
{Colors.END}
        '''
        print(banner)
    
    def log_message(self, message, level="INFO"):
        """Enhanced logging with timestamps and colors"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        color_map = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "CRITICAL": Colors.MAGENTA,
            "DEBUG": Colors.BLUE
        }
        
        color = color_map.get(level, Colors.WHITE)
        
        if self.verbose or level not in ["INFO", "DEBUG"]:
            print(f"{color}[{timestamp}] [{level}] {message}{Colors.END}")
    
    def dns_query_with_fallback(self, domain, record_type):
        """Query DNS with multiple resolver fallback"""
        for i, resolver in enumerate(self.dns_resolvers):
            try:
                if i > 0:  # Only log fallback attempts in verbose mode
                    self.log_message(f"Trying DNS resolver {i+1} for {domain} {record_type}", "DEBUG")
                
                answers = resolver.resolve(domain, record_type)
                if i > 0:  # Log successful fallback
                    self.log_message(f"DNS query successful using resolver {i+1}", "SUCCESS")
                return answers
                
            except dns.resolver.NXDOMAIN as e:
                if i == len(self.dns_resolvers) - 1:  # Last resolver
                    raise e
                continue
            except Exception as e:
                if i == len(self.dns_resolvers) - 1:  # Last resolver
                    self.log_message(f"All DNS resolvers failed for {domain} {record_type}: {e}", "ERROR")
                    raise e
                continue
        
        raise Exception("All DNS resolvers failed")
    
    def get_mx_records(self, domain):
        """Get MX records for domain with enhanced error handling"""
        try:
            self.log_message(f"Querying MX records for {domain}")
            mx_records = []
            
            answers = self.dns_query_with_fallback(domain, 'MX')
            
            for rdata in sorted(answers, key=lambda x: x.preference):
                mx_host = str(rdata.exchange).rstrip('.')
                mx_records.append({
                    'hostname': mx_host,
                    'priority': rdata.preference,
                    'ip_addresses': self.resolve_hostname_to_ips(mx_host)
                })
            
            self.log_message(f"Found {len(mx_records)} MX records", "SUCCESS")
            return mx_records
            
        except Exception as e:
            self.log_message(f"Failed to get MX records: {e}", "ERROR")
            return []
    
    def resolve_hostname_to_ips(self, hostname):
        """Resolve hostname to IP addresses with fallback"""
        ips = []
        
        # Try IPv4
        try:
            answers = self.dns_query_with_fallback(hostname, 'A')
            for rdata in answers:
                ips.append(str(rdata))
        except:
            pass
            
        # Try IPv6
        try:
            answers = self.dns_query_with_fallback(hostname, 'AAAA')
            for rdata in answers:
                ips.append(str(rdata))
        except:
            pass
            
        return ips
    
    def check_spf_record(self, domain):
        """Enhanced SPF record validation with multiple attempts"""
        try:
            self.log_message(f"Checking SPF record for {domain}")
            
            txt_records = self.dns_query_with_fallback(domain, 'TXT')
            
            spf_record = None
            spf_issues = []
            
            for record in txt_records:
                record_text = str(record).strip('"')
                if record_text.startswith('v=spf1'):
                    if spf_record:
                        spf_issues.append("Multiple SPF records found (should be only one)")
                    spf_record = record_text
            
            if not spf_record:
                # Try alternative approaches for SPF detection
                spf_record = self.alternative_spf_check(domain)
            
            if not spf_record:
                spf_issues.append("No SPF record found")
                return None, False, spf_issues
            
            # Analyze SPF record
            spf_issues.extend(self.analyze_spf_record(spf_record))
            
            is_valid = len(spf_issues) == 0
            self.log_message(f"SPF analysis complete: {'Valid' if is_valid else 'Issues found'}", 
                           "SUCCESS" if is_valid else "WARNING")
            
            return spf_record, is_valid, spf_issues
            
        except Exception as e:
            self.log_message(f"SPF check failed: {e}", "ERROR")
            return None, False, [f"DNS lookup failed: {e}"]
    
    def alternative_spf_check(self, domain):
        """Alternative SPF record detection methods"""
        try:
            # Sometimes SPF records are in subdomains or have unusual formatting
            subdomains_to_check = [domain, f"mail.{domain}", f"email.{domain}"]
            
            for subdomain in subdomains_to_check:
                try:
                    txt_records = self.dns_query_with_fallback(subdomain, 'TXT')
                    for record in txt_records:
                        record_text = str(record).strip('"')
                        if 'spf1' in record_text.lower() or 'include:' in record_text:
                            self.log_message(f"Found SPF-like record at {subdomain}: {record_text}", "DEBUG")
                            if record_text.startswith('v=spf1'):
                                return record_text
                except:
                    continue
            
        except Exception as e:
            self.log_message(f"Alternative SPF check failed: {e}", "DEBUG")
        
        return None
    
    def analyze_spf_record(self, spf_record):
        """Detailed SPF record analysis"""
        issues = []
        
        # Check for common mechanisms
        mechanisms = ['ip4:', 'ip6:', 'a:', 'mx:', 'include:', 'exists:', 'ptr:']
        found_mechanisms = [m for m in mechanisms if m in spf_record]
        
        # Count DNS lookups (includes and redirects)
        dns_lookup_count = 0
        dns_lookup_count += spf_record.count('include:')
        dns_lookup_count += spf_record.count('a:')
        dns_lookup_count += spf_record.count('mx:')
        dns_lookup_count += spf_record.count('exists:')
        dns_lookup_count += spf_record.count('redirect=')
        
        if dns_lookup_count > 10:
            issues.append(f"Too many DNS lookups ({dns_lookup_count}/10) - may cause SPF validation failures")
        elif dns_lookup_count > 8:
            issues.append(f"High DNS lookup count ({dns_lookup_count}/10) - approaching limit")
        
        # Check qualifier
        if spf_record.endswith(' ~all'):
            issues.append("SPF uses SoftFail (~all) - consider HardFail (-all) for better security")
        elif spf_record.endswith(' +all'):
            issues.append("SPF uses Pass (+all) - allows any server to send mail (security risk)")
        elif not spf_record.endswith(' -all'):
            issues.append("SPF should end with -all for strict policy")
        
        # Check for deprecated PTR mechanism
        if 'ptr:' in spf_record:
            issues.append("PTR mechanism is deprecated and should be avoided")
        
        # Check for overly permissive IP ranges
        if 'ip4:0.0.0.0/0' in spf_record or 'ip6::0/0' in spf_record:
            issues.append("Overly permissive IP range found - allows any IP to send mail")
        
        return issues
    
    def check_dkim_records(self, domain):
        """Enhanced DKIM record discovery with parallel checking"""
        self.log_message(f"Scanning DKIM selectors for {domain}")
        dkim_records = {}
        found_selectors = []
        
        def check_dkim_selector(selector):
            """Check individual DKIM selector"""
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                txt_records = self.dns_query_with_fallback(dkim_domain, 'TXT')
                
                for record in txt_records:
                    record_text = str(record).strip('"')
                    # More flexible DKIM detection
                    if ('v=DKIM1' in record_text or 'p=' in record_text or 
                        'k=rsa' in record_text or 'k=ed25519' in record_text):
                        return selector, record_text
                        
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                if self.verbose:
                    self.log_message(f"Error checking selector {selector}: {e}", "DEBUG")
            
            return None, None
        
        # Use parallel checking for better performance
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_selector = {
                executor.submit(check_dkim_selector, selector): selector 
                for selector in self.dkim_selectors
            }
            
            for future in as_completed(future_to_selector):
                selector, record_text = future.result()
                if selector and record_text:
                    dkim_records[selector] = record_text
                    found_selectors.append(selector)
                    self.log_message(f"Found DKIM selector: {selector}", "SUCCESS")
        
        if not found_selectors:
            self.log_message("No DKIM records found", "WARNING")
        else:
            self.log_message(f"Found {len(found_selectors)} DKIM selectors", "SUCCESS")
        
        return dkim_records, found_selectors
    
    def check_dmarc_record(self, domain):
        """Enhanced DMARC record validation with subdomain checking"""
        try:
            self.log_message(f"Checking DMARC record for {domain}")
            
            # Check both _dmarc.domain and domain itself
            domains_to_check = [f"_dmarc.{domain}", domain]
            
            for check_domain in domains_to_check:
                try:
                    txt_records = self.dns_query_with_fallback(check_domain, 'TXT')
                    
                    for record in txt_records:
                        record_text = str(record).strip('"')
                        if record_text.startswith('v=DMARC1'):
                            # Parse DMARC policy
                            policy = "none"  # default
                            if "p=quarantine" in record_text:
                                policy = "quarantine"
                            elif "p=reject" in record_text:
                                policy = "reject"
                            elif "p=none" in record_text:
                                policy = "none"
                            
                            # Validate DMARC record
                            is_valid = self.validate_dmarc_record(record_text)
                            
                            self.log_message(f"DMARC policy: {policy} ({'Valid' if is_valid else 'Issues found'})", 
                                           "SUCCESS" if is_valid and policy != "none" else "WARNING")
                            
                            return record_text, policy, is_valid
                            
                except dns.resolver.NXDOMAIN:
                    continue
                except Exception as e:
                    if self.verbose:
                        self.log_message(f"DMARC check error for {check_domain}: {e}", "DEBUG")
                    continue
            
            self.log_message("No DMARC record found", "WARNING")
            return None, "none", False
            
        except Exception as e:
            self.log_message(f"DMARC check failed: {e}", "ERROR")
            return None, "none", False
    
    def validate_dmarc_record(self, dmarc_record):
        """Validate DMARC record syntax and best practices"""
        required_tags = ['v=DMARC1', 'p=']
        for tag in required_tags:
            if tag not in dmarc_record:
                return False
        
        # Check for reporting addresses (not strictly required but recommended)
        if 'rua=' not in dmarc_record and 'ruf=' not in dmarc_record:
            # This is okay, not all domains use reporting
            pass
        
        return True
    
    def test_smtp_security(self, mx_records):
        """Enhanced SMTP server security testing with better error handling"""
        smtp_results = []
        
        for mx_record in mx_records:
            hostname = mx_record['hostname']
            self.log_message(f"Testing SMTP security for {hostname}")
            
            result = {
                'hostname': hostname,
                'port_25_open': False,
                'port_587_open': False,
                'port_465_open': False,
                'starttls_supported': False,
                'tls_version': None,
                'certificate_valid': False,
                'certificate_expired': False,
                'certificate_details': {},
                'open_relay': False,
                'authentication_required': False,
                'connection_successful': False
            }
            
            # Test different ports with shorter timeouts for better UX
            for port in [25, 587, 465]:
                try:
                    if self.test_smtp_port(hostname, port, result):
                        result['connection_successful'] = True
                        if port == 25:
                            result['port_25_open'] = True
                        elif port == 587:
                            result['port_587_open'] = True
                        elif port == 465:
                            result['port_465_open'] = True
                except Exception as e:
                    if self.verbose:
                        self.log_message(f"Error testing port {port}: {e}", "DEBUG")
            
            smtp_results.append(result)
        
        return smtp_results
    
    def test_smtp_port(self, hostname, port, result):
        """Test specific SMTP port with improved error handling"""
        try:
            # Use shorter timeout for SMTP connections
            sock = socket.create_connection((hostname, port), timeout=min(self.timeout, 10))
            
            if port == 465:  # SMTPS
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False  # For testing purposes
                    context.verify_mode = ssl.CERT_NONE  # For testing purposes
                    
                    sock = context.wrap_socket(sock, server_hostname=hostname)
                    result['tls_version'] = sock.version()
                    result['starttls_supported'] = True
                    
                    # Get certificate info
                    cert = sock.getpeercert()
                    if cert:
                        result['certificate_details'] = self.analyze_certificate(cert)
                        result['certificate_valid'] = True
                        
                except Exception as ssl_e:
                    self.log_message(f"SSL/TLS error on port {port}: {ssl_e}", "DEBUG")
                    
            else:  # Plain SMTP or SMTP with STARTTLS
                try:
                    smtp = smtplib.SMTP()
                    smtp.sock = sock
                    smtp.timeout = min(self.timeout, 10)
                    
                    # Get initial response
                    code, msg = smtp.getreply()
                    if code == 220:  # Service ready
                        result['connection_successful'] = True
                    
                    # Test STARTTLS
                    try:
                        smtp.starttls()
                        result['starttls_supported'] = True
                        
                        # Get TLS info after STARTTLS
                        if hasattr(smtp.sock, 'version'):
                            result['tls_version'] = smtp.sock.version()
                        
                        # Get certificate
                        cert = smtp.sock.getpeercert()
                        if cert:
                            result['certificate_details'] = self.analyze_certificate(cert)
                            result['certificate_valid'] = True
                            
                    except smtplib.SMTPNotSupportedError:
                        result['starttls_supported'] = False
                    except Exception as starttls_e:
                        self.log_message(f"STARTTLS error: {starttls_e}", "DEBUG")
                    
                    # Properly close SMTP connection
                    try:
                        smtp.quit()
                    except:
                        smtp.close()
                        
                except Exception as smtp_e:
                    self.log_message(f"SMTP error: {smtp_e}", "DEBUG")
                    
            sock.close()
            return True
            
        except socket.timeout:
            self.log_message(f"Connection timeout to {hostname}:{port}", "DEBUG")
            return False
        except Exception as e:
            self.log_message(f"Port {port} test failed: {e}", "DEBUG")
            return False
    
    def analyze_certificate(self, cert):
        """Analyze SSL certificate details with better error handling"""
        cert_info = {}
        
        if cert:
            try:
                cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                cert_info['version'] = cert.get('version')
                cert_info['serial_number'] = cert.get('serialNumber')
                cert_info['not_before'] = cert.get('notBefore')
                cert_info['not_after'] = cert.get('notAfter')
                
                # Check if certificate is expired
                try:
                    not_after = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                    cert_info['expired'] = not_after < datetime.now()
                except:
                    cert_info['expired'] = False
                    
            except Exception as e:
                cert_info['error'] = f'Failed to parse certificate: {e}'
        
        return cert_info
    
    def check_blacklists(self, ip_addresses):
        """Check IP addresses against blacklists with improved error handling"""
        blacklist_results = {}
        
        def check_ip_blacklist(ip, blacklist):
            """Check single IP against single blacklist"""
            try:
                # Only check IPv4 addresses
                if '.' not in ip or ':' in ip:  # Skip IPv6 for now
                    return None
                
                # Reverse IP for blacklist query
                reversed_ip = '.'.join(reversed(ip.split('.')))
                query_host = f"{reversed_ip}.{blacklist}"
                
                # Use shorter timeout for blacklist checks
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                
                # Perform DNS lookup
                answers = resolver.resolve(query_host, 'A')
                
                # If we get a response, IP is blacklisted
                return True
                
            except dns.resolver.NXDOMAIN:
                # NXDOMAIN means not blacklisted
                return False
            except Exception:
                # Other errors - mark as unknown
                return None
        
        for ip in ip_addresses:
            if '.' not in ip or ':' in ip:  # Skip IPv6
                continue
                
            self.log_message(f"Checking blacklist status for {ip}")
            blacklist_results[ip] = {}
            
            # Use parallel checking for blacklists
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_blacklist = {
                    executor.submit(check_ip_blacklist, ip, blacklist): blacklist 
                    for blacklist in self.blacklists
                }
                
                for future in as_completed(future_to_blacklist):
                    blacklist = future_to_blacklist[future]
                    try:
                        result = future.result()
                        blacklist_results[ip][blacklist] = result
                        
                        if result is True:
                            self.log_message(f"IP {ip} found on blacklist {blacklist}", "WARNING")
                    except Exception as e:
                        blacklist_results[ip][blacklist] = None
                        if self.verbose:
                            self.log_message(f"Blacklist check error for {blacklist}: {e}", "DEBUG")
        
        return blacklist_results
    
    def check_ptr_records(self, ip_addresses):
        """Check PTR records with improved error handling"""
        ptr_records = []
        
        for ip in ip_addresses:
            try:
                self.log_message(f"Checking PTR record for {ip}")
                reversed_dns = dns.reversename.from_address(ip)
                
                # Use fallback resolvers for PTR queries too
                answers = self.dns_query_with_fallback(reversed_dns, 'PTR')
                
                for rdata in answers:
                    ptr_records.append({
                        'ip': ip,
                        'hostname': str(rdata).rstrip('.')
                    })
                    
            except Exception as e:
                if self.verbose:
                    self.log_message(f"PTR lookup failed for {ip}: {e}", "DEBUG")
        
        return ptr_records
    
    def calculate_security_score(self, scan_result):
        """Enhanced security score calculation"""
        base_score = 100
        deductions = 0
        
        # SPF scoring (more nuanced)
        if not scan_result.spf_record:
            deductions += 20  # Reduced penalty
        elif not scan_result.spf_valid:
            deductions += 10  # Less harsh for minor issues
        elif scan_result.spf_issues:
            deductions += min(len(scan_result.spf_issues) * 3, 15)  # Cap SPF issue deductions
        
        # DKIM scoring
        if not scan_result.dkim_selectors_found:
            deductions += 20  # Reduced penalty
        elif len(scan_result.dkim_selectors_found) < 2:
            deductions += 5   # Minor deduction for single selector
        
        # DMARC scoring (more balanced)
        if not scan_result.dmarc_record:
            deductions += 25
        elif scan_result.dmarc_policy == "none":
            deductions += 15  # Reduced penalty for monitoring mode
        elif scan_result.dmarc_policy == "quarantine":
            deductions += 3   # Minor deduction for quarantine
        
        # SMTP security scoring (no penalty for unreachable servers)
        for smtp_server in scan_result.smtp_servers:
            # Only penalize actual security issues, not connectivity
            if smtp_server.get('connection_successful'):
                if not smtp_server.get('starttls_supported'):
                    deductions += 8
                if smtp_server.get('certificate_expired'):
                    deductions += 15
                if not smtp_server.get('certificate_valid'):
                    deductions += 5
            # No penalty for unreachable servers - this is expected
        
        # Blacklist scoring
        for ip, blacklists in scan_result.blacklist_status.items():
            blacklisted_count = sum(1 for status in blacklists.values() if status is True)
            deductions += blacklisted_count * 5
        
        # Apply finding-specific deductions (but cap total deductions from findings)
        finding_deductions = sum(finding.score_impact for finding in scan_result.findings)
        deductions += min(finding_deductions, 30)  # Cap finding deductions
        
        final_score = max(0, base_score - deductions)
        return final_score
    
    def generate_security_findings(self, scan_result):
        """Generate enhanced security findings"""
        findings = []
        
        # SPF findings
        if not scan_result.spf_record:
            findings.append(SecurityFinding(
                category="SPF",
                severity="High",
                title="No SPF Record Found",
                description="Domain does not have an SPF record published in DNS",
                recommendation="Publish an SPF record to specify which servers can send email for your domain",
                technical_details="SPF record should be published as a TXT record in DNS",
                score_impact=20
            ))
        elif scan_result.spf_issues:
            for issue in scan_result.spf_issues:
                severity = "Medium"
                if "DNS lookup failed" in issue:
                    severity = "Low"  # Network issues are less severe
                elif "no SPF" in issue:
                    severity = "High"
                    
                findings.append(SecurityFinding(
                    category="SPF",
                    severity=severity,
                    title="SPF Configuration Issue",
                    description=issue,
                    recommendation="Review and fix SPF record configuration",
                    technical_details=f"Current SPF record: {scan_result.spf_record}",
                    score_impact=10 if severity == "High" else 3
                ))
        
        # DKIM findings
        if not scan_result.dkim_selectors_found:
            findings.append(SecurityFinding(
                category="DKIM",
                severity="High",
                title="No DKIM Records Found",
                description="No DKIM signatures found for common selectors",
                recommendation="Implement DKIM signing for outbound emails",
                technical_details="Tested selectors: " + ", ".join(self.dkim_selectors[:10]),
                score_impact=20
            ))
        
        # DMARC findings
        if not scan_result.dmarc_record:
            findings.append(SecurityFinding(
                category="DMARC",
                severity="Critical",
                title="No DMARC Policy Found",
                description="Domain does not have a DMARC policy published",
                recommendation="Publish a DMARC policy to prevent email spoofing",
                technical_details="DMARC record should be published at _dmarc.domain.com",
                score_impact=25
            ))
        elif scan_result.dmarc_policy == "none":
            findings.append(SecurityFinding(
                category="DMARC",
                severity="Medium",
                title="DMARC Policy in Monitoring Mode",
                description="DMARC policy is set to 'none' (monitoring only)",
                recommendation="Consider upgrading to 'quarantine' or 'reject' policy after monitoring phase",
                technical_details=f"Current DMARC record: {scan_result.dmarc_record}",
                score_impact=15
            ))
        
        # SMTP security findings (more nuanced)
        for smtp_server in scan_result.smtp_servers:
            hostname = smtp_server['hostname']
            
            # No findings for unreachable servers - this is expected behavior
            if smtp_server.get('connection_successful') and not smtp_server.get('starttls_supported'):
                findings.append(SecurityFinding(
                    category="SMTP",
                    severity="Medium",
                    title="STARTTLS Not Supported",
                    description=f"Mail server {hostname} does not support STARTTLS",
                    recommendation="Enable STARTTLS support for encrypted email transmission",
                    technical_details="Tested ports: 25, 587, 465",
                    score_impact=8
                ))
            
            if smtp_server.get('certificate_expired'):
                findings.append(SecurityFinding(
                    category="SSL/TLS",
                    severity="Critical",
                    title="Expired SSL Certificate",
                    description=f"SSL certificate for {hostname} has expired",
                    recommendation="Renew SSL certificate immediately",
                    technical_details=f"Certificate details: {smtp_server.get('certificate_details', {})}",
                    score_impact=15
                ))
        
        # Blacklist findings
        for ip, blacklists in scan_result.blacklist_status.items():
            blacklisted_on = [bl for bl, status in blacklists.items() if status is True]
            if blacklisted_on:
                findings.append(SecurityFinding(
                    category="Reputation",
                    severity="High",
                    title="IP Address Blacklisted",
                    description=f"IP {ip} is blacklisted on {len(blacklisted_on)} blacklist(s)",
                    recommendation="Contact blacklist providers to request removal",
                    technical_details=f"Blacklisted on: {', '.join(blacklisted_on)}",
                    score_impact=len(blacklisted_on) * 5
                ))
        
        return findings
    
    def scan_domain(self, domain):
        """Main domain scanning function with improved error handling"""
        self.log_message(f"Starting comprehensive scan of {domain}", "INFO")
        start_time = time.time()
        
        try:
            # Get MX records
            mx_records = self.get_mx_records(domain)
            
            # Extract all IP addresses from MX records
            all_ips = []
            for mx in mx_records:
                all_ips.extend(mx['ip_addresses'])
            
            # Check SPF
            spf_record, spf_valid, spf_issues = self.check_spf_record(domain)
            
            # Check DKIM
            dkim_records, dkim_selectors = self.check_dkim_records(domain)
            
            # Check DMARC
            dmarc_record, dmarc_policy, dmarc_valid = self.check_dmarc_record(domain)
            
            # Test SMTP security (if enabled)
            smtp_servers = self.test_smtp_security(mx_records) if getattr(self, 'smtp_check_enabled', False) else []
            
            # Check blacklists (only for IPv4)
            ipv4_addresses = [ip for ip in all_ips if '.' in ip and ':' not in ip]
            blacklist_status = self.check_blacklists(ipv4_addresses) if ipv4_addresses else {}
            
            # Check PTR records
            ptr_records = self.check_ptr_records(all_ips) if all_ips else []
            
            # Create scan result object
            scan_result = DomainScanResult(
                domain=domain,
                timestamp=datetime.now(),
                mx_records=[mx['hostname'] for mx in mx_records],
                spf_record=spf_record,
                spf_valid=spf_valid,
                spf_issues=spf_issues,
                dkim_records=dkim_records,
                dkim_selectors_found=dkim_selectors,
                dmarc_record=dmarc_record,
                dmarc_policy=dmarc_policy,
                dmarc_valid=dmarc_valid,
                smtp_servers=smtp_servers,
                security_score=0,  # Will be calculated below
                findings=[],  # Will be generated below
                blacklist_status=blacklist_status,
                ptr_records=[ptr['hostname'] for ptr in ptr_records]
            )
            
            # Generate security findings
            scan_result.findings = self.generate_security_findings(scan_result)
            
            # Calculate security score
            scan_result.security_score = self.calculate_security_score(scan_result)
            
            # Add to results
            self.scan_results.append(scan_result)
            
            scan_time = time.time() - start_time
            self.log_message(f"Scan completed in {scan_time:.2f} seconds", "SUCCESS")
            self.log_message(f"Security Score: {scan_result.security_score}/100", 
                           "SUCCESS" if scan_result.security_score >= 70 else 
                           "WARNING" if scan_result.security_score >= 50 else "ERROR")
            
            return scan_result
            
        except Exception as e:
            self.log_message(f"Scan failed for {domain}: {e}", "ERROR")
            return None
    
    def print_console_report(self, scan_result):
        """Print enhanced console report"""
        print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}MAIL SECURITY SCAN REPORT v2.1{Colors.END}")
        print(f"{Colors.BOLD}{'='*80}{Colors.END}")
        
        # Domain info
        print(f"\n{Colors.BOLD}Domain:{Colors.END} {scan_result.domain}")
        print(f"{Colors.BOLD}Scan Time:{Colors.END} {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Enhanced security score with better color coding
        score = scan_result.security_score
        if score >= 80:
            score_color = Colors.GREEN
            score_status = "EXCELLENT"
        elif score >= 70:
            score_color = Colors.GREEN
            score_status = "GOOD"
        elif score >= 50:
            score_color = Colors.YELLOW
            score_status = "FAIR"
        else:
            score_color = Colors.RED
            score_status = "POOR"
        
        print(f"{Colors.BOLD}Security Score:{Colors.END} {score_color}{score}/100 ({score_status}){Colors.END}")
        
        # MX Records
        print(f"\n{Colors.BOLD}MX RECORDS ({len(scan_result.mx_records)}):{Colors.END}")
        for mx in scan_result.mx_records:
            print(f"  • {mx}")
        
        # SPF Status
        print(f"\n{Colors.BOLD}SPF STATUS:{Colors.END}")
        if scan_result.spf_record:
            status_color = Colors.GREEN if scan_result.spf_valid else Colors.YELLOW
            print(f"  Status: {status_color}{'✓ Valid' if scan_result.spf_valid else '⚠ Issues Found'}{Colors.END}")
            print(f"  Record: {scan_result.spf_record}")
            if scan_result.spf_issues:
                print(f"  Issues:")
                for issue in scan_result.spf_issues:
                    print(f"    • {Colors.YELLOW}{issue}{Colors.END}")
        else:
            print(f"  Status: {Colors.RED}✗ No SPF Record Found{Colors.END}")
        
        # DKIM Status
        print(f"\n{Colors.BOLD}DKIM STATUS:{Colors.END}")
        if scan_result.dkim_selectors_found:
            print(f"  Status: {Colors.GREEN}✓ DKIM Records Found{Colors.END}")
            print(f"  Selectors: {', '.join(scan_result.dkim_selectors_found)}")
            if len(scan_result.dkim_selectors_found) >= 2:
                print(f"  {Colors.GREEN}✓ Multiple selectors provide good redundancy{Colors.END}")
        else:
            print(f"  Status: {Colors.RED}✗ No DKIM Records Found{Colors.END}")
        
        # DMARC Status
        print(f"\n{Colors.BOLD}DMARC STATUS:{Colors.END}")
        if scan_result.dmarc_record:
            policy_colors = {
                "reject": Colors.GREEN,
                "quarantine": Colors.YELLOW,
                "none": Colors.YELLOW
            }
            policy_color = policy_colors.get(scan_result.dmarc_policy, Colors.WHITE)
            print(f"  Status: {Colors.GREEN}✓ DMARC Policy Found{Colors.END}")
            print(f"  Policy: {policy_color}{scan_result.dmarc_policy.upper()}{Colors.END}")
            print(f"  Record: {scan_result.dmarc_record}")
        else:
            print(f"  Status: {Colors.RED}✗ No DMARC Policy Found{Colors.END}")
        
        # SMTP Security (only show if SMTP check was enabled)
        if scan_result.smtp_servers:
            print(f"\n{Colors.BOLD}SMTP SECURITY:{Colors.END}")
            for smtp_server in scan_result.smtp_servers:
                hostname = smtp_server['hostname']
                print(f"  Server: {hostname}")
            
                # Connection status
                if smtp_server.get('connection_successful'):
                    print(f"    Connection: {Colors.GREEN}Connected{Colors.END}")
                else:
                    print(f"    Connection: {Colors.CYAN}Unreachable (Public access restricted - expected){Colors.END}")
                
                # STARTTLS status
                if smtp_server.get('connection_successful'):
                    starttls_status = "✓ Supported" if smtp_server.get('starttls_supported') else "✗ Not Supported"
                    starttls_color = Colors.GREEN if smtp_server.get('starttls_supported') else Colors.YELLOW
                    print(f"    STARTTLS: {starttls_color}{starttls_status}{Colors.END}")
                    
                    if smtp_server.get('tls_version'):
                        print(f"    TLS Version: {smtp_server['tls_version']}")
                    
                    cert_status = "✓ Valid" if smtp_server.get('certificate_valid') else "✗ Invalid"
                    cert_color = Colors.GREEN if smtp_server.get('certificate_valid') else Colors.YELLOW
                    print(f"    Certificate: {cert_color}{cert_status}{Colors.END}")
        
        # Security Findings
        if scan_result.findings:
            print(f"\n{Colors.BOLD}SECURITY FINDINGS ({len(scan_result.findings)}):{Colors.END}")
            
            # Group findings by severity
            findings_by_severity = {"Critical": [], "High": [], "Medium": [], "Low": []}
            for finding in scan_result.findings:
                findings_by_severity[finding.severity].append(finding)
            
            severity_colors = {
                "Critical": Colors.MAGENTA,
                "High": Colors.RED,
                "Medium": Colors.YELLOW,
                "Low": Colors.CYAN
            }
            
            for severity in ["Critical", "High", "Medium", "Low"]:
                findings = findings_by_severity[severity]
                if findings:
                    severity_color = severity_colors[severity]
                    print(f"\n  {severity_color}{severity} Severity ({len(findings)}):{Colors.END}")
                    
                    for finding in findings:
                        print(f"    • {finding.title}")
                        print(f"      Category: {finding.category}")
                        print(f"      Description: {finding.description}")
                        print(f"      Recommendation: {Colors.GREEN}{finding.recommendation}{Colors.END}")
        
        # Blacklist Status
        if scan_result.blacklist_status:
            print(f"\n{Colors.BOLD}BLACKLIST STATUS:{Colors.END}")
            clean_ips = 0
            total_ips = len(scan_result.blacklist_status)
            
            for ip, blacklists in scan_result.blacklist_status.items():
                blacklisted_count = sum(1 for status in blacklists.values() if status is True)
                if blacklisted_count > 0:
                    print(f"  {Colors.RED}IP {ip}: Listed on {blacklisted_count} blacklist(s){Colors.END}")
                else:
                    clean_ips += 1
            
            if clean_ips == total_ips and total_ips > 0:
                print(f"  {Colors.GREEN}All {total_ips} IP addresses are clean ✓{Colors.END}")
        
        print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    
    def export_json(self, filename="mail_security_scan.json"):
        """Export results to JSON format"""
        try:
            # Convert scan results to dict format
            results_dict = []
            for result in self.scan_results:
                result_dict = asdict(result)
                # Convert datetime to string
                result_dict['timestamp'] = result.timestamp.isoformat()
                results_dict.append(result_dict)
            
            with open(filename, 'w', encoding='utf-8') as f:
                if results_dict:
                    result = results_dict[0]
                    # Add scan summary with actual results
                    output = {
                        'scan_summary': {
                            'domain': result.get('domain'),
                            'scan_date': result.get('timestamp'),
                            'security_score': result.get('security_score'),
                            'spf_status': 'valid' if result.get('spf_valid') else 'invalid' if result.get('spf_record') else 'missing',
                            'dkim_selectors_found': len(result.get('dkim_selectors_found', [])),
                            'dmarc_policy': result.get('dmarc_policy', 'none'),
                            'total_findings': len(result.get('findings', [])),
                            'critical_findings': len([f for f in result.get('findings', []) if f.get('severity') == 'Critical']),
                            'high_findings': len([f for f in result.get('findings', []) if f.get('severity') == 'High'])
                        },
                        'detailed_results': result
                    }
                    json.dump(output, f, indent=2, ensure_ascii=False)
                else:
                    json.dump({}, f, indent=2, ensure_ascii=False)
            
            self.log_message(f"JSON report exported to {filename}", "SUCCESS")
            return filename
            
        except Exception as e:
            self.log_message(f"JSON export failed: {e}", "ERROR")
            return None
    
    def export_csv(self, filename="mail_security_scan.csv"):
        """Export results to CSV format"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Enhanced header
                writer.writerow([
                    'Domain', 'Scan_Time', 'Security_Score', 'Score_Grade', 'SPF_Status', 'SPF_Record',
                    'DKIM_Selectors_Count', 'DKIM_Selectors', 'DMARC_Policy', 'DMARC_Record', 
                    'SMTP_Servers', 'SMTP_Connection_Status', 'Critical_Findings', 'High_Findings', 
                    'Medium_Findings', 'Low_Findings', 'Blacklisted_IPs', 'Recommendations'
                ])
                
                # Data rows
                for result in self.scan_results:
                    # Calculate grade
                    score = result.security_score
                    if score >= 80:
                        grade = "A"
                    elif score >= 70:
                        grade = "B"
                    elif score >= 60:
                        grade = "C"
                    elif score >= 50:
                        grade = "D"
                    else:
                        grade = "F"
                    
                    # Count findings by severity
                    findings_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
                    for finding in result.findings:
                        findings_count[finding.severity] += 1
                    
                    # Count blacklisted IPs
                    blacklisted_ips = 0
                    for ip, blacklists in result.blacklist_status.items():
                        if any(status for status in blacklists.values() if status is True):
                            blacklisted_ips += 1
                    
                    # SMTP connection status
                    smtp_connected = any(smtp.get('connection_successful', False) 
                                       for smtp in result.smtp_servers)
                    smtp_status = "Connected" if smtp_connected else "Failed"
                    
                    # Generate top recommendations
                    recommendations = []
                    if not result.spf_record:
                        recommendations.append("Implement SPF")
                    if not result.dkim_selectors_found:
                        recommendations.append("Implement DKIM")
                    if not result.dmarc_record:
                        recommendations.append("Implement DMARC")
                    elif result.dmarc_policy == "none":
                        recommendations.append("Strengthen DMARC policy")
                    
                    writer.writerow([
                        result.domain,
                        result.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        result.security_score,
                        grade,
                        'Valid' if result.spf_valid else 'Issues' if result.spf_record else 'Missing',
                        result.spf_record or 'None',
                        len(result.dkim_selectors_found),
                        ', '.join(result.dkim_selectors_found) or 'None',
                        result.dmarc_policy or 'None',
                        result.dmarc_record or 'None',
                        ', '.join(result.mx_records),
                        smtp_status,
                        findings_count['Critical'],
                        findings_count['High'],
                        findings_count['Medium'],
                        findings_count['Low'],
                        blacklisted_ips,
                        '; '.join(recommendations)
                    ])
            
            self.log_message(f"CSV report exported to {filename}", "SUCCESS")
            return filename
            
        except Exception as e:
            self.log_message(f"CSV export failed: {e}", "ERROR")
            return None
    
    def export_xml(self, filename="mail_security_scan.xml"):
        """Export results to XML format"""
        try:
            root = ET.Element("MailSecurityScan")
            root.set("version", "2.1")
            root.set("scan_date", datetime.now().isoformat())
            
            summary = ET.SubElement(root, "Summary")
            ET.SubElement(summary, "TotalDomains").text = str(len(self.scan_results))
            ET.SubElement(summary, "ScannerVersion").text = "2.1"
            
            results_elem = ET.SubElement(root, "Results")
            
            for result in self.scan_results:
                domain_elem = ET.SubElement(results_elem, "Domain")
                domain_elem.set("name", result.domain)
                domain_elem.set("score", str(result.security_score))
                domain_elem.set("timestamp", result.timestamp.isoformat())
                
                # SPF
                spf_elem = ET.SubElement(domain_elem, "SPF")
                spf_elem.set("valid", str(result.spf_valid))
                if result.spf_record:
                    spf_elem.text = result.spf_record
                
                # DKIM
                dkim_elem = ET.SubElement(domain_elem, "DKIM")
                dkim_elem.set("selectors_found", str(len(result.dkim_selectors_found)))
                for selector in result.dkim_selectors_found:
                    selector_elem = ET.SubElement(dkim_elem, "Selector")
                    selector_elem.text = selector
                
                # DMARC
                dmarc_elem = ET.SubElement(domain_elem, "DMARC")
                dmarc_elem.set("policy", result.dmarc_policy)
                if result.dmarc_record:
                    dmarc_elem.text = result.dmarc_record
                
                # SMTP
                smtp_elem = ET.SubElement(domain_elem, "SMTP")
                for smtp_server in result.smtp_servers:
                    server_elem = ET.SubElement(smtp_elem, "Server")
                    server_elem.set("hostname", smtp_server['hostname'])
                    server_elem.set("starttls", str(smtp_server.get('starttls_supported', False)))
                    server_elem.set("connected", str(smtp_server.get('connection_successful', False)))
                
                # Findings
                findings_elem = ET.SubElement(domain_elem, "Findings")
                for finding in result.findings:
                    finding_elem = ET.SubElement(findings_elem, "Finding")
                    finding_elem.set("severity", finding.severity)
                    finding_elem.set("category", finding.category)
                    ET.SubElement(finding_elem, "Title").text = finding.title
                    ET.SubElement(finding_elem, "Description").text = finding.description
                    ET.SubElement(finding_elem, "Recommendation").text = finding.recommendation
            
            # Write XML file
            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ", level=0)
            tree.write(filename, encoding='utf-8', xml_declaration=True)
            
            self.log_message(f"XML report exported to {filename}", "SUCCESS")
            return filename
            
        except Exception as e:
            self.log_message(f"XML export failed: {e}", "ERROR")
            return None

def main():
    """Enhanced main function"""
    parser = argparse.ArgumentParser(
        description="Ultimate Mail Server Security Scanner v2.1 - Enhanced SPF/DKIM/DMARC Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
IMPROVEMENTS IN v2.1:
  • Multiple DNS resolver fallback (Google, Cloudflare, OpenDNS, Quad9)
  • Enhanced DKIM selector detection (30+ selectors)
  • Improved SMTP connection handling with better error recovery
  • More accurate security scoring algorithm
  • Parallel processing for faster blacklist and DKIM checking
  • Better network connectivity resilience

Examples:
  python mailsec.py google.com --verbose
  python mailsec.py microsoft.com --timeout 20 --export-all
  python mailsec.py example.org --export-json --no-console
  
Output Formats:
  --export-json     Export results to JSON format
  --export-csv      Export results to CSV format  
  --export-xml      Export results to XML format
  --export-all      Export to all formats
        """
    )
    
    parser.add_argument('domain', help='Domain to scan for mail security')
    parser.add_argument('--timeout', type=int, default=15, help='DNS/SMTP timeout in seconds (default: 15)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output with debug info')
    parser.add_argument('--no-console', action='store_true', help='Skip console output (useful with exports)')
    parser.add_argument('--smtp-check', action='store_true', help='Enable SMTP connectivity testing (most mail servers block external access)')
    
    # Export options
    parser.add_argument('--export-json', action='store_true', help='Export results to JSON')
    parser.add_argument('--export-csv', action='store_true', help='Export results to CSV')
    parser.add_argument('--export-xml', action='store_true', help='Export results to XML')
    parser.add_argument('--export-all', action='store_true', help='Export to all formats')
    
    # Output file options
    parser.add_argument('--output-dir', default='.', help='Output directory for exported files')
    parser.add_argument('--filename-prefix', default='', help='Prefix for output filenames')
    
    args = parser.parse_args()
    
    # Validate domain
    domain = args.domain.lower().strip()
    if not domain or '.' not in domain:
        print(f"{Colors.RED}Error: Invalid domain format{Colors.END}")
        sys.exit(1)
    
    # Initialize enhanced scanner
    scanner = MailSecurityScanner(timeout=args.timeout, verbose=args.verbose)
    scanner.smtp_check_enabled = args.smtp_check
    
    # Print enhanced banner
    if not args.no_console:
        scanner.print_banner()
        print(f"{Colors.CYAN}Enhanced Features: Multi-DNS fallback, Parallel processing, Better error handling{Colors.END}")
    
    try:
        # Perform enhanced scan
        scan_result = scanner.scan_domain(domain)
        
        if not scan_result:
            print(f"{Colors.RED}Scan failed for domain: {domain}{Colors.END}")
            sys.exit(1)
        
        # Display enhanced console report
        if not args.no_console:
            scanner.print_console_report(scan_result)
        
        # Export results
        exported_files = []
        
        if args.export_all or args.export_json:
            filename = os.path.join(args.output_dir, f"{args.filename_prefix}mail_security_scan_v2.1.json")
            if scanner.export_json(filename):
                exported_files.append(filename)
        
        if args.export_all or args.export_csv:
            filename = os.path.join(args.output_dir, f"{args.filename_prefix}mail_security_scan_v2.1.csv")
            if scanner.export_csv(filename):
                exported_files.append(filename)
        
        if args.export_all or args.export_xml:
            filename = os.path.join(args.output_dir, f"{args.filename_prefix}mail_security_scan_v2.1.xml")
            if scanner.export_xml(filename):
                exported_files.append(filename)
        
        # Summary
        if exported_files:
            print(f"\n{Colors.GREEN}Exported files:{Colors.END}")
            for file in exported_files:
                print(f"  • {file}")
        
        # Enhanced exit codes
        if scan_result.security_score >= 80:
            exit_code = 0
            status = "EXCELLENT"
        elif scan_result.security_score >= 70:
            exit_code = 0
            status = "GOOD"
        elif scan_result.security_score >= 50:
            exit_code = 1
            status = "NEEDS IMPROVEMENT"
        else:
            exit_code = 1
            status = "POOR"
        
        print(f"\n{Colors.CYAN}Scan completed: {status} (Score: {scan_result.security_score}/100){Colors.END}")
        print(f"{Colors.CYAN}Exit code: {exit_code}{Colors.END}")
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}Fatal error: {e}{Colors.END}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()