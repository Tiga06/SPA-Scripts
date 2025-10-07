import requests
import yaml
import concurrent.futures
from typing import Dict, List, Optional
import re
from urllib.parse import urlparse

class ServiceFingerprinter:
    def __init__(self, fingerprints_file: str = 'fingerprints.yaml', max_workers: int = 50):
        self.max_workers = max_workers
        self.fingerprints = self._load_fingerprints(fingerprints_file)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SubjackScanner/1.0'
        })
        
    def _load_fingerprints(self, filename: str) -> Dict:
        """Load service fingerprints from YAML file"""
        try:
            with open(filename, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"[!] Error loading fingerprints: {e}")
            return {'services': {}}
    
    def check_cname_match(self, cname: str) -> Optional[str]:
        """Check if CNAME matches known vulnerable services"""
        cname = cname.lower().rstrip('.')
        
        for service_name, config in self.fingerprints.get('services', {}).items():
            cname_patterns = config.get('cname', [])
            for pattern in cname_patterns:
                if pattern.lower() in cname:
                    return service_name
        return None
    
    def check_http_response(self, subdomain: str, service: str) -> Dict:
        """Check HTTP response for vulnerability fingerprints"""
        result = {
            'subdomain': subdomain,
            'service': service,
            'vulnerable': False,
            'confidence': 'low',
            'evidence': [],
            'http_status': None,
            'response_body': '',
            'error': None
        }
        
        urls = [f"http://{subdomain}", f"https://{subdomain}"]
        
        for url in urls:
            try:
                response = self.session.get(
                    url, 
                    timeout=10, 
                    allow_redirects=True,
                    verify=False
                )
                
                result['http_status'] = response.status_code
                result['response_body'] = response.text[:2000]  # Limit response size
                
                # Check for service-specific fingerprints
                service_config = self.fingerprints.get('services', {}).get(service, {})
                fingerprint_patterns = service_config.get('fingerprint', [])
                
                for pattern in fingerprint_patterns:
                    if pattern.lower() in response.text.lower():
                        result['vulnerable'] = True
                        result['confidence'] = 'high'
                        result['evidence'].append({
                            'type': 'http_response',
                            'pattern': pattern,
                            'url': url,
                            'status_code': response.status_code
                        })
                
                # Additional checks for common takeover indicators
                takeover_indicators = [
                    'not found',
                    'no such',
                    'does not exist',
                    'is not configured',
                    'suspended',
                    'parked',
                    'available for registration',
                    'this domain is for sale'
                ]
                
                response_lower = response.text.lower()
                for indicator in takeover_indicators:
                    if indicator in response_lower:
                        result['vulnerable'] = True
                        result['confidence'] = 'medium'
                        result['evidence'].append({
                            'type': 'generic_indicator',
                            'pattern': indicator,
                            'url': url,
                            'status_code': response.status_code
                        })
                
                break  # If we got a response, no need to try other protocols
                
            except requests.exceptions.RequestException as e:
                result['error'] = str(e)
                continue
        
        return result
    
    def analyze_subdomain(self, dns_record: Dict) -> Optional[Dict]:
        """Analyze a single subdomain for takeover vulnerability"""
        subdomain = dns_record.get('subdomain')
        cnames = dns_record.get('CNAME', [])
        
        if not cnames:
            return None
        
        # Check each CNAME for potential services
        for cname in cnames:
            service = self.check_cname_match(cname)
            if service:
                # Perform HTTP checks
                http_result = self.check_http_response(subdomain, service)
                http_result['cname'] = cname
                return http_result
        
        return None
    
    def analyze_batch(self, dns_records: List[Dict], silent: bool = False) -> List[Dict]:
        """Analyze multiple subdomains for takeover vulnerabilities"""
        if not silent:
            print(f"[+] Analyzing {len(dns_records)} subdomains for takeover vulnerabilities...")
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_record = {
                executor.submit(self.analyze_subdomain, record): record 
                for record in dns_records
            }
            
            for future in concurrent.futures.as_completed(future_to_record):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    record = future_to_record[future]
                    print(f"[!] Error analyzing {record.get('subdomain')}: {e}")
        
        vulnerable_count = len([r for r in results if r.get('vulnerable')])
        if not silent:
            print(f"[+] Found {vulnerable_count} potentially vulnerable subdomains")
        
        return results
    
    def generate_remediation(self, result: Dict) -> str:
        """Generate remediation advice for a vulnerable subdomain"""
        service = result.get('service', 'unknown')
        subdomain = result.get('subdomain')
        cname = result.get('cname')
        
        remediation_map = {
            'github': f"Remove the CNAME record pointing to {cname} or create a GitHub Pages site",
            'heroku': f"Remove the CNAME record pointing to {cname} or recreate the Heroku app",
            'aws_s3': f"Remove the CNAME record pointing to {cname} or create the S3 bucket",
            'azure': f"Remove the CNAME record pointing to {cname} or recreate the Azure resource",
            'shopify': f"Remove the CNAME record pointing to {cname} or configure Shopify properly",
            'fastly': f"Remove the CNAME record pointing to {cname} or configure Fastly service",
            'cloudfront': f"Remove the CNAME record pointing to {cname} or configure CloudFront distribution"
        }
        
        return remediation_map.get(service, f"Remove the CNAME record pointing to {cname}")
    
    def filter_vulnerable(self, results: List[Dict]) -> List[Dict]:
        """Filter results to only include vulnerable subdomains"""
        vulnerable = [r for r in results if r.get('vulnerable')]
        
        # Add remediation advice
        for result in vulnerable:
            result['remediation'] = self.generate_remediation(result)
        
        return vulnerable