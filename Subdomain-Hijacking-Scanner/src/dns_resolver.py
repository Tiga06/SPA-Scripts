import dns.resolver
import concurrent.futures
from typing import Dict, List, Optional
import json

class DNSResolver:
    def __init__(self, dns_servers: List[str] = None, max_workers: int = 100):
        self.dns_servers = dns_servers or ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        self.max_workers = max_workers
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        
    def resolve_subdomain(self, subdomain: str) -> Dict:
        """Resolve DNS records for a subdomain"""
        result = {
            'subdomain': subdomain,
            'A': [],
            'AAAA': [],
            'CNAME': [],
            'NS': [],
            'MX': [],
            'TXT': [],
            'status': 'unknown'
        }
        
        record_types = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(subdomain, record_type)
                result[record_type] = [str(rdata) for rdata in answers]
                result['status'] = 'resolved'
            except dns.resolver.NXDOMAIN:
                result['status'] = 'nxdomain'
                break
            except dns.resolver.NoAnswer:
                continue
            except Exception as e:
                continue
                
        return result
    
    def resolve_batch(self, subdomains: List[str], silent: bool = False) -> List[Dict]:
        """Resolve DNS records for multiple subdomains"""
        if not silent:
            print(f"[+] Resolving DNS records for {len(subdomains)} subdomains...")
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self.resolve_subdomain, sub): sub 
                for sub in subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    subdomain = future_to_subdomain[future]
                    results.append({
                        'subdomain': subdomain,
                        'status': 'error',
                        'error': str(e)
                    })
        
        resolved_count = len([r for r in results if r['status'] == 'resolved'])
        if not silent:
            print(f"[+] Successfully resolved {resolved_count}/{len(subdomains)} subdomains")
        
        return results
    
    def save_results(self, results: List[Dict], filename: str, silent: bool = False):
        """Save DNS resolution results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        if not silent:
            print(f"[+] DNS results saved to {filename}")
    
    def filter_cname_records(self, results: List[Dict], silent: bool = False) -> List[Dict]:
        """Filter results to only include subdomains with CNAME records"""
        cname_results = []
        for result in results:
            if result.get('CNAME') and result['status'] == 'resolved':
                cname_results.append(result)
        
        if not silent:
            print(f"[+] Found {len(cname_results)} subdomains with CNAME records")
        return cname_results