#!/usr/bin/env python3

import click
import yaml
import sys
import json
from pathlib import Path
from colorama import init, Fore, Style
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# Add src directory to path
sys.path.append(str(Path(__file__).parent / 'src'))

from subdomain_enum import SubdomainEnumerator
from dns_resolver import DNSResolver
from fingerprinter import ServiceFingerprinter
from reporter import Reporter

def load_config(config_file: str = 'config.yaml') -> dict:
    """Load configuration from YAML file"""
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"{Fore.RED}[!] Error loading config: {e}")
        return {}

def print_banner():
    """Print tool banner"""
    banner = f"""
{Fore.CYAN}
 ███████╗██╗   ██╗██████╗      ██╗ █████╗  ██████╗██╗  ██╗
 ██╔════╝██║   ██║██╔══██╗     ██║██╔══██╗██╔════╝██║ ██╔╝
 ███████╗██║   ██║██████╔╝     ██║███████║██║     █████╔╝ 
 ╚════██║██║   ██║██╔══██╗██   ██║██╔══██║██║     ██╔═██╗ 
 ███████║╚██████╔╝██████╔╝╚█████╔╝██║  ██║╚██████╗██║  ██╗
 ╚══════╝ ╚═════╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}    Subdomain Hijacking Vulnerability Assessment Tool
{Fore.GREEN}                    Version 1.0 - Agent06
{Style.RESET_ALL}
"""
    print(banner)

@click.command()
@click.option('--domain', '-d', required=True, help='Target domain to assess')
@click.option('--config', '-c', default='config.yaml', help='Configuration file path')
@click.option('--output-dir', '-o', default='output', help='Output directory for results')
@click.option('--wordlist', '-w', help='Custom wordlist file for subdomain enumeration')
@click.option('--dns-servers', help='Comma-separated list of DNS servers')
@click.option('--threads', '-t', type=int, help='Number of threads for concurrent operations')
@click.option('--timeout', type=int, help='HTTP request timeout in seconds')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--json-output', '-j', is_flag=True, help='Output results in JSON format (minimal)')
def main(domain, config, output_dir, wordlist, dns_servers, threads, timeout, verbose, json_output):
    """
    SUBJACK - Subdomain Hijacking Vulnerability Assessment Tool
    
    This tool performs comprehensive subdomain hijacking assessment by:
    1. Enumerating subdomains using multiple techniques
    2. Resolving DNS records for discovered subdomains  
    3. Fingerprinting services for takeover vulnerabilities
    4. Generating detailed reports with remediation guidance
    """
    
    if not json_output:
        print_banner()
    
    # Load configuration
    cfg = load_config(config)
    
    # Override config with command line arguments
    if dns_servers:
        cfg['dns_servers'] = dns_servers.split(',')
    if threads:
        cfg['threading'] = cfg.get('threading', {})
        cfg['threading']['max_workers'] = threads
    if timeout:
        cfg['http_settings'] = cfg.get('http_settings', {})
        cfg['http_settings']['timeout'] = timeout
    
    # Create output directory
    Path(output_dir).mkdir(exist_ok=True)
    
    try:
        # Subdomain Discovery Phase
        if not json_output:
            print(f"{Fore.CYAN}🔍 RECONNAISSANCE PHASE → Subdomain Discovery{Style.RESET_ALL}")
        enumerator = SubdomainEnumerator(
            domain, 
            max_workers=cfg.get('threading', {}).get('max_workers', 50)
        )
        
        if wordlist:
            with open(wordlist, 'r') as f:
                custom_wordlist = [line.strip() for line in f if line.strip()]
            subdomains = enumerator.wordlist_enum(custom_wordlist)
        else:
            subdomains = enumerator.enumerate_all(silent=json_output)
        
        if not subdomains:
            if not json_output:
                print(f"{Fore.RED}[!] No subdomains found. Exiting.{Style.RESET_ALL}")
            return
        
        if not json_output:
            print(f"{Fore.GREEN}[+] Found {len(subdomains)} unique subdomains{Style.RESET_ALL}")
        
        # DNS Intelligence Gathering
        if not json_output:
            print(f"\n{Fore.CYAN}🌐 INTELLIGENCE PHASE → DNS Resolution & Analysis{Style.RESET_ALL}")
        resolver = DNSResolver(
            dns_servers=cfg.get('dns_servers'),
            max_workers=cfg.get('threading', {}).get('dns_workers', 100)
        )
        
        dns_results = resolver.resolve_batch(list(subdomains), silent=json_output)
        cname_results = resolver.filter_cname_records(dns_results, silent=json_output)
        
        if not cname_results:
            if not json_output:
                print(f"{Fore.YELLOW}[!] No subdomains with CNAME records found.{Style.RESET_ALL}")
        
        # Vulnerability Assessment
        if not json_output:
            print(f"\n{Fore.CYAN}🎯 ASSESSMENT PHASE → Service Fingerprinting & Validation{Style.RESET_ALL}")
        fingerprinter = ServiceFingerprinter(
            fingerprints_file=cfg.get('fingerprints_file', 'fingerprints.yaml'),
            max_workers=cfg.get('threading', {}).get('max_workers', 50)
        )
        
        analysis_results = fingerprinter.analyze_batch(cname_results, silent=json_output)
        vulnerable_results = fingerprinter.filter_vulnerable(analysis_results)
        
        # Intelligence Reporting
        if not json_output:
            print(f"\n{Fore.CYAN}📊 REPORTING PHASE → Intelligence Documentation{Style.RESET_ALL}")
        reporter = Reporter(domain)
        
        # Change to output directory for file generation
        import os
        original_cwd = os.getcwd()
        os.chdir(output_dir)
        
        try:
            report_files = reporter.generate_all_reports(
                list(subdomains), 
                dns_results, 
                vulnerable_results,
                silent=json_output
            )
        finally:
            os.chdir(original_cwd)
        
        # Output Results
        if json_output:
            # JSON Output Format
            json_result = {
                "domain": domain,
                "timestamp": reporter.timestamp,
                "statistics": {
                    "total_subdomains": len(subdomains),
                    "resolved_subdomains": len([r for r in dns_results if r.get('status') == 'resolved']),
                    "cname_records": len(cname_results),
                    "vulnerable_subdomains": len(vulnerable_results)
                },
                "vulnerable_subdomains": [
                    {
                        "subdomain": result['subdomain'],
                        "service": result['service'],
                        "cname": result['cname'],
                        "confidence": result['confidence'],
                        "remediation": result['remediation']
                    } for result in vulnerable_results
                ],
                "report_files": {k: f"{output_dir}/{v}" for k, v in report_files.items()}
            }
            print(json.dumps(json_result, indent=2))
        else:
            # Standard Output Format
            print(f"\n{Fore.CYAN}✅ MISSION ACCOMPLISHED → Assessment Complete{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Domain Assessed: {domain}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total Subdomains: {len(subdomains)}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Resolved Subdomains: {len([r for r in dns_results if r.get('status') == 'resolved'])}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}CNAME Records: {len(cname_results)}{Style.RESET_ALL}")
            
            if vulnerable_results:
                print(f"{Fore.RED}Vulnerable Subdomains: {len(vulnerable_results)}{Style.RESET_ALL}")
                print(f"\n{Fore.RED}[!] VULNERABLE SUBDOMAINS DETECTED:{Style.RESET_ALL}")
                for result in vulnerable_results:
                    print(f"  • {result['subdomain']} -> {result['service']} ({result['confidence']} confidence)")
            else:
                print(f"{Fore.GREEN}Vulnerable Subdomains: 0{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] No vulnerable subdomains detected!{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}📋 INTELLIGENCE ARTIFACTS → Reports Generated{Style.RESET_ALL}")
            for report_type, filename in report_files.items():
                print(f"  • {report_type}: {output_dir}/{filename}")
            
            print(f"\n{Fore.YELLOW}[+] Assessment completed successfully!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        if not json_output:
            print(f"\n{Fore.RED}[!] Assessment interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        if not json_output:
            print(f"\n{Fore.RED}[!] Error during assessment: {e}{Style.RESET_ALL}")
            if verbose:
                import traceback
                traceback.print_exc()
        else:
            print(json.dumps({"error": str(e)}, indent=2))
        sys.exit(1)

if __name__ == '__main__':
    main()