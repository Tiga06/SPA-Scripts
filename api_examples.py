#!/usr/bin/env python3

import requests
import json
import time

API_BASE = "http://localhost:5000/api"

def example_headers_audit():
    """Example: HTTP Headers Audit"""
    print("=== HTTP Headers Audit Example ===")
    
    payload = {"domain": "example.com"}
    response = requests.post(f"{API_BASE}/headers-audit", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        if result['success']:
            print("✓ Headers audit completed successfully")
            print(json.dumps(result['data'], indent=2))
        else:
            print(f"✗ Error: {result['error']}")
    else:
        print(f"✗ HTTP Error: {response.status_code}")

def example_port_services():
    """Example: Port & Services Enumeration"""
    print("\n=== Port & Services Enumeration Example ===")
    
    payload = {"domain": "scanme.nmap.org"}
    response = requests.post(f"{API_BASE}/port-services", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        if result['success']:
            print("✓ Port enumeration completed successfully")
            print(json.dumps(result['data'], indent=2))
        else:
            print(f"✗ Error: {result['error']}")
    else:
        print(f"✗ HTTP Error: {response.status_code}")

def example_ssl_validator():
    """Example: SSL Certificate Validation"""
    print("\n=== SSL Certificate Validation Example ===")
    
    payload = {"domain": "google.com", "port": 443}
    response = requests.post(f"{API_BASE}/ssl-validator", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        if result['success']:
            print("✓ SSL validation completed successfully")
            print(json.dumps(result['data'], indent=2))
        else:
            print(f"✗ Error: {result['error']}")
    else:
        print(f"✗ HTTP Error: {response.status_code}")

def example_subjack():
    """Example: Subdomain Hijacking Assessment"""
    print("\n=== Subdomain Hijacking Assessment Example ===")
    
    payload = {"domain": "example.com"}
    response = requests.post(f"{API_BASE}/subjack", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        if result['success']:
            print("✓ Subdomain hijacking assessment completed successfully")
            print(json.dumps(result['data'], indent=2))
        else:
            print(f"✗ Error: {result['error']}")
    else:
        print(f"✗ HTTP Error: {response.status_code}")

def example_mail_security():
    """Example: Mail Server Security Assessment"""
    print("\n=== Mail Server Security Assessment Example ===")
    
    payload = {"domain": "example.com", "timeout": 15}
    response = requests.post(f"{API_BASE}/mail-security", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        if result['success']:
            print("✓ Mail security assessment completed successfully")
            print(json.dumps(result['data'], indent=2))
        else:
            print(f"✗ Error: {result['error']}")
    else:
        print(f"✗ HTTP Error: {response.status_code}")

def example_dnssec_analysis():
    """Example: DNSSEC Security Analysis"""
    print("\n=== DNSSEC Security Analysis Example ===")
    
    payload = {"domain": "example.com", "resolver": "8.8.8.8"}
    response = requests.post(f"{API_BASE}/dnssec-analysis", json=payload)
    
    if response.status_code == 200:
        result = response.json()
        if result['success']:
            print("✓ DNSSEC analysis completed successfully")
            print(json.dumps(result['data'], indent=2))
        else:
            print(f"✗ Error: {result['error']}")
    else:
        print(f"✗ HTTP Error: {response.status_code}")

def check_api_health():
    """Check if API is running"""
    try:
        response = requests.get(f"{API_BASE}/health", timeout=5)
        if response.status_code == 200:
            print("✓ API is running and healthy")
            return True
        else:
            print(f"✗ API health check failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"✗ Cannot connect to API: {e}")
        print("Make sure to start the API server first:")
        print("  python3 security_tools_api.py")
        return False

def main():
    """Run all examples"""
    print("Security Tools API Examples")
    print("=" * 40)
    
    if not check_api_health():
        return
    
    # Run examples (uncomment the ones you want to test)
    example_headers_audit()
    
    # Note: These examples use real targets and may take time
    # Uncomment to test:
    # example_port_services()
    # example_ssl_validator()
    # example_subjack()
    # example_mail_security()
    # example_dnssec_analysis()
    
    print("\n" + "=" * 40)
    print("Examples completed!")

if __name__ == "__main__":
    main()