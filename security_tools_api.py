#!/usr/bin/env python3

from flask import Flask, request, jsonify
import subprocess
import json
import os
import sys
import glob
from pathlib import Path
import hashlib
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

app = Flask(__name__)

# Base directory for tools
BASE_DIR = Path(__file__).parent
CACHE_DIR = BASE_DIR / 'cache'
CACHE_DIR.mkdir(exist_ok=True)

# Tool paths
TOOLS = {
    'headers_audit': BASE_DIR / 'HTTP-Security-Headers' / 'http_header_audit.sh',
    'port_services': BASE_DIR / 'Port-Service-Enumeration' / 'enumtool.py',
    'ssl_validator': BASE_DIR / 'SSL-Certificate-Validation' / 'ssl_cert_validator.py',
    'subjack': BASE_DIR / 'Subdomain-Hijacking-Scanner' / 'subjack.py',
    'mail_security': BASE_DIR / 'Mail-Server-Security' / 'mailsec.py',
    'dnssec_analysis': BASE_DIR / 'DNSSEC-Analysis' / 'dnssec_analysis.py'
}

def run_command(cmd, cwd=None, timeout=300):
    """Execute command and return JSON result"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            cwd=cwd
        )
        
        # For mail security, non-zero exit just means low score, not failure
        if 'mailsec.py' in cmd:
            try:
                return {'success': True, 'data': json.loads(result.stdout)}
            except json.JSONDecodeError:
                return {'success': True, 'data': {'output': result.stdout}}
        
        if result.returncode == 0:
            try:
                return {'success': True, 'data': json.loads(result.stdout)}
            except json.JSONDecodeError:
                return {'success': True, 'data': {'output': result.stdout}}
        else:
            return {'success': False, 'error': result.stderr or result.stdout}
            
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Command timed out'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def get_domain_hash(domain):
    """Generate hash for domain caching"""
    return hashlib.md5(domain.encode()).hexdigest()[:10]

def get_cache_file(domain):
    """Get cache file path for domain"""
    domain_hash = get_domain_hash(domain)
    return CACHE_DIR / f"{domain_hash}.json"

def is_cache_valid(cache_file, max_age_hours=24):
    """Check if cache file is valid and not expired"""
    if not cache_file.exists():
        return False
    
    file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
    return file_age < timedelta(hours=max_age_hours)

def parse_nuclei_output(output_lines):
    """Parse Nuclei JSON output and extract findings"""
    findings = []
    
    for line in output_lines:
        line = line.strip()
        if not line:
            continue
            
        try:
            result = json.loads(line)
            
            # Extract key information from Nuclei result
            finding = {
                'id': result.get('template-id', 'unknown'),
                'name': result.get('info', {}).get('name', 'Unknown Vulnerability'),
                'severity': result.get('info', {}).get('severity', 'info'),
                'matched': result.get('matched-at', result.get('host', '')),
                'description': result.get('info', {}).get('description', 'No description available')
            }
            
            findings.append(finding)
            
        except json.JSONDecodeError:
            continue
    
    return findings

@app.route('/api/headers-audit', methods=['POST'])
def headers_audit():
    """HTTP Security Headers Audit"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain parameter required'}), 400
    
    domain = data['domain']
    # Add https:// if not present
    url = domain if domain.startswith(('http://', 'https://')) else f"https://{domain}"
    cmd = f"bash {TOOLS['headers_audit']} -j {url}"
    result = run_command(cmd, cwd=TOOLS['headers_audit'].parent)
    
    return jsonify(result)

@app.route('/api/port-services', methods=['POST'])
def port_services():
    """Port and Services Enumeration"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain parameter required'}), 400
    
    domain = data['domain']
    cmd = f"python3 {TOOLS['port_services']} -t {domain}"
    result = run_command(cmd, cwd=TOOLS['port_services'].parent)
    
    return jsonify(result)

@app.route('/api/ssl-validator', methods=['POST'])
def ssl_validator():
    """SSL/TLS Certificate Chain Validation"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain parameter required'}), 400
    
    domain = data['domain']
    port = data.get('port', 443)
    cmd = f"python3 {TOOLS['ssl_validator']} {domain} -p {port} --json-only"
    result = run_command(cmd, cwd=TOOLS['ssl_validator'].parent, timeout=60)
    
    return jsonify(result)

@app.route('/api/subjack', methods=['POST'])
def subjack():
    """Subdomain Hijacking Assessment"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain parameter required'}), 400
    
    domain = data['domain']
    cmd = f"python3 {TOOLS['subjack']} -d {domain} --json-output"
    result = run_command(cmd, cwd=TOOLS['subjack'].parent, timeout=600)
    
    return jsonify(result)

@app.route('/api/mail-security', methods=['POST'])
def mail_security():
    """Mail Server Security Assessment"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain parameter required'}), 400
    
    domain = data['domain']
    timeout = data.get('timeout', 15)
    
    # Run the tool and capture result - use fast mode with blacklist checking
    cmd = f"python3 {TOOLS['mail_security']} {domain} --timeout {timeout} --export-json --no-console --fast --blacklist-check"
    # Fast mode with blacklist should complete in 45-60 seconds
    result = run_command(cmd, cwd=TOOLS['mail_security'].parent, timeout=90)
    
    if result['success']:
        # Read the generated JSON file
        import glob
        json_files = glob.glob(str(TOOLS['mail_security'].parent / 'mail_security_scan_v2.1.json'))
        if json_files:
            try:
                with open(json_files[0], 'r') as f:
                    json_data = json.load(f)
                # Clean up the file
                os.remove(json_files[0])
                return jsonify({'success': True, 'data': json_data})
            except Exception as e:
                return jsonify({'success': False, 'error': f'Failed to read JSON output: {e}'})
    
    return jsonify(result)

@app.route('/api/dnssec-analysis', methods=['POST'])
def dnssec_analysis():
    """DNSSEC Security Analysis"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain parameter required'}), 400
    
    domain = data['domain']
    resolver = data.get('resolver')
    
    # Build command
    cmd = f"python3 {TOOLS['dnssec_analysis']} -d {domain} --no-ns-check --out /tmp"
    if resolver:
        cmd += f" --resolver {resolver}"
    
    result = run_command(cmd, cwd=TOOLS['dnssec_analysis'].parent, timeout=60)
    
    if result['success']:
        # Read the generated JSON file
        json_files = glob.glob('/tmp/dnssec_deep_*.json')
        if json_files:
            try:
                with open(json_files[0], 'r') as f:
                    json_data = json.load(f)
                # Clean up the file
                os.remove(json_files[0])
                return jsonify({'success': True, 'data': json_data})
            except Exception as e:
                return jsonify({'success': False, 'error': f'Failed to read JSON output: {e}'})
    
    return jsonify(result)

@app.route('/api/vulnscan', methods=['POST'])
def vulnerability_scan():
    """Nuclei Vulnerability Scanning with Caching"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain parameter required'}), 400
    
    domain = data['domain']
    
    # Normalize domain (add https:// if not present)
    if not domain.startswith(('http://', 'https://')):
        domain = f"https://{domain}"
    
    # Check cache first
    cache_file = get_cache_file(domain)
    
    if is_cache_valid(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            cached_data['cache_hit'] = True
            return jsonify({'success': True, 'data': cached_data})
        except Exception:
            pass  # Continue with fresh scan if cache read fails
    
    # Perform Nuclei scan
    start_time = time.time()
    
    cmd = f"nuclei -u {domain} -severity critical -jsonl -silent -rate-limit 200 -timeout 10 -tags sqli,xss,rce"
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60  # 1 minute timeout
        )
        
        # Parse Nuclei output
        output_lines = result.stdout.strip().split('\n') if result.stdout else []
        findings = parse_nuclei_output(output_lines)
        
        execution_time = time.time() - start_time
        
        # Prepare response
        scan_result = {
            'target': domain,
            'scan_status': 'completed',
            'total_findings': len(findings),
            'findings': findings,
            'cache_fingerprint': f"{get_domain_hash(domain)}.json",
            'execution_time': f"{execution_time:.2f}s",
            'cache_hit': False,
            'timestamp': datetime.now().isoformat()
        }
        
        # Cache the results
        try:
            with open(cache_file, 'w') as f:
                json.dump(scan_result, f, indent=2)
        except Exception as e:
            # Don't fail the request if caching fails
            pass
        
        return jsonify({'success': True, 'data': scan_result})
        
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Scan timed out after 1 minute'})
    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'Nuclei not found. Please install nuclei first.'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Scan failed: {str(e)}'})

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'tools': list(TOOLS.keys())})

@app.route('/api/tools', methods=['GET'])
def list_tools():
    """List available tools and their descriptions"""
    tools_info = {
        'headers_audit': {
            'name': 'HTTP Security Headers Audit',
            'description': 'Audits HTTP security headers for vulnerabilities',
            'endpoint': '/api/headers-audit',
            'parameters': {'domain': 'Target domain to audit'}
        },
        'port_services': {
            'name': 'Port & Services Enumeration',
            'description': 'Discovers open ports and identifies services',
            'endpoint': '/api/port-services',
            'parameters': {'domain': 'Target domain to scan'}
        },
        'ssl_validator': {
            'name': 'SSL/TLS Certificate Validator',
            'description': 'Validates SSL/TLS certificate chains',
            'endpoint': '/api/ssl-validator',
            'parameters': {'domain': 'Target domain', 'port': 'Port number (optional, default: 443)'}
        },
        'subjack': {
            'name': 'Subdomain Hijacking Assessment',
            'description': 'Identifies subdomain hijacking vulnerabilities',
            'endpoint': '/api/subjack',
            'parameters': {'domain': 'Target domain to assess'}
        },
        'mail_security': {
            'name': 'Mail Server Security Scanner',
            'description': 'Comprehensive SPF/DKIM/DMARC security assessment',
            'endpoint': '/api/mail-security',
            'parameters': {'domain': 'Target domain to scan', 'timeout': 'DNS/SMTP timeout in seconds (optional, default: 15)'}
        },
        'dnssec_analysis': {
            'name': 'DNSSEC Security Analysis',
            'description': 'Deep DNSSEC validation and trust chain analysis',
            'endpoint': '/api/dnssec-analysis',
            'parameters': {'domain': 'Target domain to analyze', 'resolver': 'Custom DNS resolver IP (optional)'}
        },
        'vulnscan': {
            'name': 'Nuclei Vulnerability Scanner',
            'description': 'Known vulnerability scanning using Nuclei engine with caching',
            'endpoint': '/api/vulnscan',
            'parameters': {'domain': 'Target domain/URL to scan for vulnerabilities'}
        }
    }
    return jsonify(tools_info)

if __name__ == '__main__':
    # Check if tools exist
    missing_tools = []
    for tool_name, tool_path in TOOLS.items():
        if not tool_path.exists():
            missing_tools.append(f"{tool_name}: {tool_path}")
    
    if missing_tools:
        print("Missing tools:")
        for tool in missing_tools:
            print(f"  - {tool}")
        sys.exit(1)
    
    print("Security Tools API Server (with Nuclei Integration)")
    print("Available endpoints:")
    print("  GET  /api/health - Health check")
    print("  GET  /api/tools - List available tools")
    print("  POST /api/headers-audit - HTTP headers audit")
    print("  POST /api/port-services - Port enumeration")
    print("  POST /api/ssl-validator - SSL certificate validation")
    print("  POST /api/subjack - Subdomain hijacking assessment")
    print("  POST /api/mail-security - Mail server security assessment")
    print("  POST /api/dnssec-analysis - DNSSEC security analysis")
    print("  POST /api/vulnscan - Nuclei vulnerability scanning")
    
    app.run(host='0.0.0.0', port=5000, debug=True)