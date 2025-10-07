#!/usr/bin/env python3

from flask import Flask, request, jsonify
import subprocess
import json
import os
import sys
import glob
from pathlib import Path

app = Flask(__name__)

# Base directory for tools
BASE_DIR = Path(__file__).parent

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
    
    # Run the tool and capture result
    cmd = f"python3 {TOOLS['mail_security']} {domain} --timeout {timeout} --export-json --no-console"
    result = run_command(cmd, cwd=TOOLS['mail_security'].parent, timeout=timeout+60)
    
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
    
    print("Security Tools API Server")
    print("Available endpoints:")
    print("  GET  /api/health - Health check")
    print("  GET  /api/tools - List available tools")
    print("  POST /api/headers-audit - HTTP headers audit")
    print("  POST /api/port-services - Port enumeration")
    print("  POST /api/ssl-validator - SSL certificate validation")
    print("  POST /api/subjack - Subdomain hijacking assessment")
    print("  POST /api/mail-security - Mail server security assessment")
    print("  POST /api/dnssec-analysis - DNSSEC security analysis")
    
    app.run(host='0.0.0.0', port=5000, debug=True)