#!/usr/bin/env python3

import argparse
import json
import subprocess
import xml.etree.ElementTree as ET
import re
import sys
import socket

def run_command(cmd):
    """Execute shell command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1

def get_ip_from_target(target):
    """Resolve target to IP address"""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target

def is_local_target(target):
    """Check if target is local/internal"""
    local_patterns = ['127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', 'localhost']
    return any(target.startswith(pattern) for pattern in local_patterns) or target == 'localhost'

def port_scan(target):
    """Perform initial port scan to find open ports"""
    if is_local_target(target):
        # Aggressive scan for local targets
        cmd = f"nmap -p- --min-rate 1000 -T4 {target} -oG -"
    else:
        # Conservative scan for external targets - top 1000 ports only
        cmd = f"nmap --top-ports 1000 -T3 {target} -oG -"
    
    stdout, stderr, code = run_command(cmd)
    
    if code != 0:
        return []
    
    ports = []
    for line in stdout.split('\n'):
        if 'Ports:' in line:
            port_info = line.split('Ports: ')[1]
            for port_entry in port_info.split(', '):
                if '/open/' in port_entry:
                    port_num = port_entry.split('/')[0]
                    ports.append(int(port_num))
    
    return sorted(ports)

def service_enumeration(target, ports):
    """Perform service enumeration on open ports"""
    if not ports:
        return {}
    
    port_list = ','.join(map(str, ports))
    if is_local_target(target):
        cmd = f"nmap -sV -sC -p {port_list} {target} -oX -"
    else:
        # Less aggressive for external targets
        cmd = f"nmap -sV -T3 -p {port_list} {target} -oX -"
    
    stdout, stderr, code = run_command(cmd)
    
    if code != 0:
        return {}
    
    return parse_nmap_xml(stdout)

def banner_grabbing(target, ports):
    """Grab banners from open ports"""
    if not ports:
        return {}
    
    port_list = ','.join(map(str, ports))
    if is_local_target(target):
        cmd = f"nmap --script=banner -p {port_list} {target} -oX -"
    else:
        cmd = f"nmap --script=banner -T3 -p {port_list} {target} -oX -"
    
    stdout, stderr, code = run_command(cmd)
    
    if code != 0:
        return {}
    
    return parse_banner_xml(stdout)

def parse_nmap_xml(xml_data):
    """Parse nmap XML output for service information"""
    services = {}
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                port_id = int(port.get('portid'))
                protocol = port.get('protocol', 'tcp')
                
                state_elem = port.find('state')
                state = state_elem.get('state') if state_elem is not None else 'unknown'
                
                service_elem = port.find('service')
                if service_elem is not None:
                    service = service_elem.get('name', '')
                    product = service_elem.get('product', '')
                    version = service_elem.get('version', '')
                else:
                    service = product = version = ''
                
                services[port_id] = {
                    'protocol': protocol,
                    'state': state,
                    'service': service,
                    'product': product,
                    'version': version
                }
    except ET.ParseError:
        pass
    
    return services

def parse_banner_xml(xml_data):
    """Parse nmap XML output for banner information"""
    banners = {}
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                port_id = int(port.get('portid'))
                
                for script in port.findall('.//script'):
                    if script.get('id') == 'banner':
                        banner_text = script.get('output', '').strip()
                        if banner_text:
                            banners[port_id] = banner_text
    except ET.ParseError:
        pass
    
    return banners

def enumerate_target(target):
    """Main enumeration function for a single target"""
    ip = get_ip_from_target(target)
    
    # Step 1: Port scan
    open_ports = port_scan(target)
    
    if not open_ports:
        return {
            "target": target,
            "ip": ip,
            "ports": []
        }
    
    # Step 2: Service enumeration
    services = service_enumeration(target, open_ports)
    
    # Step 3: Banner grabbing
    banners = banner_grabbing(target, open_ports)
    
    # Combine results
    ports_data = []
    for port in open_ports:
        port_info = {
            "port": port,
            "protocol": services.get(port, {}).get('protocol', 'tcp'),
            "state": services.get(port, {}).get('state', 'open'),
            "service": services.get(port, {}).get('service', ''),
            "product": services.get(port, {}).get('product', ''),
            "version": services.get(port, {}).get('version', ''),
            "banner": banners.get(port, '')
        }
        ports_data.append(port_info)
    
    return {
        "target": target,
        "ip": ip,
        "ports": ports_data
    }

def main():
    parser = argparse.ArgumentParser(description='Automated Port & Service Enumeration Tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', help='Single target to scan')
    group.add_argument('-l', '--list', help='File containing list of targets')
    
    args = parser.parse_args()
    
    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(json.dumps({"error": f"File not found: {args.list}"}))
            sys.exit(1)
    
    results = []
    for target in targets:
        result = enumerate_target(target)
        results.append(result)
    
    # Output results
    if len(results) == 1:
        print(json.dumps(results[0], indent=2))
    else:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()