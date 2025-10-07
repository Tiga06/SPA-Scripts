import json
import csv
from datetime import datetime
from typing import List, Dict
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

class Reporter:
    def __init__(self, domain: str):
        self.domain = domain
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def save_subdomains_txt(self, subdomains: List[str], filename: str = None, silent: bool = False):
        """Save subdomain list to text file"""
        if not filename:
            filename = f"subdomains_{self.domain}_{self.timestamp}.txt"
        
        with open(filename, 'w') as f:
            for subdomain in sorted(subdomains):
                f.write(f"{subdomain}\n")
        
        if not silent:
            print(f"[+] Subdomains saved to {filename}")
        return filename
    
    def save_dns_json(self, dns_results: List[Dict], filename: str = None, silent: bool = False):
        """Save DNS resolution results to JSON"""
        if not filename:
            filename = f"resolved_{self.domain}_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(dns_results, f, indent=2)
        
        if not silent:
            print(f"[+] DNS results saved to {filename}")
        return filename
    
    def save_vulnerable_json(self, vulnerable_results: List[Dict], filename: str = None, silent: bool = False):
        """Save vulnerable subdomains to JSON"""
        if not filename:
            filename = f"hijackable_{self.domain}_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(vulnerable_results, f, indent=2)
        
        if not silent:
            print(f"[+] Vulnerable subdomains saved to {filename}")
        return filename
    
    def save_vulnerable_csv(self, vulnerable_results: List[Dict], filename: str = None, silent: bool = False):
        """Save vulnerable subdomains to CSV"""
        if not filename:
            filename = f"hijackable_{self.domain}_{self.timestamp}.csv"
        
        if not vulnerable_results:
            return filename
        
        fieldnames = ['subdomain', 'service', 'cname', 'vulnerable', 'confidence', 'http_status', 'remediation']
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in vulnerable_results:
                row = {
                    'subdomain': result.get('subdomain', ''),
                    'service': result.get('service', ''),
                    'cname': result.get('cname', ''),
                    'vulnerable': result.get('vulnerable', False),
                    'confidence': result.get('confidence', ''),
                    'http_status': result.get('http_status', ''),
                    'remediation': result.get('remediation', '')
                }
                writer.writerow(row)
        
        if not silent:
            print(f"[+] Vulnerable subdomains CSV saved to {filename}")
        return filename
    
    def generate_executive_summary(self, stats: Dict) -> str:
        """Generate executive summary text"""
        total_subdomains = stats.get('total_subdomains', 0)
        resolved_subdomains = stats.get('resolved_subdomains', 0)
        cname_subdomains = stats.get('cname_subdomains', 0)
        vulnerable_subdomains = stats.get('vulnerable_subdomains', 0)
        
        risk_level = "LOW"
        if vulnerable_subdomains > 5:
            risk_level = "HIGH"
        elif vulnerable_subdomains > 0:
            risk_level = "MEDIUM"
        
        summary = f"""
EXECUTIVE SUMMARY

Domain Assessed: {self.domain}
Assessment Date: {datetime.now().strftime("%B %d, %Y")}
Risk Level: {risk_level}

FINDINGS OVERVIEW:
• Total Subdomains Discovered: {total_subdomains}
• Successfully Resolved: {resolved_subdomains}
• Subdomains with CNAME Records: {cname_subdomains}
• Potentially Vulnerable Subdomains: {vulnerable_subdomains}

RISK ASSESSMENT:
Subdomain hijacking vulnerabilities allow attackers to take control of subdomains by claiming 
abandoned third-party services. This can lead to phishing attacks, malware distribution, 
and reputation damage.

IMMEDIATE ACTIONS REQUIRED:
"""
        
        if vulnerable_subdomains > 0:
            summary += f"""
1. Review and remediate {vulnerable_subdomains} flagged vulnerable subdomains immediately
2. Remove or fix dangling DNS records pointing to unclaimed services
3. Implement DNS monitoring to detect future dangling records
4. Establish subdomain governance policies
"""
        else:
            summary += """
1. No immediate vulnerabilities detected
2. Continue regular DNS monitoring
3. Maintain subdomain inventory and governance
"""
        
        return summary
    
    def generate_pdf_report(self, stats: Dict, vulnerable_results: List[Dict], filename: str = None):
        """Generate comprehensive PDF report"""
        if not filename:
            filename = f"subjack_report_{self.domain}_{self.timestamp}.pdf"
        
        doc = SimpleDocTemplate(filename, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph(f"Subdomain Hijacking Assessment Report", title_style))
        story.append(Paragraph(f"Domain: {self.domain}", styles['Heading2']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary_text = self.generate_executive_summary(stats)
        for line in summary_text.split('\n'):
            if line.strip():
                story.append(Paragraph(line, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Statistics Table
        story.append(Paragraph("Assessment Statistics", styles['Heading2']))
        stats_data = [
            ['Metric', 'Count'],
            ['Total Subdomains Discovered', str(stats.get('total_subdomains', 0))],
            ['Successfully Resolved', str(stats.get('resolved_subdomains', 0))],
            ['Subdomains with CNAME Records', str(stats.get('cname_subdomains', 0))],
            ['Potentially Vulnerable', str(stats.get('vulnerable_subdomains', 0))]
        ]
        
        stats_table = Table(stats_data)
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        # Vulnerable Subdomains Details
        if vulnerable_results:
            story.append(Paragraph("Vulnerable Subdomains Details", styles['Heading2']))
            
            vuln_data = [['Subdomain', 'Service', 'CNAME Target', 'Confidence', 'Status']]
            for result in vulnerable_results:
                vuln_data.append([
                    result.get('subdomain', ''),
                    result.get('service', ''),
                    result.get('cname', ''),
                    result.get('confidence', ''),
                    str(result.get('http_status', ''))
                ])
            
            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)
            story.append(Spacer(1, 20))
            
            # Remediation Steps
            story.append(Paragraph("Remediation Steps", styles['Heading2']))
            for i, result in enumerate(vulnerable_results, 1):
                story.append(Paragraph(f"{i}. {result.get('subdomain', '')}", styles['Heading3']))
                story.append(Paragraph(f"Remediation: {result.get('remediation', '')}", styles['Normal']))
                story.append(Spacer(1, 10))
        
        # Methodology
        story.append(Paragraph("Methodology", styles['Heading2']))
        methodology_text = """
This assessment was conducted using the following methodology:

1. Subdomain Enumeration: Certificate Transparency logs and wordlist-based discovery
2. DNS Resolution: Comprehensive DNS record collection (A, AAAA, CNAME, NS, MX, TXT)
3. Service Fingerprinting: Matching CNAME targets against known vulnerable services
4. HTTP Validation: Checking HTTP responses for takeover indicators
5. Manual Verification: Non-destructive validation of flagged candidates

The assessment focused on identifying dangling DNS records that point to unclaimed 
third-party services, which could be exploited for subdomain hijacking attacks.
"""
        
        for line in methodology_text.split('\n'):
            if line.strip():
                story.append(Paragraph(line, styles['Normal']))
        
        doc.build(story)
        if not hasattr(self, '_silent') or not self._silent:
            print(f"[+] PDF report generated: {filename}")
        return filename
    
    def generate_all_reports(self, subdomains: List[str], dns_results: List[Dict], 
                           vulnerable_results: List[Dict], silent: bool = False) -> Dict[str, str]:
        """Generate all report formats"""
        files = {}
        self._silent = silent
        
        # Calculate statistics
        stats = {
            'total_subdomains': len(subdomains),
            'resolved_subdomains': len([r for r in dns_results if r.get('status') == 'resolved']),
            'cname_subdomains': len([r for r in dns_results if r.get('CNAME')]),
            'vulnerable_subdomains': len(vulnerable_results)
        }
        
        # Generate all report files
        files['subdomains_txt'] = self.save_subdomains_txt(subdomains, silent=silent)
        files['dns_json'] = self.save_dns_json(dns_results, silent=silent)
        files['vulnerable_json'] = self.save_vulnerable_json(vulnerable_results, silent=silent)
        files['vulnerable_csv'] = self.save_vulnerable_csv(vulnerable_results, silent=silent)
        files['pdf_report'] = self.generate_pdf_report(stats, vulnerable_results)
        
        return files