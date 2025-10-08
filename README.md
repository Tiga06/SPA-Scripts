# Security Assessment Toolkit

A comprehensive collection of security assessment tools integrated into a unified REST API for automated security testing and analysis.

## 🛡️ Overview

This toolkit provides 6 specialized security assessment tools accessible through both command-line interfaces and a unified REST API. Each tool focuses on specific security domains to provide comprehensive coverage of common security assessment needs.

## 🔧 Tools Included

| Tool | Purpose | Key Features |
|------|---------|--------------|
| **HTTP Headers Audit** | Web security headers analysis | CSP analysis, security header validation, JSON output |
| **Port & Services Enumeration** | Network service discovery | Nmap integration, service fingerprinting, banner grabbing |
| **SSL/TLS Certificate Validator** | Certificate chain validation | Complete chain analysis, expiration checks, trust validation |
| **Subdomain Hijacking Scanner** | Subdomain takeover detection | Multi-source enumeration, service fingerprinting, vulnerability assessment |
| **Mail Server Security** | Email authentication analysis | SPF/DKIM/DMARC validation, security scoring, comprehensive reporting |
| **DNSSEC Analysis** | DNS security validation | DNSSEC chain validation, trust anchor verification, status differentiation |
| **Nuclei Vulnerability Scanner** | Known vulnerability detection | CVE scanning, template-based detection, caching for performance |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone -b master --single-branch https://github.com/Tiga06/SPA-Scripts.git
cd SPA-Scripts

# Install dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x */*.py */*.sh
```

### API Server

```bash
# Start the API server
python3 security_tools_api.py

# Server runs on http://localhost:5000
```

### Individual Tool Usage

```bash
# HTTP Headers Audit
./HTTP-Security-Headers/http_header_audit.sh -j https://example.com

# Port Enumeration
python3 Port-Service-Enumeration/enumtool.py -t example.com

# SSL Validation
python3 SSL-Certificate-Validation/ssl_cert_validator.py example.com --json-only

# Subdomain Hijacking
python3 Subdomain-Hijacking-Scanner/subjack.py -d example.com --json-output

# Mail Security
python3 Mail-Server-Security/mailsec.py example.com --export-json --no-console

# DNSSEC Analysis
python3 DNSSEC-Analysis/dnssec_analysis.py -d example.com
```

## 📡 REST API

### Endpoints

All endpoints use consistent `domain` parameter and return JSON responses.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/health` | GET | API health check |
| `/api/tools` | GET | List available tools |
| `/api/headers-audit` | POST | HTTP security headers analysis |
| `/api/port-services` | POST | Port and service enumeration |
| `/api/ssl-validator` | POST | SSL certificate validation |
| `/api/subjack` | POST | Subdomain hijacking assessment |
| `/api/mail-security` | POST | Mail server security analysis |
| `/api/dnssec-analysis` | POST | DNSSEC security validation |
| `/api/vulnscan` | POST | Nuclei vulnerability scanning |

### Example Usage

```bash
# Headers audit
curl -X POST http://localhost:5000/api/headers-audit \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Port enumeration
curl -X POST http://localhost:5000/api/port-services \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# SSL validation
curl -X POST http://localhost:5000/api/ssl-validator \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "port": 443}'

# Mail security
curl -X POST http://localhost:5000/api/mail-security \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "timeout": 15}'

# DNSSEC analysis
curl -X POST http://localhost:5000/api/dnssec-analysis \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "resolver": "8.8.8.8"}'

# Vulnerability scanning
curl -X POST http://localhost:5000/api/vulnscan \
  -H "Content-Type: application/json" \
  -d '{"domain": "https://example.com"}'
```

### Response Format

```json
{
  "success": true,
  "data": {
    // Tool-specific results
  }
}
```

## 🏗️ Architecture

```
security-assessment-toolkit/
├── HTTP-Security-Headers/      # HTTP security headers analysis
├── Port-Service-Enumeration/   # Network port and service enumeration
├── SSL-Certificate-Validation/ # SSL/TLS certificate validation
├── Subdomain-Hijacking-Scanner/ # Subdomain hijacking detection
├── Mail-Server-Security/       # Email security assessment
├── DNSSEC-Analysis/            # DNS security validation
├── security_tools_api.py       # Unified REST API server
├── api_examples.py             # API usage examples
└── requirements.txt            # Python dependencies
```

## 🔍 Use Cases

### Security Assessments
- **Web Application Security**: Headers audit, SSL validation, subdomain analysis
- **Network Security**: Port enumeration, service fingerprinting
- **Email Security**: SPF/DKIM/DMARC validation, mail server analysis
- **DNS Security**: DNSSEC validation, trust chain verification

### Automation & Integration
- **CI/CD Pipelines**: Automated security checks in deployment workflows
- **Security Monitoring**: Regular assessment of security posture
- **Compliance Reporting**: Generate security compliance reports
- **Vulnerability Management**: Identify and track security issues

### Research & Analysis
- **Security Research**: Analyze security implementations across domains
- **Threat Intelligence**: Gather security-related information
- **Educational Purposes**: Learn about various security technologies

## 📊 Output Formats

Each tool supports multiple output formats:

- **JSON**: Machine-readable structured data
- **CSV**: Spreadsheet-compatible summaries
- **TXT**: Human-readable reports
- **Console**: Colored terminal output

## 🛠️ Dependencies

### Core Requirements
- Python 3.6+
- dnspython
- requests
- colorama
- Flask

### System Requirements
- nmap (for port enumeration)
- OpenSSL (for certificate validation)
- curl (for HTTP analysis)
- nuclei (for vulnerability scanning)

### Installation
```bash
pip install -r requirements.txt

# Install Nuclei (required for vulnerability scanning)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# or download from: https://github.com/projectdiscovery/nuclei/releases
```

## 🔒 Security Considerations

- All tools perform **read-only assessments**
- No intrusive testing or exploitation
- Respects rate limits and timeouts
- Safe for production environment scanning
- Follows responsible disclosure practices

## 📝 Individual Tool Documentation

Each tool includes detailed documentation:

- [HTTP Headers Audit](HTTP-Security-Headers/README.md)
- [Port & Services Enumeration](Port-Service-Enumeration/README.md)
- [SSL/TLS Certificate Validator](SSL-Certificate-Validation/README.md)
- [Subdomain Hijacking Scanner](Subdomain-Hijacking-Scanner/README.md)
- [Mail Server Security](Mail-Server-Security/README.md)
- [DNSSEC Analysis](DNSSEC-Analysis/README.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add new tools or improve existing ones
4. Update documentation
5. Submit a pull request

## ⚖️ License

This project is intended for educational and authorized security testing purposes only. Users are responsible for ensuring proper authorization before testing any systems.

## 🚨 Disclaimer

These tools are provided for educational and authorized security assessment purposes only. Users must ensure they have proper authorization before scanning or testing any systems they do not own or have explicit permission to test.

## 📞 Support

For issues, questions, or contributions, please use the GitHub issue tracker or submit pull requests.
