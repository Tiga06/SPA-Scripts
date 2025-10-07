# Subdomain Hijacking Scanner (SUBJACK)

Advanced subdomain hijacking vulnerability assessment tool that identifies dangling DNS records vulnerable to takeover attacks.

## Features

### Vulnerability Detection
- **Multi-source Enumeration**: Certificate Transparency logs and wordlist-based discovery
- **DNS Analysis**: Comprehensive record collection (A, AAAA, CNAME, NS, MX, TXT)
- **Service Fingerprinting**: Detects 12+ vulnerable cloud services
- **HTTP Validation**: Confirms vulnerabilities through response analysis
- **Confidence Scoring**: Risk assessment for each finding

### Enhanced Features
- **Multiple Output Formats**: JSON, CSV, TXT, and PDF reports
- **Executive Summary**: Non-technical risk assessment for management
- **Remediation Guidance**: Tailored fix recommendations for each service
- **Configurable Settings**: Customizable via YAML configuration
- **Progress Tracking**: Real-time progress indicators
- **Comprehensive Reporting**: Detailed technical and executive reports

### Supported Services
- GitHub Pages
- Heroku
- AWS S3
- Microsoft Azure
- Shopify
- Fastly
- CloudFront
- Bitbucket
- Tumblr
- WordPress.com
- Ghost.io
- Surge.sh

## Integration

This tool is integrated into the Security Assessment Toolkit API:

```bash
# Via API
curl -X POST http://localhost:5000/api/subjack \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Direct usage
python3 subjack.py -d example.com --json-output
```

## Command Options

| Option | Description |
|--------|-------------|
| `-d DOMAIN` | Target domain to assess |
| `--json-output` | JSON format output (used by API) |
| `--output-dir DIR` | Output directory for reports |
| `--threads N` | Number of concurrent threads |
| `--timeout N` | HTTP request timeout |
| `--verbose` | Enable verbose output |

## Configuration

Edit `config.yaml` to customize:

```yaml
subdomain_sources:
  - crt.sh
  - sublist3r
  - amass
  - subfinder

dns_servers:
  - 8.8.8.8
  - 1.1.1.1
  - 9.9.9.9

http_settings:
  timeout: 10
  max_redirects: 5
  user_agent: "SubjackScanner/1.0"

threading:
  max_workers: 50
  dns_workers: 100
```

## Output Files

The tool generates multiple report formats:

1. **subdomains_[domain]_[timestamp].txt** - List of discovered subdomains
2. **resolved_[domain]_[timestamp].json** - DNS resolution results
3. **hijackable_[domain]_[timestamp].json** - Vulnerable subdomains (JSON)
4. **hijackable_[domain]_[timestamp].csv** - Vulnerable subdomains (CSV)
5. **subjack_report_[domain]_[timestamp].pdf** - Comprehensive PDF report

## Methodology

1. **Subdomain Enumeration**
   - Certificate Transparency log analysis
   - Wordlist-based brute force discovery
   - Multi-threaded DNS resolution

2. **DNS Analysis**
   - Comprehensive record collection
   - CNAME record identification
   - Dangling record detection

3. **Service Fingerprinting**
   - CNAME pattern matching
   - HTTP response analysis
   - Vulnerability confidence scoring

4. **Validation & Reporting**
   - Non-destructive verification
   - Evidence collection
   - Remediation guidance generation

## Example Output

```
✅ MISSION ACCOMPLISHED → Assessment Complete
Domain Assessed: example.com
Total Subdomains: 156
Resolved Subdomains: 142
CNAME Records: 23
Vulnerable Subdomains: 3

[!] VULNERABLE SUBDOMAINS DETECTED:
  • old-blog.example.com -> github (high confidence)
  • staging-app.example.com -> heroku (medium confidence)
  • assets.example.com -> aws_s3 (high confidence)

📋 INTELLIGENCE ARTIFACTS → Reports Generated
  • subdomains_txt: output/subdomains_example.com_20241204_143022.txt
  • dns_json: output/resolved_example.com_20241204_143022.json
  • vulnerable_json: output/hijackable_example.com_20241204_143022.json
  • vulnerable_csv: output/hijackable_example.com_20241204_143022.csv
  • pdf_report: output/subjack_report_example.com_20241204_143022.pdf
```

## Security Considerations

- **Non-destructive Testing**: Tool only performs reconnaissance and validation
- **No Exploitation**: Does not attempt to claim or exploit vulnerable services
- **Rate Limiting**: Configurable threading to avoid overwhelming targets
- **Ethical Use**: Intended for authorized security assessments only

## Remediation

For each vulnerable subdomain, the tool provides specific remediation steps:

- **Remove CNAME Record**: Delete the dangling DNS record
- **Claim Service**: Recreate the service at the target provider
- **Update DNS**: Point to active, controlled resources
- **Monitor**: Implement ongoing DNS monitoring

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add new service fingerprints to `fingerprints.yaml`
4. Submit a pull request

## License

This tool is provided for educational and authorized security testing purposes only.

## Disclaimer

Users are responsible for ensuring they have proper authorization before testing any domains. The authors are not responsible for any misuse of this tool.