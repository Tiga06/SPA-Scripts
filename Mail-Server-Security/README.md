# Mail Server Security Scanner

Comprehensive email authentication security assessment tool that validates SPF, DKIM, and DMARC implementations.

## Features

### Email Security Analysis
- **SPF Validation** - Comprehensive Sender Policy Framework analysis
- **DKIM Detection** - Scans 30+ common DKIM selectors with parallel processing
- **DMARC Assessment** - Policy validation and configuration analysis
- **Security Scoring** - 0-100 security score with detailed breakdown
- **Blacklist Monitoring** - IP reputation checking across multiple providers
- **DNS Resilience** - Multiple DNS resolver fallback for reliability

### Enhanced Features v2.1
- **Multiple DNS Resolver Fallback** - Google, Cloudflare, OpenDNS, Quad9
- **Parallel Processing** - Faster DKIM and blacklist checking
- **Improved Error Recovery** - Better network connectivity resilience
- **Enhanced Security Scoring** - More accurate risk assessment
- **Comprehensive Reporting** - JSON, CSV, XML export formats

## Integration

This tool is integrated into the Security Assessment Toolkit API:

```bash
# Via API
curl -X POST http://localhost:5000/api/mail-security \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "timeout": 15}'

# Direct usage
python3 mailsec.py example.com --export-json --no-console
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `domain` | Target domain to scan (required) |
| `--timeout` | DNS/SMTP timeout in seconds (default: 15) |
| `--verbose, -v` | Enable verbose output with debug info |
| `--no-console` | Skip console output (useful with exports) |
| `--export-json` | Export results to JSON format |
| `--export-csv` | Export results to CSV format |
| `--export-xml` | Export results to XML format |
| `--export-all` | Export to all formats |
| `--output-dir` | Output directory for exported files |
| `--filename-prefix` | Prefix for output filenames |

## Security Scoring

The tool provides a comprehensive security score (0-100) based on:

- **SPF Configuration** (20 points)
- **DKIM Implementation** (20 points) 
- **DMARC Policy** (25 points)
- **SMTP Security** (15 points)
- **IP Reputation** (10 points)
- **Additional Findings** (10 points)

### Score Grades
- **80-100**: Excellent (A)
- **70-79**: Good (B)
- **60-69**: Fair (C)
- **50-59**: Poor (D)
- **0-49**: Critical (F)

## Output Formats

### Console Report
Detailed colored console output with:
- Security score and grade
- SPF/DKIM/DMARC status
- SMTP server security details
- Security findings by severity
- Blacklist status
- Recommendations

### JSON Export
Structured data format for API integration:
```json
{
  "domain": "example.com",
  "security_score": 85,
  "spf_record": "v=spf1 include:_spf.google.com ~all",
  "dkim_selectors_found": ["default", "google"],
  "dmarc_policy": "quarantine",
  "findings": [...]
}
```

### CSV Export
Spreadsheet-compatible format with:
- Domain, timestamp, security score
- SPF/DKIM/DMARC status
- Finding counts by severity
- Recommendations summary

### XML Export
Structured XML format for enterprise integration

## Security Checks Performed

### SPF (Sender Policy Framework)
- Record existence and syntax validation
- DNS lookup count analysis (RFC limit: 10)
- Policy mechanism evaluation
- Qualifier assessment (-all, ~all, +all)
- Common misconfigurations detection

### DKIM (DomainKeys Identified Mail)
- Comprehensive selector scanning (30+ selectors)
- Public key validation
- Algorithm support verification
- Multiple selector redundancy check

### DMARC (Domain-based Message Authentication)
- Policy existence and syntax validation
- Alignment mode checking
- Reporting configuration analysis
- Policy strength assessment

### SMTP Security
- Port accessibility (25, 587, 465)
- STARTTLS support verification
- SSL/TLS certificate validation
- Certificate expiration checking
- Connection security analysis

### Reputation Monitoring
- Multi-blacklist IP checking
- PTR record validation
- Reverse DNS consistency
- Reputation score impact

## Improvements in v2.1

1. **Enhanced DNS Resilience**
   - Multiple DNS resolver fallback
   - Improved timeout handling
   - Better error recovery

2. **Performance Optimizations**
   - Parallel DKIM selector checking
   - Concurrent blacklist queries
   - Faster overall scan times

3. **Better Error Handling**
   - Network connectivity resilience
   - Graceful failure handling
   - Improved debugging output

4. **More Accurate Scoring**
   - Refined scoring algorithm
   - Better penalty distribution
   - Context-aware deductions

## Exit Codes

- **0**: Scan successful, good security score (≥70)
- **1**: Scan successful, needs improvement (<70)
- **130**: Interrupted by user (Ctrl+C)
- **1**: Fatal error occurred

## Examples

### Basic Domain Scan
```bash
python3 mailsec.py google.com
```

### Enterprise Scan with Full Export
```bash
python3 mailsec.py company.com --verbose --export-all --output-dir reports/
```

### API Integration Mode
```bash
python3 mailsec.py domain.com --no-console --export-json --filename-prefix api_
```

## Dependencies

- `dnspython` - DNS resolution and queries
- `requests` - HTTP requests for additional checks
- Python 3.6+ - Core runtime

## Troubleshooting

### DNS Resolution Issues
- Tool automatically falls back to public DNS servers
- Use `--verbose` to see DNS resolver attempts
- Check network connectivity and firewall settings

### SMTP Connection Failures
- Some mail servers block external connections
- Firewall rules may prevent SMTP testing
- Use `--timeout` to adjust connection timeouts

### False Positives
- Network issues may cause temporary failures
- Re-run scan to verify persistent issues
- Check verbose output for detailed error information

## Security Considerations

- Tool performs read-only security assessment
- No intrusive testing or exploitation attempts
- Respects rate limits and connection timeouts
- Safe for production environment scanning

## License

Developed for cybersecurity research and educational purposes.