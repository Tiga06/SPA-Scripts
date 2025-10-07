# HTTP Security Headers Audit

A lightweight tool for auditing HTTP security headers and identifying web security misconfigurations.

## Features

- **Comprehensive Header Analysis**: Validates all major security headers
- **Advanced CSP Parsing**: Detects unsafe-inline, unsafe-eval, and wildcard sources
- **Server Fingerprinting**: Identifies server versions and technology stack
- **Redirect Analysis**: Tracks redirect chains and security implications
- **JSON Output**: Structured data for API integration
- **Risk Assessment**: Categorizes findings by security impact

## Integration

This tool is integrated into the Security Assessment Toolkit API:

```bash
# Via API
curl -X POST http://localhost:5000/api/headers-audit \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Direct usage
./http_header_audit.sh -j https://example.com
```

## Command Options

| Option | Description |
|--------|-------------|
| `-j` | JSON output only (used by API) |
| `-p` | Pretty-print JSON output |
| `-r` | Don't follow redirects |
| `-f FILE` | Read targets from file |
| `-h` | Show help |

## Sample Output

### CLI Summary
```
=== https://example.com ===
⚠ High Risk Issues: 2
✗ Missing Headers: 3
```

### JSON Output
```json
{
  "url": "https://example.com",
  "headers": {
    "Content-Security-Policy": {
      "status": "present",
      "value": "default-src 'self'",
      "risk": "Low"
    },
    "X-Frame-Options": {
      "status": "missing",
      "risk": "High"
    }
  },
  "server_info": {
    "Server": "Apache/2.4.29"
  },
  "summary": {
    "missing_headers": ["X-Frame-Options"],
    "high_risk_issues": ["X-Frame-Options missing"]
  }
}
```

## Automation

### Daily Scans with Cron
```bash
0 7 * * * /path/to/http_header_audit.sh -f targets.txt > /path/to/reports/$(date +\%F)_report.json
```

## Redirect Handling

By default, the tool follows redirects to analyze the final destination. This provides:
- **Redirect tracking**: Shows redirect count and final URL
- **Security impact**: Identifies potential redirect-based attacks
- **Complete analysis**: Headers from the actual served content

Use `-r` flag to analyze only the original URL without following redirects.

## Security Headers Checked

- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- Permissions-Policy
- Referrer-Policy
- X-XSS-Protection

## Server Information Headers

- Server
- X-Powered-By
- Via
- X-AspNet-Version
- X-Generator