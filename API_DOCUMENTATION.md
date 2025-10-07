# Security Assessment Toolkit - API Documentation

Complete REST API documentation for the Security Assessment Toolkit.

## Base URL

```
http://localhost:5000
```

## Authentication

No authentication required for local deployment.

## Response Format

All endpoints return JSON responses in the following format:

### Success Response
```json
{
  "success": true,
  "data": {
    // Tool-specific results
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error message description"
}
```

## Endpoints

### Health Check

**GET** `/api/health`

Check API server status and list available tools.

**Response:**
```json
{
  "status": "healthy",
  "tools": ["headers_audit", "port_services", "ssl_validator", "subjack", "mail_security", "dnssec_analysis"]
}
```

### List Tools

**GET** `/api/tools`

Get detailed information about all available tools.

**Response:**
```json
{
  "headers_audit": {
    "name": "HTTP Security Headers Audit",
    "description": "Audits HTTP security headers for vulnerabilities",
    "endpoint": "/api/headers-audit",
    "parameters": {"domain": "Target domain to audit"}
  },
  // ... other tools
}
```

---

## Security Assessment Endpoints

### HTTP Headers Audit

**POST** `/api/headers-audit`

Analyzes HTTP security headers for web security misconfigurations.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Response Example:**
```json
{
  "success": true,
  "data": {
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
}
```

### Port & Services Enumeration

**POST** `/api/port-services`

Discovers open ports and identifies running services.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Response Example:**
```json
{
  "success": true,
  "data": {
    "target": "example.com",
    "ip": "93.184.216.34",
    "ports": [
      {
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.57",
        "banner": "Apache/2.4.57 (Debian)"
      },
      {
        "port": 443,
        "protocol": "tcp",
        "state": "open",
        "service": "https",
        "product": "Apache httpd",
        "version": "2.4.57"
      }
    ]
  }
}
```

### SSL Certificate Validation

**POST** `/api/ssl-validator`

Validates SSL/TLS certificate chains and security configuration.

**Request Body:**
```json
{
  "domain": "example.com",
  "port": 443
}
```

**Parameters:**
- `domain` (required): Target domain
- `port` (optional): Port number (default: 443)

**Response Example:**
```json
{
  "success": true,
  "data": {
    "hostname": "example.com",
    "port": 443,
    "overall_valid": true,
    "connection": {
      "success": true,
      "tls_version": "TLSv1.3",
      "cipher_suite": ["TLS_AES_256_GCM_SHA384", "TLSv1.3", 256]
    },
    "certificates": [
      {
        "index": 0,
        "type": "leaf",
        "subject": "CN=example.com",
        "validity": {
          "valid": true,
          "not_before": "2024-01-01T00:00:00+00:00",
          "not_after": "2024-12-31T23:59:59+00:00",
          "days_until_expiry": 180
        },
        "hostname_validation": {
          "valid": true,
          "matched_name": "example.com"
        }
      }
    ],
    "warnings": [],
    "errors": []
  }
}
```

### Subdomain Hijacking Assessment

**POST** `/api/subjack`

Identifies subdomain hijacking vulnerabilities through DNS analysis.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Response Example:**
```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "statistics": {
      "total_subdomains": 156,
      "resolved_subdomains": 142,
      "cname_records": 23,
      "vulnerable_subdomains": 2
    },
    "vulnerable_subdomains": [
      {
        "subdomain": "old-blog.example.com",
        "service": "github",
        "cname": "old-blog.github.io",
        "confidence": "high",
        "remediation": "Remove CNAME record or reclaim GitHub Pages"
      }
    ]
  }
}
```

### Mail Server Security Assessment

**POST** `/api/mail-security`

Comprehensive email authentication security analysis (SPF, DKIM, DMARC).

**Request Body:**
```json
{
  "domain": "example.com",
  "timeout": 15
}
```

**Parameters:**
- `domain` (required): Target domain
- `timeout` (optional): DNS timeout in seconds (default: 15)

**Response Example:**
```json
{
  "success": true,
  "data": {
    "scan_summary": {
      "domain": "example.com",
      "security_score": 87,
      "spf_status": "valid",
      "dkim_selectors_found": 3,
      "dmarc_policy": "reject",
      "total_findings": 2,
      "critical_findings": 0,
      "high_findings": 1
    },
    "detailed_results": {
      "domain": "example.com",
      "spf_record": "v=spf1 include:_spf.google.com ~all",
      "spf_valid": true,
      "dkim_selectors_found": ["20161025", "delta", "20210112"],
      "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
      "dmarc_policy": "reject",
      "security_score": 87,
      "findings": [
        {
          "category": "SPF",
          "severity": "Medium",
          "title": "SPF uses SoftFail",
          "description": "SPF record uses ~all instead of -all",
          "recommendation": "Consider using -all for stricter policy"
        }
      ]
    }
  }
}
```

### DNSSEC Security Analysis

**POST** `/api/dnssec-analysis`

Deep DNSSEC validation and trust chain analysis.

**Request Body:**
```json
{
  "domain": "example.com",
  "resolver": "8.8.8.8"
}
```

**Parameters:**
- `domain` (required): Target domain
- `resolver` (optional): Custom DNS resolver IP

**Response Example:**
```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "timestamp": "20241007T123456Z",
    "summary": {
      "status": "Unsigned",
      "validated_chain": false,
      "risk_level": "Medium",
      "note": "Domain does not implement DNSSEC - responses cannot be cryptographically verified",
      "has_dnskey": false,
      "has_parent_ds": false,
      "rrsig_valid": false,
      "ds_matches": false
    },
    "zones": [
      {
        "zone": "example.com",
        "resolver_used": "8.8.8.8",
        "dnskey_entries": [],
        "computed_ds": [],
        "parent_ds": null,
        "parent_ds_matches_computed": false
      }
    ]
  }
}
```

## Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request (missing required parameters) |
| 500 | Internal Server Error |

## Error Handling

Common error scenarios:

### Missing Parameters
```json
{
  "success": false,
  "error": "Domain parameter required"
}
```

### Tool Execution Failure
```json
{
  "success": false,
  "error": "Command timed out"
}
```

### Invalid Domain
```json
{
  "success": false,
  "error": "Invalid domain format"
}
```

## Rate Limiting

No rate limiting implemented in the current version. Consider implementing rate limiting for production deployments.

## Examples

### Python Example
```python
import requests

# Headers audit
response = requests.post('http://localhost:5000/api/headers-audit', 
                        json={'domain': 'example.com'})
result = response.json()

if result['success']:
    print(f"Headers audit completed: {result['data']}")
else:
    print(f"Error: {result['error']}")
```

### JavaScript Example
```javascript
fetch('http://localhost:5000/api/ssl-validator', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    domain: 'example.com',
    port: 443
  })
})
.then(response => response.json())
.then(data => {
  if (data.success) {
    console.log('SSL validation:', data.data);
  } else {
    console.error('Error:', data.error);
  }
});
```

### cURL Examples
```bash
# Basic headers audit
curl -X POST http://localhost:5000/api/headers-audit \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# SSL validation with custom port
curl -X POST http://localhost:5000/api/ssl-validator \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "port": 8443}'

# Mail security with timeout
curl -X POST http://localhost:5000/api/mail-security \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "timeout": 30}'
```

## Integration Notes

1. **Consistent Parameters**: All endpoints use `domain` as the primary parameter
2. **JSON Output**: All tools return structured JSON data
3. **Error Handling**: Comprehensive error reporting with descriptive messages
4. **Timeouts**: Configurable timeouts prevent hanging requests
5. **File Cleanup**: Temporary files are automatically cleaned up after processing

## Deployment Considerations

- **Security**: Run behind reverse proxy with authentication for production
- **Monitoring**: Implement logging and monitoring for API usage
- **Scaling**: Consider containerization for horizontal scaling
- **Rate Limiting**: Implement rate limiting to prevent abuse
- **CORS**: Configure CORS headers for web application integration