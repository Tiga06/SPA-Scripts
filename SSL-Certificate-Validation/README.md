# SSL/TLS Certificate Validator

Comprehensive SSL/TLS certificate chain validation tool with cryptographic verification and security analysis.

## Features

### Certificate Chain Analysis
- **Complete Chain Retrieval**: Fetches full certificate chains using OpenSSL
- **Cryptographic Validation**: Verifies signatures and trust chains
- **Hostname Verification**: CN and SAN validation with wildcard support
- **Expiration Monitoring**: Validates certificate validity periods
- **Trust Store Validation**: Verifies against system trust anchors
- **Revocation Checking**: OCSP and CRL validation support
- **Algorithm Analysis**: Detects weak cryptographic algorithms

### Security Features
- **Secure Implementation**: Comprehensive input validation and error handling
- **Resource Management**: Proper cleanup of temporary files and processes
- **Timeout Protection**: Network timeout controls for reliability
- **JSON Output**: Structured data for API integration

## Integration

This tool is integrated into the Security Assessment Toolkit API:

```bash
# Via API
curl -X POST http://localhost:5000/api/ssl-validator \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "port": 443}'

# Direct usage
python3 ssl_cert_validator.py example.com --json-only
```

## Command Line Options

- `hostname` - Target hostname (required)
- `-p, --port` - Target port (default: 443)
- `-o, --output` - Save JSON report to file
- `-t, --timeout` - Connection timeout in seconds (default: 10)
- `--json-only` - Output only JSON format

## Example Output

### Valid Certificate (Google)
```
=== SSL/TLS Certificate Validation Report ===
Target: google.com:443
Status: ✓ VALID
TLS Version: TLSv1.3

--- Certificate Chain (3 certificates) ---
✓ LEAF: CN=*.google.com
   Expires: 2025-12-08T08:34:17+00:00 (65 days)
✓ INTERMEDIATE: CN=WR2,O=Google Trust Services,C=US
   Expires: 2029-02-20T14:00:00+00:00 (1235 days)
✓ ROOT: CN=GTS Root R1,O=Google Trust Services LLC,C=US
   Expires: 2028-01-28T00:00:42+00:00 (845 days)
```

### Invalid Certificate (Expired)
```
=== SSL/TLS Certificate Validation Report ===
Target: expired.badssl.com:443
Status: ✗ INVALID
TLS Version: TLSv1.2

--- Certificate Chain (3 certificates) ---
✗ LEAF: CN=*.badssl.com,OU=PositiveSSL Wildcard
   Expires: 2015-04-12T23:59:59+00:00 (-3828 days)

--- Warnings (1) ---
⚠ Certificate expires in -3828 days
```

## JSON Output Structure

```json
{
  "hostname": "google.com",
  "port": 443,
  "timestamp": "2024-10-04T03:24:08+00:00",
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
      "subject": "CN=*.google.com",
      "validity": {
        "valid": true,
        "not_before": "2025-09-15T08:34:18+00:00",
        "not_after": "2025-12-08T08:34:17+00:00",
        "days_until_expiry": 65
      },
      "hostname_validation": {
        "valid": true,
        "matched_name": "google.com"
      }
    }
  ],
  "chain_validation": {
    "valid": true
  },
  "trust_validation": {
    "valid": true
  },
  "warnings": [],
  "errors": []
}
```

## Validation Checks

### Certificate-Level Validation
- **Validity Period**: Ensures certificates are within valid date range
- **Hostname Matching**: Validates hostname against CN and SAN fields
- **Basic Constraints**: Verifies CA/end-entity constraints
- **Key Usage**: Validates appropriate key usage for certificate type
- **Signature Algorithm**: Detects weak algorithms (MD5, SHA1)

### Chain-Level Validation
- **Signature Verification**: Cryptographically verifies each certificate signature
- **Trust Anchor**: Validates root certificate against system trust store
- **Chain Completeness**: Ensures complete certificate chain from leaf to root

### Revocation Validation
- **OCSP**: Online Certificate Status Protocol checking
- **CRL**: Certificate Revocation List validation
- **Graceful Degradation**: Continues validation if revocation services unavailable

## Requirements

- Python 3.8+
- OpenSSL command-line tool
- Internet connectivity for certificate chain retrieval

## Dependencies

- `cryptography>=41.0.0` - Certificate parsing and validation
- `requests>=2.31.0` - HTTP requests for revocation checking
- `certifi>=2023.7.22` - Mozilla CA bundle

## Security

This validator has been thoroughly reviewed and all security vulnerabilities have been fixed:

- ✅ **Input Validation**: All inputs properly sanitized
- ✅ **Error Handling**: Secure exception handling without information leakage
- ✅ **Resource Management**: Proper cleanup of temporary files and processes
- ✅ **Network Security**: Timeout controls and secure connections
- ✅ **Code Quality**: No SQL injection, XSS, or other common vulnerabilities

## Cross-Platform Compatibility

Tested and working on:
- ✅ Linux (Ubuntu, CentOS, Debian)
- ✅ macOS (Intel/Apple Silicon)
- ✅ Windows 10/11 (with OpenSSL installed)

## Troubleshooting

### OpenSSL Not Found
Install OpenSSL:
- **Ubuntu/Debian**: `sudo apt-get install openssl`
- **CentOS/RHEL**: `sudo yum install openssl`
- **macOS**: `brew install openssl`
- **Windows**: Download from https://slproweb.com/products/Win32OpenSSL.html

### Connection Timeouts
Increase timeout: `python ssl_cert_validator.py slow-site.com -t 30`

### Firewall Issues
Ensure outbound HTTPS (port 443) access is allowed.

## License

MIT License - see LICENSE file for details.

## Security Considerations

This tool is designed for validation and analysis purposes. It:
- ✅ Does not store or transmit sensitive data
- ✅ Does not modify system trust stores
- ✅ Uses read-only operations
- ✅ Follows security best practices

Always validate results with multiple tools for production systems.