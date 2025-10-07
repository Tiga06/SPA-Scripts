# DNSSEC Security Analysis

Research-grade DNSSEC validation tool that performs comprehensive DNS Security Extensions analysis with enhanced status reporting.

## Features

### DNSSEC Validation
- **Complete Chain Analysis** - Validates DNSSEC from domain to root
- **Cryptographic Verification** - RRSIG signature validation
- **Trust Chain Validation** - DS record matching and verification
- **Status Differentiation** - Distinguishes between Unsigned, Broken, and Valid DNSSEC
- **Risk Assessment** - Provides security risk levels and recommendations

### Advanced Features
- **Multi-Zone Analysis** - Walks entire delegation chain (domain → parent → root)
- **Authoritative NS Consistency** - Checks consistency across all authoritative nameservers
- **NSEC/NSEC3 Detection** - Identifies denial of existence mechanisms
- **CDS/CDNSKEY Support** - Analyzes child-submission records for automated updates
- **Multiple Output Formats** - JSON, CSV, and human-readable TXT reports

### Technical Capabilities
- **Resolver Flexibility** - Uses system resolvers or custom resolver IPs
- **Fallback Mechanisms** - Automatic fallback to public DNS (8.8.8.8, 1.1.1.1)
- **UDP/TCP Handling** - Automatic TCP fallback for truncated responses
- **Error Resilience** - Comprehensive error handling and reporting

## Integration

This tool is integrated into the Security Assessment Toolkit API:

```bash
# Via API
curl -X POST http://localhost:5000/api/dnssec-analysis \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "resolver": "8.8.8.8"}'

# Direct usage
python3 dnssec_analysis.py -d example.com
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain to analyze (required) |
| `--resolver` | Custom DNS resolver IP to use |
| `--no-ns-check` | Skip authoritative nameserver consistency checks |
| `--out` | Output directory (default: ~/Downloads) |

## Output Formats

The tool generates three complementary output files:

### 1. JSON Report (`dnssec_deep_TIMESTAMP.json`)
Detailed machine-readable analysis including:
- Complete zone hierarchy data
- DNSKEY entries with algorithms and key tags
- RRSIG validation results
- DS record comparisons
- NS consistency analysis

### 2. CSV Summary (`dnssec_deep_summary_TIMESTAMP.csv`)
One-line summary with:
- Domain name
- Validation status (True/False)
- Summary reasons
- Timestamp

### 3. Human-Readable Report (`dnssec_deep_report_TIMESTAMP.txt`)
Formatted text report with:
- Executive summary
- Zone-by-zone analysis
- Key validation details
- NS consistency results

## Analysis Components

### DNSSEC Chain Validation
1. **DNSKEY Retrieval** - Fetches DNSKEY records from target domain
2. **RRSIG Verification** - Validates RRSIG signatures over DNSKEY records
3. **DS Computation** - Computes DS records (SHA-1 and SHA-256) from DNSKEYs
4. **Parent DS Lookup** - Retrieves DS records from parent zone
5. **Chain Verification** - Validates DS record matching between parent and child

### Authoritative NS Consistency
- Queries all authoritative nameservers for the domain
- Compares DNSKEY records across all servers
- Identifies inconsistencies that could break DNSSEC validation
- Groups nameservers by DNSKEY fingerprints

### Security Analysis
- **Algorithm Assessment** - Identifies cryptographic algorithms in use
- **Key Strength Analysis** - Examines key sizes and types
- **Signature Validity** - Verifies cryptographic signatures
- **Trust Anchor Validation** - Validates chain to DNS root

## Example Output

### Console Output
```
Starting deep DNSSEC audit for: example.com
example.com validated=True
 - DNSKEY present
 - At least one valid RRSIG over DNSKEY
 - Parent DS matches child's computed DS

Saved JSON -> /home/user/Downloads/dnssec_deep_20241007T123456Z.json
Saved CSV  -> /home/user/Downloads/dnssec_deep_summary_20241007T123456Z.csv
Saved TXT  -> /home/user/Downloads/dnssec_deep_report_20241007T123456Z.txt
```

### JSON Structure
```json
{
  "domain": "example.com",
  "timestamp": "20241007T123456Z",
  "summary": {
    "validated_chain": true,
    "reasons": [
      "DNSKEY present",
      "At least one valid RRSIG over DNSKEY",
      "Parent DS matches child's computed DS"
    ]
  },
  "zones": [
    {
      "zone": "example.com",
      "dnskey_entries": [...],
      "dnskey_rrsigs": [...],
      "computed_ds": [...],
      "parent_ds": [...],
      "parent_ds_matches_computed": true
    }
  ],
  "ns_consistency": {
    "consistent": true,
    "ns": [...]
  }
}
```

## Validation Logic

The tool determines DNSSEC validation status based on:

1. **DNSKEY Presence** - Domain must have DNSKEY records
2. **RRSIG Validity** - At least one valid RRSIG over DNSKEY must exist
3. **DS Chain Match** - Parent DS records must match computed child DS records
4. **Cryptographic Verification** - All signatures must validate cryptographically

## Common Use Cases

### Security Assessment
- Verify DNSSEC implementation correctness
- Identify configuration issues
- Validate trust chain integrity

### Troubleshooting
- Diagnose DNSSEC validation failures
- Identify inconsistencies across nameservers
- Debug DS record mismatches

### Research & Analysis
- Study DNSSEC deployment patterns
- Analyze cryptographic algorithm usage
- Research DNS security implementations

## Technical Details

### Supported Record Types
- **DNSKEY** - DNS public keys
- **RRSIG** - Resource record signatures
- **DS** - Delegation signer records
- **NSEC/NSEC3** - Denial of existence records
- **CDS/CDNSKEY** - Child delegation signer records

### Cryptographic Algorithms
- RSA/SHA-1, RSA/SHA-256, RSA/SHA-512
- ECDSA P-256/SHA-256, ECDSA P-384/SHA-384
- EdDSA (Ed25519, Ed448)

### DNS Transport
- UDP with automatic TCP fallback
- Configurable timeouts (6 seconds default)
- Multiple resolver support with fallback

## Troubleshooting

### Common Issues

**No DNSKEY Found**
- Domain may not have DNSSEC enabled
- Check if domain is properly signed

**RRSIG Validation Failures**
- Clock skew between systems
- Expired signatures
- Key rollover in progress

**DS Record Mismatches**
- Parent zone not updated after key rollover
- Algorithm mismatch between parent and child

**NS Inconsistency**
- Nameservers serving different DNSKEY sets
- DNS propagation delays
- Configuration synchronization issues

### Debug Tips
- Use `--resolver 8.8.8.8` to test with specific resolver
- Check timestamps in RRSIG records for expiration
- Verify parent zone DS records manually

## Dependencies

- **dnspython** - DNS protocol implementation
- **colorama** - Terminal color output (optional)
- **Python 3.6+** - Core runtime

## Security Considerations

- Tool performs read-only DNS queries
- No modification of DNS records
- Safe for production environment analysis
- Respects DNS rate limits and timeouts

## License

Educational and research use. Ensure proper authorization before analyzing domains you don't own.