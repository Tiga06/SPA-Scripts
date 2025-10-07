# Port & Services Enumeration

Automated network port discovery and service identification tool with comprehensive banner grabbing capabilities.

## Features

- **Intelligent Port Scanning**: Adaptive scanning based on target type (local vs external)
- **Service Fingerprinting**: Detailed service version detection using nmap
- **Banner Grabbing**: Captures service banners for additional intelligence
- **JSON Output**: Structured data for API integration
- **Performance Optimized**: Different scan profiles for local and external targets

## Integration

This tool is integrated into the Security Assessment Toolkit API:

```bash
# Via API
curl -X POST http://localhost:5000/api/port-services \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Direct usage
python3 enumtool.py -t example.com
```

## Requirements

- Python 3.6+
- nmap (system dependency)
- Linux/Unix operating system

## Command Options

| Option | Description |
|--------|-------------|
| `-t TARGET` | Single target to scan |
| `-l FILE` | File containing list of targets |

## Output Format

The tool outputs JSON with the following structure:
```json
{
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
    }
  ]
}
```