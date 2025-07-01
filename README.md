# Sud0Recon

<div align="center">
  <h1>🔍 Sud0Recon</h1>
  <p><strong>Next-level automated reconnaissance & vulnerability scanning tool</strong></p>
  <p>Developed by <strong>Sud0-x</strong></p>
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
  [![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
</div>

## 🚀 Features

- **🔧 Modular Plugin Architecture**: Easy-to-extend plugin system for custom scanners
- **⚡ Async/Multi-threaded**: High-performance scanning with asyncio
- **🌐 CLI & REST API**: Use via command line or integrate with other tools
- **📊 Multiple Report Formats**: JSON, HTML, and console output
- **🔍 Subdomain Enumeration**: DNS brute force and API-based discovery
- **🔍 Port Scanning**: TCP connect scans with banner grabbing
- **🛡️ Vulnerability Detection**: Basic CVE checks and default credential detection
- **💾 Database Storage**: SQLite backend for persistent scan results
- **🎨 Colorful Output**: Rich terminal interface with progress indicators
- **🐳 Docker Support**: Easy deployment with Docker containers

## 📦 Installation

### Option 1: Quick Setup (Recommended)
```bash
git clone https://github.com/Sud0-x/Sud0Recon.git
cd Sud0Recon
./sud0recon setup    # Automatic setup - installs everything!
```

### Option 2: Manual Setup
```bash
git clone https://github.com/Sud0-x/Sud0Recon.git
cd Sud0Recon
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Option 2: Using Docker
```bash
docker build -t sud0recon .
docker run -p 8000:8000 sud0recon
```

## 🎯 Usage

### Command Line Interface

#### Basic Scanning
```bash
# Scan a single target
./sud0recon -t example.com

# Scan multiple targets
./sud0recon -t example.com,google.com,github.com

# Aggressive scan (enables all scan types)
./sud0recon -t example.com -A

# Scan with specific output formats
./sud0recon -t example.com -o json,html
```

#### Advanced Options
```bash
# Custom thread count and timeout
./sud0recon -t example.com --threads 100 --timeout 60

# Enable specific scan types
./sud0recon -t example.com --subdomain-enum --port-scan --banner-grab

# Verbose output
./sud0recon -t example.com -vvv

# Custom output directory
./sud0recon -t example.com --output-dir /path/to/reports
```

#### Utility Commands
```bash
# Show help
./sud0recon help
./sud0recon --help

# Run interactive demo
./sud0recon demo

# View latest scan report
./sud0recon view

# List all scan reports
./sud0recon list

# Run setup (first time)
./sud0recon setup
```

### REST API

#### Start the API Server
```bash
uvicorn src.sud0recon.api.main:app --host 0.0.0.0 --port 8000 --reload
```

#### API Endpoints
```bash
# Check server status
curl http://localhost:8000/status

# API documentation
open http://localhost:8000/docs
```

### Docker Usage

#### CLI Mode
```bash
docker run --rm -v $(pwd)/reports:/app/reports sud0recon \
  ./sud0recon -t example.com
```

#### API Mode
```bash
docker run -d -p 8000:8000 --name sud0recon-api sud0recon
```

## 📋 Sample Output

### CLI Output
```
╭─────────────────────────────────────────────────────────────── Sud0Recon ───────────────────────────────────────────────────────────────╮
│ Sud0Recon v1.0.0                                                                                                                             │
│ Next-level automated reconnaissance tool                                                                                                     │
│ by Sud0-x                                                                                                                                    │
╰────────────────────────────────────────────────────────────── sud0x.dev@proton.me ──────────────────────────────────────────────────────╯

Scanning 1 target(s):
  • example.com

Configuration:
  • Threads: 50
  • Timeout: 30s
  • Output: json

Scanning ████████████████████████████████████████ 100% 0:00:00

Scan completed! Found 1 results.
✓ Results saved in JSON format
```

### JSON Report Structure
See [sample_report.json](docs/sample_report.json) for complete example:

```json
{
  "scan_metadata": {
    "scan_id": "sud0recon_20240701_143022",
    "timestamp": "2024-07-01T14:30:22.123456Z",
    "scanner_version": "1.0.0"
  },
  "targets": [
    {
      "target": "example.com",
      "scan_results": {
        "subdomain_enumeration": {...},
        "port_scanning": {...},
        "vulnerability_scan": {...}
      }
    }
  ]
}
```

## 🔌 Plugin Development

Sud0Recon uses a plugin-based architecture. Create custom plugins by inheriting from base classes:

```python
from sud0recon.plugins.base import ReconPlugin

class MyCustomPlugin(ReconPlugin):
    def __init__(self):
        super().__init__("MyPlugin", "Custom reconnaissance plugin")
    
    async def scan(self, target: str, **kwargs):
        # Your scanning logic here
        return {"target": target, "results": "..."}
    
    def get_plugin_info(self):
        return {
            "name": self.name,
            "description": self.description,
            "version": "1.0.0"
        }
```

## 🧪 Testing

```bash
# Run unit tests
python -m pytest tests/ -v

# Run tests with coverage
python -m pytest --cov=sud0recon tests/
```

## 📁 Project Structure

```
Sud0Recon/
├── src/sud0recon/
│   ├── core/                 # Core scanner functionality
│   ├── plugins/              # Scanning plugins
│   ├── api/                  # REST API implementation
│   ├── utils/                # Utility functions
│   └── cli.py                # Command-line interface (launched via sud0recon)
├── tests/                    # Unit tests
├── docs/                     # Documentation and examples
├── reports/                  # Generated scan reports
├── Dockerfile                # Docker container setup
├── requirements.txt          # Python dependencies
├── pyproject.toml           # Project configuration
└── README.md                # This file
```

## 🔒 Security Considerations

- **Ethical Use Only**: Use Sud0Recon only on systems you own or have explicit permission to test
- **Rate Limiting**: Be mindful of scan rates to avoid overwhelming target systems
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Report vulnerabilities responsibly to system owners

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Contact and Support

- **Email**: sud0x.dev@proton.me
- **Issues**: [GitHub Issues](https://github.com/Sud0-x/Sud0Recon/issues)
- **Security**: Please review our [Security Policy](SECURITY.md)

## ⚠️ Disclaimer

Sud0Recon is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The developers assume no liability for misuse of this tool.

---

<div align="center">
  <p><strong>Made with ❤️ by Sud0-x</strong></p>
  <p>🔗 <a href="mailto:sud0x.dev@proton.me">sud0x.dev@proton.me</a></p>
</div>

