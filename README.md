# 🛡️ SubSpector 
[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

**Advanced Subdomain Monitoring & Security Analysis Tool**

SubSpector is a comprehensive security analysis tool designed to discover, monitor, and analyze subdomains for security vulnerabilities. It provides real-time monitoring, SSL certificate analysis, security headers assessment, and subdomain takeover detection.


## ✨ Key Features

- 🔍 **Comprehensive Subdomain Discovery** - Advanced enumeration using multiple sources
- 🛡️ **Security Analysis** - SSL certificates, security headers, and vulnerability assessment
- 🔒 **Security Assessment** - Comprehensive 0-100 security rating system
- ⚠️ **Takeover Detection** - Identifies potential subdomain takeover vulnerabilities
- 📊 **Real-time Monitoring** - Continuous monitoring with customizable intervals
- 📈 **Detailed Reporting** - JSON reports with comprehensive statistics
- 🌐 **Cross-platform** - Works on Windows, Linux, and macOS


## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- Subfinder

### Installation

#### Linux/macOS (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/subspector.git
cd subspector

# Run automatic installation
chmod +x install_linux.sh
./install_linux.sh

# Start analyzing
./run_subspector.sh reddit.com -m analysis
```

#### Windows

```cmd
# Clone the repository
git clone https://github.com/your-username/subspector.git
cd subspector

# Install dependencies
pip install -r requirements.txt

# Subfinder will be downloaded automatically on first run

# Run analysis
python subspector.py reddit.com -m analysis
```

## 📊 Usage Examples

### Security Analysis Mode (Default)
```bash
python subspector.py example.com -m security
```

### Comprehensive Analysis Mode
```bash
python subspector.py reddit.com -m analysis
```

### Continuous Monitoring Mode
```bash
python subspector.py facebook.com -m monitor -i 600
```

### Limited Analysis (for testing)
```bash
python subspector.py github.com -m analysis -n 50
```

## 🔧 Analysis Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `security` | Quick security assessment | Security audits, compliance checks |
| `analysis` | Comprehensive subdomain analysis | Detailed reconnaissance, full assessment |
| `monitor` | Continuous monitoring | Real-time security monitoring |

## 📋 Output Examples

### Security Score Dashboard
```
🛡️ Security Analysis for: reddit.com
├── 🔐 SSL Certificate: ✅ Valid (90 days remaining)
├── 🛡️ Security Headers: ✅ 8/10 implemented  
├── ⚠️ Subdomain Takeover: ✅ Protected
└── 📊 Overall Score: 85/100
```

### Comprehensive Analysis Summary
```
📊 Analysis Results:
├── 📍 Total Subdomains: 156
├── 🟢 Active: 142
├── 🔴 Inactive: 14
└── 🛡️ Security Distribution:
    ├── Excellent (90-100): 45 domains
    ├── Good (70-89): 67 domains  
    ├── Fair (50-69): 25 domains
    └── Critical (<50): 19 domains
```

## 📁 Project Structure

```
SubSpector/
├── subspector.py          # Main application
├── scanner.py             # Subdomain discovery engine (auto-downloads subfinder)
├── security_headers.py    # Security headers analysis
├── config.py             # Configuration settings
├── logger.py             # Logging system
├── requirements.txt      # Python dependencies
├── install_linux.sh      # Linux installation script
├── LICENSE              # MIT License
└── README.md           # This file
```

## 🔒 Security Features

### SSL/TLS Certificate Analysis
- Certificate validity and expiration checking
- Issuer and subject information
- Certificate chain validation
- Multiple validation methods

### Security Headers Assessment
- **HSTS** - HTTP Strict Transport Security
- **CSP** - Content Security Policy
- **X-Frame-Options** - Clickjacking protection
- **X-Content-Type-Options** - MIME sniffing protection
- **Referrer-Policy** - Referrer information control
- And 6+ additional security headers

### Subdomain Takeover Detection
- CNAME record analysis
- Service-specific vulnerability patterns
- Risk assessment and recommendations


## 🔧 Troubleshooting

### Common Issues

**Permission Denied (Linux)**
```bash
chmod +x subspector.py install_linux.sh
```

**Missing Dependencies**
```bash
pip install --upgrade -r requirements.txt
```

**Subfinder Download Issues**
```bash
# Subfinder downloads automatically on first run
# If download fails, check internet connection or install manually:

# Linux/macOS:
wget https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip
unzip subfinder_linux_amd64.zip
chmod +x subfinder

# Windows: Download from GitHub releases page
# https://github.com/projectdiscovery/subfinder/releases
```

**DNS Resolution Issues**
```bash
# Test DNS connectivity
nslookup google.com 8.8.8.8
```


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ Security

If you discover a security vulnerability, please send an email to security@subspector.dev. All security vulnerabilities will be promptly addressed.


## 🏆 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) - For the excellent subfinder tool


</div>
