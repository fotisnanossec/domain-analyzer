# Domain Analyzer

## Cybersecurity Reconnaissance Tool

[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-aware-green.svg)](#security-considerations)

> **Cybersecurity Portfolio Project** - Demonstrating OSINT, reconnaissance, and security analysis capabilities for SOC Analyst positions.

The Domain Analyzer is a comprehensive security reconnaissance tool designed for cybersecurity professionals conducting threat assessment and vulnerability analysis. Built with security-first principles, it automates OSINT collection, performs systematic security assessments, and generates professional reports suitable for SOC operations and incident response workflows.


-----

## 🔍 Core Capabilities

### **Reconnaissance & Intelligence Gathering**
- **Multi-Source OSINT Collection**: Automated WHOIS, DNS, SSL certificate, and HTTP header analysis
- **Port Scanning Integration**: Nmap-based service detection and version enumeration
- **Security Header Assessment**: Comprehensive evaluation of web security controls
- **Certificate Chain Analysis**: SSL/TLS security posture evaluation

### **Professional Interface Options**
- **Command-Line Interface**: Scriptable automation for SOC workflows and batch processing
- **Graphical User Interface**: Interactive analysis for detailed investigation and presentation
- **API Integration Ready**: Structured output for integration with SIEM and threat intelligence platforms

### **Advanced Analysis Features**
- **AI-Powered Report Generation**: Local LLM integration for intelligent threat assessment
- **Executive Summary Creation**: Professional reports suitable for management briefings
- **Historical Tracking**: Persistent storage for trend analysis and baseline comparisons
- **Mock Data Testing**: Controlled environments for training and capability demonstration

### **Security-First Design**
- **Input Validation Framework**: Protection against command injection and malformed data
- **Modular Architecture**: Secure separation of concerns with defined interfaces
- **Error Handling**: Comprehensive exception management for operational reliability
- **Configurable Timeouts**: Protection against resource exhaustion attacks

-----

## 🎯 Professional Use Cases

### **SOC Operations & Incident Response**
- **Threat Hunting**: Systematic reconnaissance of suspicious domains and infrastructure
- **Incident Analysis**: Rapid assessment of compromised or suspicious assets
- **Threat Intelligence**: Collection and correlation of IOCs (Indicators of Compromise)
- **Security Baselines**: Establishment of normal security postures for monitoring

### **Vulnerability Assessment & Penetration Testing**
- **External Attack Surface Mapping**: Identification of exposed services and configurations
- **Security Control Validation**: Assessment of implemented security headers and certificates
- **Reconnaissance Phase Support**: Automated OSINT collection for ethical hacking engagements
- **Compliance Auditing**: Verification of security standard implementations

### **Enterprise Security Architecture**
- **Third-Party Risk Assessment**: Evaluation of vendor and partner security postures
- **Supply Chain Security**: Assessment of external dependencies and integrations
- **Digital Asset Inventory**: Systematic cataloging of organizational web presence
- **Continuous Monitoring**: Automated tracking of security posture changes

### **Optimal Target Profile**
**Primary Focus**: Small to medium-sized websites and applications
- **Single-Server Deployments**: Traditional hosting environments with straightforward architectures
- **Standard Web Applications**: Sites utilizing common technologies and configurations
- **SMB Infrastructure**: Organizations without complex CDN or multi-tier architectures

**Note**: While effective for enterprise reconnaissance, this tool is optimized for environments where consistent data collection and analysis provide maximum value for security assessment activities.


-----

## 🚀 Installation and Setup

#### 1\. Prerequisites

Ensure the following tools are installed and available in your system's PATH:

  * **Python 3.x**
  * `whois`
  * `dig` (part of `dnsutils` on Debian/Ubuntu)
  * `nmap`
  * `openssl`
  * `curl`

#### 2\. Dependencies

Install the required Python packages using `pip`:

```bash
pip install -r requirements.txt
```

#### 3\. Configuration

Edit the `config.toml` file to point to your local LLM API server. For example, if you are using LM Studio, configure the `host` and `model` as follows:

```toml
[llm]
host = "192.168.0.52:1234"
model = "mistral-nemo-instruct-2407"
timeout = 4800

[paths]
reports_dir = "reports"
```

-----

## 💻 Usage Examples

### **Command-Line Interface (CLI)**

#### Basic Domain Analysis
```bash
# Analyze a domain for security posture assessment
python main.py example.com

# Analyze an IP address for infrastructure reconnaissance  
python main.py 192.168.1.100
```

#### Mock Data Testing (Training & Demonstration)
```bash
# Generate report from vulnerable site simulation
python main.py --mock-data vulnerable

# Test with secure configuration scenario
python main.py --mock-data secure
```

### **Graphical User Interface (GUI)**
```bash
# Launch interactive analysis interface
python main.py --gui
```

The GUI provides real-time status updates, detailed result visualization, and professional report generation suitable for stakeholder presentations.

### **Professional Usage Scenarios**

#### SOC Analyst Workflow
```bash
# Threat hunting investigation
python main.py suspicious-domain.com

# Incident response reconnaissance
python main.py compromised-site.org

# IOC validation and enrichment
python main.py malicious-ip-address
```

#### Vulnerability Assessment Integration
```bash
# External attack surface enumeration
python main.py target-organization.com

# Third-party security validation
python main.py vendor-portal.com

# Continuous monitoring baseline
python main.py corporate-assets.com
```

-----

## 🏗️ Technical Architecture

### **Project Structure**
```
domain-analyzer/
├── config.toml               # Security configurations and API settings
├── main.py                   # Main entry point with argument validation
├── prompts/                  # AI analysis templates and prompt engineering
│   └── llm_prompt.txt       #   - Structured threat assessment prompts
├── reports/                  # Generated security reports and historical data
├── requirements.txt          # Python dependencies with security considerations
├── scan.sh                  # Standalone reconnaissance script
└── src/                     # Core security analysis modules
    ├── clients.py           #   - Secure API client implementations
    ├── core.py              #   - Primary reconnaissance and analysis engine
    ├── exceptions.py        #   - Security-aware error handling
    ├── gui.py               #   - Professional user interface
    └── mock_data_generator.py #   - Training data and testing scenarios
```

### **Security-First Design Principles**
- **Modular Architecture**: Clean separation between data collection, analysis, and reporting
- **Input Validation**: Systematic validation of all external inputs and API responses  
- **Error Handling**: Comprehensive exception management preventing information disclosure
- **Process Isolation**: Secure subprocess execution with controlled environments
- **Configurable Security**: Externalized security settings for operational flexibility

-----



## 📋 License & Professional Use

This project is licensed under the MIT License, making it suitable for:
- **Portfolio Demonstration**: Showcasing technical capabilities to potential employers
- **Educational Use**: Learning and teaching cybersecurity reconnaissance techniques  
- **Professional Development**: Foundation for building enterprise security tools
- **Open Source Contribution**: Community collaboration on security tool development

**Note**: This tool is designed for legitimate security testing and assessment activities. Users are responsible for ensuring compliance with applicable laws and regulations, including proper authorization for all reconnaissance activities.

---



















