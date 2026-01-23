# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit

## Overview

The VAPT Toolkit provides a streamlined way to install, configure, and maintain a complete penetration testing environment with 50+ security tools and custom automation frameworks organized across multiple categories. This is desiged to work on Ubuntu 22.

## Features

- **Automated Installation**: One-click installation of essential security tools
- **Organized Structure**: Tools categorized by function (web, network, wireless, cloud, etc.)
- **Custom Automation**: Integrated custom tools for OSINT, O365 testing, wireless attacks, and reporting
- **Dependency Management**: Automatic installation of required dependencies
- **Multi-Client Support**: Session resume and target-specific directory organization
- **Update Management**: Bulk update functionality for all installed tools

## Tool Categories and Tooling (Not Inclusive)

### Exploitation Tools
Metasploit, Covenant, Merlin, SILENTTRINITY, Impacket

### Web Application Testing
Nikto, XSStrike, Dirsearch, FFUF, Kiterunner, OWASP ZAP, SQLMap, BurpSuite

### Network Scanning & Enumeration
Nmap, Masscan, Nuclei, Amass

### Active Directory
BloodHound, PowerSploit, Rubeus, Certipy, Impacket suite

### Mobile Security
MobSF, Objection

### Cloud Security
Trivy, Checkov, Pacu, ScoutSuite, custom S3/EC2 enumeration modules

### Password & Credential Tools
John the Ripper, Hashcat, SecLists

### OSINT & Reconnaissance
TheHarvester, Recon-ng, SpiderFoot

## Custom Tools

### OSINT Collection Framework
- **CT Mining**: Certificate Transparency log enumeration and subdomain discovery
- **OSINT Correlator**: Automated intelligence correlation across multiple data sources
- **Recon Automation**: Integrated reconnaissance workflow with target profiling

### Office 365 Security Testing
- **O365 Enumerator**: User enumeration via multiple Microsoft endpoints
- **Spray Framework**: Intelligent password spraying with lockout detection and timing controls
- **Token Analysis**: OAuth token extraction and analysis utilities

### Wireless Security Testing
- **Attack Automation**: Custom Python framework integrating aircrack-ng suite
- **Handshake Capture**: Automated WPA/WPA2 handshake collection with mdk3 deauth
- **Captive Portal**: Portal cloning and credential capture framework
- **Enterprise Testing**: 802.1X and WPA3 assessment modules
- **Hardware Support**: Optimized for USB adapters and Raspberry Pi deployment

### Reporting & Documentation
- **Report Generator**: Automated penetration test report generation from scan data
- **Finding Consolidator**: Multi-tool output parsing and deduplication
- **Evidence Manager**: Screenshot and proof-of-concept organization
- **Compliance Mapper**: Finding-to-framework mapping (NIST 800-53, CMMC, etc.)

## Installation

### Prerequisites
- Ubuntu 22
- Internet connection

### Quick Start
```bash
# Clone the repository
git clone https://github.com/sec0ps/va-pt.git
cd va-pt

# Run the installer
python3 vapt_installer.py
```

## Usage

Run the installer script and select from the menu options:
- Install base system dependencies first
- Install security tool packages
- Optionally install large wordlists
- Use update function to keep tools current

## Professional Services

### Red Cell Security, LLC
For enterprise deployments, custom integrations, or professional security assessments:

- **Email**: keith@redcellsecurity.org
- **Website**: www.redcellsecurity.org
- **Services**: Custom RF security solutions, threat hunting, defensive countermeasures

## Disclaimer

This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

## License & Copyright

**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2026 Keith Pachulski. All rights reserved.

**License**: MIT License - You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support Development

If you find this project valuable for your security operations:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)
