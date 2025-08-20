# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit

## Overview

The VAPT Toolkit provides a streamlined way to install, configure, and maintain a complete penetration testing environment with over 50+ security tools organized across multiple categories.

## Features

- **Automated Installation**: One-click installation of essential security tools
- **Organized Structure**: Tools categorized by function (web, network, mobile, etc.)
- **Dependency Management**: Automatic installation of required dependencies
- **Update Management**: Bulk update functionality for all installed tools
- **Clean Migration**: Automatic cleanup and migration from older installations

## Tool Categories

- **Exploitation Tools**: Metasploit, Covenant, Merlin, SILENTTRINITY, Impacket
- **Web Testing**: Nikto, XSStrike, Dirsearch, FFUF, Kiterunner, OWASP ZAP
- **Network Scanning**: Nmap, Masscan, Nuclei, Amass
- **Active Directory**: BloodHound, PowerSploit, Rubeus, Certipy
- **Mobile Security**: MobSF, Objection
- **Cloud Security**: Trivy, Checkov, Pacu, ScoutSuite
- **Password Tools**: John the Ripper, Hashcat, SecLists
- **OSINT**: TheHarvester, Recon-ng, SpiderFoot
- **Wireless**: QtTinySA, QSpectrumAnalyzer

## Installation

### Prerequisites
- Ubuntu/Debian-based Linux system
- Non-root user with sudo privileges
- Internet connection

### Quick Start
```bash
# Clone the repository
git clone <repository-url>
cd vapt-toolkit

# Make executable
chmod +x vapt_installer.py

# Run the installer
python3 vapt_installer.py
```

### Installation Options
1. **Install Base Dependencies** - System packages and dependencies
2. **Install Toolkit Packages** - Security tools and frameworks
3. **Install Weakpass Dictionary** - 30GB password cracking wordlist
4. **Update Toolsets** - Update all installed tools

## Directory Structure

```
/vapt/
├── exploits/        # Exploitation frameworks and tools
├── web/             # Web application testing tools
├── network/         # Network scanning and analysis
├── ad_windows/      # Active Directory and Windows tools
├── mobile/          # Mobile security testing
├── cloud/           # Cloud security tools
├── scanners/        # Vulnerability scanners
├── passwords/       # Password cracking tools
├── intel/           # OSINT and reconnaissance
├── wireless/        # Wireless security tools
├── fuzzers/         # Fuzzing tools
├── audit/           # Security audit tools
└── misc/            # Miscellaneous utilities
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

© 2025 Keith Pachulski. All rights reserved.

**License**: MIT License - You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support Development

If you find this project valuable for your security operations:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

---

## Support My Work

If you find my work useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

> **DISCLAIMER**:  
> This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders
> be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
