# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit

## Overview

The VAPT Toolkit installs, configures, and maintains a complete penetration testing environment with 50+ third-party security tools plus a growing set of custom automation frameworks written for authorized VAPT engagements. Alongside the installer it ships three standalone orchestration subsystems, a reporting and deliverable pipeline, a wireless attack framework, and a large collection of purpose-built recon, enumeration, and exploitation tools. The base environment targets Ubuntu 22.

## Repository Layout

| Path | Contents |
| --- | --- |
| `vapt-installer.py` | Menu-driven installer and updater for the full tool environment |
| `automation/` | Deterministic network exploitation orchestrator (nmap plus Metasploit) |
| `browser-automation/` | MITM browser autopwn orchestrator (bettercap, Responder, browser_autopwn2) |
| `darkweb-recon/` | Tor-based dark web recon with a multi-user web console |
| `tools/` | Custom recon, enumeration, exploitation, and utility scripts |
| `reporting/` | Scan-output parsers and report generators for client deliverables |
| `raspbian/` | Wireless attack framework and portable deployment scripts |
| `misc/` | Lab support tooling |

## Installation

### Prerequisites

- Ubuntu 22
- Internet connection
- Root or sudo access for tool installation

### Quick Start

```
# Clone the repository
git clone https://github.com/sec0ps/va-pt.git
cd va-pt

# Run the installer
sudo python3 vapt-installer.py
```

The installer provisions the `/vapt` directory structure, installs base system dependencies, pulls the security tool packages, optionally installs large wordlists, and provides a bulk update path to keep everything current. bettercap is pulled from the official GitHub release binary rather than built from source. Old directory layouts from previous installs are cleaned up automatically.

## Core Automation Frameworks

### Network Exploitation Orchestrator (`automation/`)

A deterministic exploitation pipeline that discovers live hosts, scans them for known-vulnerable services, corroborates the findings, and optionally fires matching Metasploit modules. The pipeline runs discover, scan, analyze, check, and fire, with a rich terminal dashboard showing live status. nmap handles discovery and detection through the vulners NSE script, and Metasploit handles exploitation over msfrpcd.

Default mode is check only, which finds and verifies without ever exploiting. autopwn mode fires reverse payloads only at candidates that checked vulnerable or likely. Runs are resumable through a JSON checkpoint, and the host firewall is snapshotted, disabled for the run so callbacks are not blocked, and restored on teardown. Configuration is zero-touch, with the msfrpcd password generated and stored at `0600` on first run.

```
# check only, the default
sudo python3 orchestrator.py 10.0.0.0/24

# autopwn against a confirmed target
sudo python3 orchestrator.py --mode autopwn 10.0.0.5

# resume an interrupted run
sudo python3 orchestrator.py --resume 10.0.0.0/24
```

### MITM Browser Autopwn (`browser-automation/`)

A standalone MITM browser autopwn orchestrator for authorized internal testing. It ties three off-the-shelf tools into one run behind a three-panel TUI and a scope guard. bettercap handles layer-two ARP spoofing plus a transparent HTTP proxy with JavaScript injection and optional DNS spoofing, Responder handles LLMNR, NBT-NS, and mDNS poisoning with SMB NetNTLM capture, and Metasploit browser_autopwn2 handles fingerprinting and exploitation.

The tool self-bootstraps a virtualenv on first run, resolves and caches dependency paths, and always strips operator addresses and the default gateway from the spoof set so the local segment cannot be blackholed. Cleartext HTTP victims get a hidden one-pixel iframe injected into rewritten responses, while HTTPS-only victims are handled through an optional DNS-spoofed lure domain that redirects to the autopwn landing.

```
# targeted run against three hosts
sudo python3 orchestrator.py -i eth0 -t 10.0.0.10,10.0.0.11,10.0.0.12 --lhost 10.0.0.5

# full subnet, self and gateway stripped automatically
sudo python3 orchestrator.py -i eth0 --full-subnet --lhost 10.0.0.5
```

### Dark Web Recon Console (`darkweb-recon/`)

Tor-based dark web reconnaissance for authorized OSINT and VAPT engagements. It runs manual searches from the CLI and scheduled or on-demand content searches from a multi-user Flask web console, with all fetching routed through a managed Tor instance using per-engagement stream isolation. Search sources query Ahmia over Tor, watch terms drive both the queries and a match engine over returned titles and snippets, and findings are deduplicated per workspace with a triage status of new, confirmed, or dismissed.

Watch-term types include literal, regex, domain, email, ipv4, ipv6, credential, card, btc, eth, and hash, with credential and card matches masked at rest by default. Admins manage users, workspaces, sources, terms, and schedules, while operators are scoped to their assigned workspaces. The stack ships as a Docker image with an install script.

```
cd va-pt/darkweb-recon
sudo bash install.sh
docker compose up -d
```

Because this tool fetches hostile content from onion services, run it inside a dedicated research VM or a segmented network. A container is packaging, not an isolation boundary.

## Custom Tooling (`tools/`)

### Reconnaissance and OSINT

- **quick_recon.py** - Penetration testing reconnaissance automation with target profiling
- **passive_targeting.py** - Strictly passive internal target discovery that catalogs new source addresses and infers subnet CIDRs from observed broadcast, multicast, and unicast traffic
- **o365_recon_spray.py** - O365 user enumeration and password spraying with lockout detection and timing controls
- **github_toolsearch.py** - GitHub search automation for tooling and code discovery

### Enumeration

- **ad_enum.py** - Active Directory enumeration for authorized testing
- **windows_enum.py** - Windows system enumeration built on the Impacket suite
- **mdns_enum.py** - System information enumeration over mDNS
- **mysqlaudit.py** - MySQL security assessment using mysql.connector
- **dell_idrac_snmp.py** - Dell iDRAC information extraction over SNMP

### Active Directory and Credentials

- **auto_certipy.py** - Certipy wrapper chaining find, exploit, and authenticate
- **auto_john.py** - John the Ripper wrapper that locates john and wordlists, then cracks

### Exploitation

- **CVE-2024-6387.py** - Complete exploit for regreSSHion (CVE-2024-6387)
- **wsdl_auto_exploit.py** - WSDL recon with JNDI and XXE probing over DNS or TCP callbacks
- **ldap_inject_fuzzer.py** - Advanced LDAP injection fuzzer
- **cisco_tftp.py** - Cisco TFTP configuration retrieval
- **stealcookie.js** - Browser cookie extraction payload

### Network Discovery and Utilities

- **l2_broadcast.py** - Listener for layer-two broadcast and discovery traffic
- **if2cidr.py** - Convert `ifconfig`, `ip addr`, or `ipconfig` output to nmap-ready CIDRs
- **proxy_test.py** - Test whether a service is acting as an open proxy
- **tsexit.py** - Manage the Tailscale exit node
- **ap-parse.sh** - Access point capture parsing
- **wordlist.sh** - Wordlist preparation helper

## Reporting and Deliverables (`reporting/`)

- **nessus_parser.py** - Nessus file merger and report generator
- **burp_zap_parser.py** - Parse OWASP ZAP and Burp Suite reports into DOCX
- **vapt_report_parser.py** - Unified parser converting Nessus, Burp, and ZAP XML plus manual report DOCX into DOCX deliverables and DefectDojo JSON
- **zap_cleanup.py** - ZAP output normalization and noise reduction

## Wireless Attack Framework (`raspbian/`)

- **wireless_attack_framework.py** - Custom Python framework integrating the aircrack-ng suite, with automated WPA/WPA2 handshake capture using mdk3 deauth
- **wireless-connect.py** and **wireless-mgmt.py** - Interface and connection management for portable deployment
- **installer.py** - Standalone installer for portable wireless deployments

## Lab and Misc (`misc/`)

- **deploy_metasploitable.py** - Deploy and tear down Metasploitable2 on a Docker macvlan for lab targets
- **if2cidr.py** - Interface-to-CIDR helper for lab scoping

## Installed Tool Categories

The installer provisions a broad third-party tool set across the following categories.

| Category | Tools |
| --- | --- |
| Exploitation | Metasploit, Covenant, Merlin, SILENTTRINITY, Impacket |
| Web Application | Nikto, XSStrike, Dirsearch, FFUF, Kiterunner, OWASP ZAP, SQLMap, Burp Suite |
| Network Scanning | Nmap, Masscan, Nuclei, Amass |
| Active Directory | BloodHound, PowerSploit, Rubeus, Certipy, Impacket suite |
| Mobile Security | MobSF, Objection |
| Cloud Security | Trivy, Checkov, Pacu, ScoutSuite |
| Credentials | John the Ripper, Hashcat, SecLists |
| OSINT | theHarvester, Recon-ng, SpiderFoot |
| MITM and Capture | bettercap, Responder |

## Professional Services

### Red Cell Security, LLC

For enterprise deployments, custom integrations, or professional security assessments:

- **Email**: <operations@redcellsecurity.org>
- **Website**: [www.redcellsecurity.org](http://www.redcellsecurity.org)
- **Services**: Custom RF security solutions, threat hunting, defensive countermeasures

## Authorization and Disclaimer

This toolkit is intended for authorized security testing only. Users are responsible for ensuring compliance with all applicable laws and regulations. Unauthorized use of these tools may violate local, state, federal, and international laws.

This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

## License and Copyright

**Company**: Red Cell Security, LLC
**Email**: <operations@redcellsecurity.org>
**Website**: [www.redcellsecurity.org](http://www.redcellsecurity.org)

© 2026 Keith Pachulski. All rights reserved.

**License**: MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support Development

If you find this project valuable for your security operations:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)
