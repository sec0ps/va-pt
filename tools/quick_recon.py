#!/usr/bin/env python3
# =============================================================================
# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This script provides an automated installation and management system
#          for a vulnerability assessment and penetration testing
#          toolkit. It installs and configures security tools across multiple
#          categories including exploitation, web testing, network scanning,
#          mobile security, cloud security, and Active Directory testing.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# NOTICE: This toolkit is intended for authorized security testing only.
#         Users are responsible for ensuring compliance with all applicable laws
#         and regulations. Unauthorized use of these tools may violate local,
#         state, federal, and international laws.
#
# =============================================================================

import argparse
import json
import re
import subprocess
import sys
import socket
import requests
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import concurrent.futures
import ipaddress
import shutil
import urllib3
import dns.resolver
import time
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ReconAutomation:
    def __init__(self, domain: str, ip_ranges: List[str], output_dir: str, client_name: str):
        self.domain = domain
        self.ip_ranges = ip_ranges
        self.output_dir = Path(output_dir)
        self.client_name = client_name

        # Initialize requests session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Load or create config
        self.config_file = Path('quick_recon_config.json')
        self.config = self.load_config()

        # Locate theHarvester
        self.theharvester_path = self._locate_theharvester()

        self.results = {
            'timestamp': datetime.now().isoformat(),
            'domain': domain,
            'ip_ranges': ip_ranges,
            'client': client_name,
            'scope_validation': {},
            'dns_enumeration': {},
            'technology_stack': {},
            'email_addresses': [],
            'breach_data': {},
            'network_scan': {},
            's3_buckets': {},
            'azure_storage': {},
            'gcp_storage': {},
            'github_secrets': {},
            'linkedin_intel': {},
            'asn_data': {},
            'subdomain_takeovers': []
        }

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def print_banner(self):
        """Print script banner"""
        banner = f"""
{Colors.HEADER}{'='*80}
    PENETRATION TESTING RECONNAISSANCE AUTOMATION
    Client: {self.client_name}
    Domain: {self.domain}
    Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*80}{Colors.ENDC}
"""
        print(banner)

    def print_section(self, title: str):
        """Print section header"""
        print(f"\n{Colors.OKBLUE}[*] {title}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}{'='*80}{Colors.ENDC}")

    def print_success(self, message: str):
        """Print success message"""
        print(f"{Colors.OKGREEN}[+] {message}{Colors.ENDC}")

    def print_warning(self, message: str):
        """Print warning message"""
        print(f"{Colors.WARNING}[!] {message}{Colors.ENDC}")

    def print_error(self, message: str):
        """Print error message"""
        print(f"{Colors.FAIL}[-] {message}{Colors.ENDC}")

    def print_info(self, message: str):
        """Print info message"""
        print(f"{Colors.OKCYAN}[i] {message}{Colors.ENDC}")

    def run_command(self, command: List[str], timeout: int = 60) -> Optional[str]:
        """Execute system command and return output"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.stdout if result.returncode == 0 else None
        except subprocess.TimeoutExpired:
            self.print_error(f"Command timed out: {' '.join(command)}")
            return None
        except Exception as e:
            self.print_error(f"Command failed: {e}")
            return None

    def _download_file(self, url: str, output_path: Path, max_size_mb: int = 10) -> bool:
            """Download file from URL with size limit"""
            try:
                # HEAD request to check file size first
                head_response = self.session.head(url, timeout=5, allow_redirects=True, verify=False)
                content_length = int(head_response.headers.get('Content-Length', 0))

                # Check size limit (convert MB to bytes)
                if content_length > 0 and content_length > (max_size_mb * 1024 * 1024):
                    self.print_warning(f"Skipping file (too large: {content_length/(1024*1024):.1f}MB)")
                    return False

                # Download file
                response = self.session.get(url, timeout=30, stream=True, verify=False)
                if response.status_code == 200:
                    with open(output_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                    return True
            except Exception as e:
                self.print_error(f"Download failed: {e}")
                return False

            return False

    def _is_sensitive_file(self, filename: str) -> tuple[bool, str]:
            """Determine if a file is potentially sensitive based on extension and name patterns"""
            filename_lower = filename.lower()

            # Image extensions to exclude
            image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico', '.tiff', '.tif', '.heic', '.heif'}

            # Media/binary files to exclude (not typically sensitive)
            media_extensions = {'.mp4', '.mp3', '.avi', '.mov', '.wav', '.flac', '.zip', '.tar', '.gz', '.exe', '.dll', '.so'}

            # HIGH INTEREST - Configuration, credentials, keys
            high_interest = {
                '.env': 'Environment configuration',
                '.config': 'Configuration file',
                '.conf': 'Configuration file',
                '.cfg': 'Configuration file',
                '.ini': 'Configuration file',
                '.yaml': 'Configuration file',
                '.yml': 'Configuration file',
                '.json': 'JSON data/config',
                '.xml': 'XML data/config',
                '.properties': 'Configuration properties',
                '.key': 'Private key',
                '.pem': 'Certificate/key',
                '.p12': 'Certificate',
                '.pfx': 'Certificate',
                '.cer': 'Certificate',
                '.crt': 'Certificate',
                '.der': 'Certificate',
                '.pub': 'Public key',
                '.ppk': 'PuTTY private key',
                '.keystore': 'Java keystore',
                '.jks': 'Java keystore',
                '.kdbx': 'KeePass database',
                '.asc': 'PGP key',
                '.gpg': 'GPG key'
            }

            # MEDIUM INTEREST - Databases, backups, documents
            medium_interest = {
                '.sql': 'SQL database/dump',
                '.db': 'Database file',
                '.sqlite': 'SQLite database',
                '.mdb': 'Access database',
                '.bak': 'Backup file',
                '.backup': 'Backup file',
                '.old': 'Old/backup file',
                '.log': 'Log file',
                '.pcap': 'Packet capture',
                '.cap': 'Packet capture',
                '.xlsx': 'Excel spreadsheet',
                '.xls': 'Excel spreadsheet',
                '.csv': 'CSV data',
                '.doc': 'Word document',
                '.docx': 'Word document',
                '.pdf': 'PDF document',
                '.txt': 'Text file'
            }

            # MEDIUM INTEREST - Source code
            code_extensions = {
                '.py': 'Python script',
                '.js': 'JavaScript',
                '.php': 'PHP script',
                '.sh': 'Shell script',
                '.bash': 'Bash script',
                '.ps1': 'PowerShell script',
                '.bat': 'Batch script',
                '.rb': 'Ruby script',
                '.pl': 'Perl script',
                '.java': 'Java source',
                '.cs': 'C# source',
                '.cpp': 'C++ source',
                '.c': 'C source',
                '.go': 'Go source'
            }

            # HIGH INTEREST - Sensitive filename patterns
            sensitive_patterns = {
                'password': 'Password file',
                'passwd': 'Password file',
                'secret': 'Secret data',
                'credential': 'Credentials',
                'apikey': 'API key',
                'api_key': 'API key',
                'private': 'Private data',
                'confidential': 'Confidential data',
                'backup': 'Backup file',
                'dump': 'Database dump',
                'export': 'Data export',
                'migration': 'Migration data',
                'users': 'User data',
                'accounts': 'Account data',
                'token': 'Token/credential',
                'auth': 'Authentication data',
                '.env': 'Environment file',
                'config': 'Configuration',
                'settings': 'Settings file',
                'id_rsa': 'SSH private key',
                'id_dsa': 'SSH private key',
                'id_ecdsa': 'SSH private key',
                'wallet': 'Wallet/credentials',
                'shadow': 'Shadow password file',
                'htpasswd': 'HTTP passwords'
            }

            # Check if it's an excluded type
            for ext in image_extensions | media_extensions:
                if filename_lower.endswith(ext):
                    return (False, f'Excluded: {ext}')

            # Check high interest extensions
            for ext, reason in high_interest.items():
                if filename_lower.endswith(ext):
                    return (True, f'HIGH: {reason}')

            # Check sensitive patterns in filename
            for pattern, reason in sensitive_patterns.items():
                if pattern in filename_lower:
                    return (True, f'HIGH: {reason}')

            # Check medium interest extensions
            for ext, reason in medium_interest.items():
                if filename_lower.endswith(ext):
                    return (True, f'MEDIUM: {reason}')

            # Check code extensions (medium interest, but lower priority)
            for ext, reason in code_extensions.items():
                if filename_lower.endswith(ext):
                    return (True, f'MEDIUM: {reason}')

            # Unknown file type - might be interesting
            return (True, 'UNKNOWN: Unknown file type')

    def scope_validation(self):
            """Perform scope validation including WHOIS and DNS verification"""
            self.print_section("SCOPE VALIDATION")

            # WHOIS lookup for IP ranges (skip if none provided)
            whois_results = {}

            if self.ip_ranges:
                self.print_info("Performing WHOIS lookups for IP ranges...")
                for ip_range in self.ip_ranges:
                    try:
                        # Extract first IP from range for WHOIS lookup
                        if '/' in ip_range:
                            ip = str(ipaddress.ip_network(ip_range, strict=False).network_address)
                        else:
                            ip = ip_range

                        output = self.run_command(['whois', ip])
                        if output:
                            whois_results[ip_range] = self._parse_whois(output)
                            org = whois_results[ip_range].get('org', 'Unknown')
                            self.print_success(f"{ip_range} - Organization: {org}")
                    except Exception as e:
                        self.print_error(f"WHOIS failed for {ip_range}: {e}")
            else:
                self.print_info("Skipping WHOIS lookups (no IP ranges provided)")

            self.results['scope_validation']['whois'] = whois_results

            # DNS verification for domain
            self.print_info(f"Verifying DNS records for {self.domain}...")
            dns_records = self._get_dns_records(self.domain)
            self.results['scope_validation']['dns_verification'] = dns_records

            if dns_records.get('A'):
                self.print_success(f"Domain resolves to: {', '.join(dns_records['A'])}")

                # Check if resolved IPs are in scope (only if IP ranges provided)
                if self.ip_ranges:
                    for ip in dns_records['A']:
                        in_scope = self._is_ip_in_scope(ip)
                        if in_scope:
                            self.print_success(f"✓ {ip} is within authorized scope")
                        else:
                            self.print_warning(f"✗ {ip} is NOT in provided scope ranges")

    def load_config(self) -> Dict[str, str]:
        """Load configuration from file"""
        default_config = {
            'github_token': '',
            'shodan_api_key': '',
            'censys_api_id': '',
            'censys_api_secret': ''
        }

        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults in case new keys were added
                    default_config.update(loaded_config)
                    return default_config
            except Exception as e:
                self.print_warning(f"Error loading config: {e}")
                return default_config

        return default_config

    def save_config(self):
            """Save configuration to file (excludes temporary credentials)"""
            try:
                # Create a copy without temporary credentials
                config_to_save = self.config.copy()

                # Remove temporary credentials that shouldn't be saved
                config_to_save.pop('linkedin_cookie', None)
                config_to_save.pop('linkedin_cookies', None)

                with open(self.config_file, 'w') as f:
                    json.dump(config_to_save, f, indent=2)
                self.print_success(f"Configuration saved to {self.config_file}")
            except Exception as e:
                self.print_error(f"Error saving config: {e}")

    def prompt_for_api_keys(self):
            """Prompt user for API keys if not already configured"""
            print("\n" + "="*80)
            print("API KEY CONFIGURATION")
            print("="*80)
            print("Some modules require API keys/tokens for enhanced functionality.")
            print("Press Enter to skip any key you don't have or want to configure later.")
            print("")

            updated = False

            # GitHub Token
            if not self.config.get('github_token'):
                print("[*] GitHub Token (for secret scanning in repos/gists/issues)")
                print("    Generate at: https://github.com/settings/tokens")
                print("    Required scopes: public_repo (read:org optional)")
                token = input("    Enter GitHub token (or press Enter to skip): ").strip()
                if token:
                    self.config['github_token'] = token
                    updated = True
                    self.print_success("GitHub token configured")
                else:
                    self.print_info("Skipping GitHub token - secret scanning will be limited")
            else:
                self.print_success("GitHub token already configured")

            print("")

            # LinkedIn Cookies - ALWAYS prompt (not saved, expires after use)
            print("="*80)
            print("LINKEDIN COOKIES REQUIRED")
            print("="*80)
            print("[*] LinkedIn Session Cookies (for employee enumeration)")
            print("    Note: Requires FULL cookie string from browser")
            print("    1. Open LinkedIn in your browser and log in")
            print("    2. Open Developer Tools (F12) -> Network tab")
            print("    3. Refresh the page, click any linkedin.com request")
            print("    4. In Request Headers, find 'Cookie:' and copy the ENTIRE value")
            print("    5. Paste the full cookie string below (will NOT be saved)")
            cookies = input("    Enter full LinkedIn cookie string (or press Enter to skip): ").strip()
            if cookies:
                self.config['linkedin_cookies'] = cookies
                # NOTE: Do NOT save to config file - it's temporary
                self.print_success("LinkedIn cookies configured for this session only")
            else:
                self.print_info("Skipping LinkedIn cookies - employee enumeration will be skipped")

            print("")

            # HIBP API Key (optional but recommended)
            if not self.config.get('hibp_api_key'):
                print("[*] Have I Been Pwned API Key (optional - for breach checking)")
                print("    Get key at: https://haveibeenpwned.com/API/Key")
                print("    Cost: $3.50/month for full API access")
                key = input("    Enter HIBP API key (or press Enter to skip): ").strip()
                if key:
                    self.config['hibp_api_key'] = key
                    updated = True
                    self.print_success("HIBP API key configured")
                else:
                    self.print_info("Skipping HIBP API key - breach checking will use free tier (limited)")
            else:
                self.print_success("HIBP API key already configured")

            print("")

            # Optional: Shodan (for future use)
            if not self.config.get('shodan_api_key'):
                print("[*] Shodan API Key (optional - for enhanced service discovery)")
                print("    Register at: https://account.shodan.io/register")
                key = input("    Enter Shodan API key (or press Enter to skip): ").strip()
                if key:
                    self.config['shodan_api_key'] = key
                    updated = True
                    self.print_success("Shodan API key configured")
            else:
                self.print_success("Shodan API key already configured")

            if updated:
                self.save_config()

            print("="*80 + "\n")

    def github_secret_scanning(self):
            """Search GitHub for leaked credentials and secrets"""
            self.print_section("GITHUB SECRET SCANNING")

            if not self.config.get('github_token'):
                self.print_warning("No GitHub token configured. Skipping GitHub scanning.")
                self.print_info("Run with a configured token for enhanced secret detection")
                return

            github_findings = {
                'repositories': [],
                'gists': [],
                'issues': [],
                'commits': [],
                'total_secrets_found': 0
            }

            headers = {
                'Authorization': f"token {self.config['github_token']}",
                'Accept': 'application/vnd.github.v3+json'
            }

            # Define search queries
            search_queries = [
                f'"{self.domain}"',
                f'"{self.domain.replace(".", " ")}"',
                f'"{self.domain.split(".")[0]}"',  # company name
                f'{self.domain} password',
                f'{self.domain} api_key',
                f'{self.domain} secret',
                f'{self.domain} credentials',
                f'{self.domain} aws_access_key',
                f'{self.domain} private_key'
            ]

            # Sensitive patterns to look for
            sensitive_patterns = {
                'aws_access_key': r'AKIA[0-9A-Z]{16}',
                'aws_secret_key': r'aws_secret_access_key.*?["\']([^"\']{40})["\']',
                'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                'api_key': r'api[_-]?key.*?["\']([a-zA-Z0-9_\-]{20,})["\']',
                'password': r'password.*?["\']([^"\']{8,})["\']',
                'database_url': r'(postgresql|mysql|mongodb)://[^\s]+',
                'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                'slack_token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
                'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
                's3_bucket': r'[a-z0-9.-]+\.s3\.amazonaws\.com',
                'azure_storage': r'[a-z0-9]+\.blob\.core\.windows\.net',
                'gcp_bucket': r'[a-z0-9._-]+\.storage\.googleapis\.com'
            }

            # Create GitHub downloads directory
            github_download_dir = self.output_dir / 'github_secrets'
            github_download_dir.mkdir(parents=True, exist_ok=True)

            self.print_info(f"Searching GitHub with {len(search_queries)} queries...")

            # Search Code
            self.print_info("Searching code repositories...")
            for query in search_queries:
                try:
                    url = f"https://api.github.com/search/code?q={query}&per_page=10"
                    response = self.session.get(url, headers=headers, timeout=15)

                    if response.status_code == 200:
                        data = response.json()

                        for item in data.get('items', []):
                            repo_finding = {
                                'repository': item.get('repository', {}).get('full_name'),
                                'file_path': item.get('path'),
                                'html_url': item.get('html_url'),
                                'secrets_found': []
                            }

                            # Get file content
                            try:
                                content_url = item.get('url')
                                if content_url:
                                    content_resp = self.session.get(content_url, headers=headers, timeout=10)
                                    if content_resp.status_code == 200:
                                        content_data = content_resp.json()
                                        content = base64.b64decode(content_data.get('content', '')).decode('utf-8', errors='ignore')

                                        # Check for sensitive patterns with validation
                                        for secret_type, pattern in sensitive_patterns.items():
                                            matches = re.findall(pattern, content, re.IGNORECASE)
                                            if matches:
                                                # Validate if it's a real secret (inline validation)
                                                is_real = True

                                                # High confidence patterns are always real
                                                high_confidence = {'aws_access_key', 'private_key', 'jwt_token', 'slack_token', 'google_api'}

                                                if secret_type not in high_confidence:
                                                    # For password patterns, check for false positives
                                                    if secret_type == 'password':
                                                        content_lower = content.lower()
                                                        false_positive_contexts = [
                                                            'password:', 'password =', 'password">', 'your password',
                                                            'enter password', 'password must', 'password field',
                                                            'password input', 'password strength', 'password policy',
                                                            'example password', 'test password', 'sample password',
                                                            'placeholder="password"', 'type="password"', '# password',
                                                            '// password', '* password', 'password requirements'
                                                        ]
                                                        if any(fp in content_lower for fp in false_positive_contexts):
                                                            is_real = False

                                                    # For API keys, validate they look real
                                                    elif secret_type == 'api_key':
                                                        for match in matches:
                                                            if len(match) < 20 or 'xxx' in match.lower() or 'your_api_key' in match.lower() or 'example' in match.lower():
                                                                is_real = False
                                                                break

                                                    # Database URLs with localhost/example are not real
                                                    elif secret_type == 'database_url':
                                                        for match in matches:
                                                            if 'localhost' in match or '127.0.0.1' in match or 'example' in match:
                                                                is_real = False
                                                                break

                                                    # Cloud storage with many matches is likely documentation
                                                    elif secret_type in {'s3_bucket', 'azure_storage', 'gcp_bucket'}:
                                                        if len(matches) > 5:
                                                            is_real = False

                                                if is_real:
                                                    repo_finding['secrets_found'].append({
                                                        'type': secret_type,
                                                        'count': len(matches)
                                                    })
                                                    github_findings['total_secrets_found'] += len(matches)

                                        if repo_finding['secrets_found']:
                                            github_findings['repositories'].append(repo_finding)
                                            self.print_warning(f"Secrets found in: {repo_finding['repository']}/{repo_finding['file_path']}")
                                            for secret in repo_finding['secrets_found']:
                                                self.print_info(f"  - {secret['type']}: {secret['count']} match(es)")

                                            # Download the file with secrets
                                            safe_repo_name = repo_finding['repository'].replace('/', '_')
                                            safe_file_name = repo_finding['file_path'].replace('/', '_')
                                            output_file = github_download_dir / f"{safe_repo_name}_{safe_file_name}"

                                            try:
                                                with open(output_file, 'w', encoding='utf-8') as f:
                                                    f.write(content)
                                                self.print_success(f"  Downloaded to: {output_file}")
                                            except Exception as e:
                                                self.print_error(f"  Failed to save file: {e}")

                            except Exception as e:
                                self.print_error(f"Error fetching content: {e}")

                    elif response.status_code == 403:
                        self.print_warning("GitHub API rate limit reached. Waiting 60 seconds...")
                        time.sleep(60)
                    elif response.status_code == 401:
                        self.print_error("GitHub token is invalid or expired")
                        break

                    time.sleep(2)  # Rate limiting

                except Exception as e:
                    self.print_error(f"Error searching code: {e}")

            # Search Gists
            self.print_info("Searching gists...")
            for query in search_queries[:3]:  # Limit gist queries
                try:
                    url = f"https://api.github.com/search/code?q={query}+in:file+language:text&per_page=5"
                    response = self.session.get(url, headers=headers, timeout=15)

                    if response.status_code == 200:
                        data = response.json()
                        for item in data.get('items', []):
                            if 'gist' in item.get('html_url', ''):
                                gist_finding = {
                                    'gist_id': item.get('html_url'),
                                    'file': item.get('path'),
                                    'secrets_found': []
                                }
                                github_findings['gists'].append(gist_finding)
                                self.print_success(f"Found gist: {gist_finding['gist_id']}")

                    time.sleep(2)
                except Exception as e:
                    self.print_error(f"Error searching gists: {e}")

            # Search Issues
            self.print_info("Searching issues...")
            for query in search_queries[:3]:  # Limit issue queries
                try:
                    url = f"https://api.github.com/search/issues?q={query}+in:body&per_page=10"
                    response = self.session.get(url, headers=headers, timeout=15)

                    if response.status_code == 200:
                        data = response.json()

                        for item in data.get('items', []):
                            body = item.get('body', '')

                            # Check for sensitive patterns in issue body with validation
                            secrets_found = []
                            for secret_type, pattern in sensitive_patterns.items():
                                matches = re.findall(pattern, body, re.IGNORECASE)
                                if matches:
                                    # Same validation logic as code search
                                    is_real = True
                                    high_confidence = {'aws_access_key', 'private_key', 'jwt_token', 'slack_token', 'google_api'}

                                    if secret_type not in high_confidence:
                                        if secret_type == 'password':
                                            body_lower = body.lower()
                                            if any(fp in body_lower for fp in ['password:', 'your password', 'example password']):
                                                is_real = False
                                        elif secret_type in {'s3_bucket', 'azure_storage', 'gcp_bucket'} and len(matches) > 5:
                                            is_real = False

                                    if is_real:
                                        secrets_found.append({
                                            'type': secret_type,
                                            'count': len(matches)
                                        })
                                        github_findings['total_secrets_found'] += len(matches)

                            if secrets_found:
                                issue_finding = {
                                    'title': item.get('title'),
                                    'html_url': item.get('html_url'),
                                    'state': item.get('state'),
                                    'secrets_found': secrets_found
                                }
                                github_findings['issues'].append(issue_finding)
                                self.print_warning(f"Secrets in issue: {issue_finding['title']}")
                                self.print_info(f"  URL: {issue_finding['html_url']}")

                                # Save issue body
                                safe_title = re.sub(r'[^\w\s-]', '', issue_finding['title'])[:50]
                                output_file = github_download_dir / f"issue_{safe_title}.txt"
                                try:
                                    with open(output_file, 'w', encoding='utf-8') as f:
                                        f.write(f"Title: {issue_finding['title']}\n")
                                        f.write(f"URL: {issue_finding['html_url']}\n")
                                        f.write(f"State: {issue_finding['state']}\n\n")
                                        f.write(body)
                                    self.print_success(f"  Saved to: {output_file}")
                                except Exception as e:
                                    self.print_error(f"  Failed to save issue: {e}")

                    time.sleep(2)
                except Exception as e:
                    self.print_error(f"Error searching issues: {e}")

            # Store results
            self.results['github_secrets'] = github_findings

            # Summary
            self.print_info("\nGitHub Secret Scanning Summary:")
            self.print_info(f"  Repositories with secrets: {len(github_findings['repositories'])}")
            self.print_info(f"  Issues with secrets: {len(github_findings['issues'])}")
            self.print_info(f"  Total secrets found: {github_findings['total_secrets_found']}")

            if github_findings['total_secrets_found'] > 0:
                self.print_warning(f"\n[!] Downloaded files with secrets to: {github_download_dir}")

    def linkedin_enumeration(self):
            """LinkedIn intelligence gathering using authenticated session"""
            self.print_section("LinkedIn Information Gathering")

            linkedin_intel = {
                'company_info': {},
                'employees': [],
                'email_patterns': {},
                'titles': {},
                'departments': set()
            }

            # Check if LinkedIn cookies are configured
            if not self.config.get('linkedin_cookies'):
                self.print_warning("No LinkedIn session cookies provided.")
                self.print_info("LinkedIn requires fresh session cookies for each run.")
                self.print_info("To enable LinkedIn enumeration:")
                self.print_info("  1. Open LinkedIn in your browser and log in")
                self.print_info("  2. Open Developer Tools (F12) -> Network tab")
                self.print_info("  3. Click any request to linkedin.com")
                self.print_info("  4. Copy the FULL 'Cookie:' header value from Request Headers")
                self.print_info("  5. Paste the entire cookie string when prompted")
                self.print_info("Skipping LinkedIn enumeration...")
                return

            search_term = self.client_name
            self.print_info(f"Searching LinkedIn for: {search_term}")

            # Get max results from args or default
            max_employee_results = getattr(self.args, 'linkedin_max_results', 100) if hasattr(self, 'args') else 100
            max_company_results = 50

            self.print_info(f"Max employee results: {max_employee_results}")

            # Set up authenticated session with all cookies
            linkedin_session = requests.Session()

            # Parse the cookie string and set all cookies
            cookie_string = self.config['linkedin_cookies']
            for cookie in cookie_string.split('; '):
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    linkedin_session.cookies.set(name, value, domain='.linkedin.com')

            # Extract CSRF token from JSESSIONID
            jsessionid = linkedin_session.cookies.get('JSESSIONID', '').strip('"')
            if not jsessionid:
                self.print_error("JSESSIONID not found in cookies")
                return

            self.print_success(f"Using CSRF token: {jsessionid[:30]}...")
            self.print_info(f"Loaded {len(linkedin_session.cookies)} cookies")

            # API headers matching browser exactly
            api_headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
                'Accept': 'application/vnd.linkedin.normalized+json+2.1',
                'Accept-Language': 'en-US,en;q=0.9',
                'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Linux"',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Dest': 'empty',
                'Referer': 'https://www.linkedin.com/search/results/companies/',
                'X-Li-Lang': 'en_US',
                'X-Li-Page-Instance': 'urn:li:page:d_flagship3_search_srp_companies;' + str(int(time.time() * 1000)),
                'X-Li-Track': '{"clientVersion":"1.13.9101","mpVersion":"1.13.9101","osName":"web","timezoneOffset":-6,"timezone":"America/Chicago","deviceFormFactor":"DESKTOP","mpName":"voyager-web","displayDensity":1}',
                'X-Restli-Protocol-Version': '2.0.0',
                'Csrf-Token': jsessionid,
            }

            encoded_term = search_term.replace(' ', '%20').replace(',', '%2C')

            # =====================================================================
            # SEARCH 1: Find companies (with pagination)
            # =====================================================================
            self.print_info(f"\n[1/2] Searching for companies: {search_term}")

            all_companies = []
            start = 0
            page_size = 10

            while start < max_company_results:
                company_search_url = f"https://www.linkedin.com/voyager/api/voyagerSearchDashClusters?decorationId=com.linkedin.voyager.dash.deco.search.SearchClusterCollection-174&origin=SWITCH_SEARCH_VERTICAL&q=all&query=(keywords:{encoded_term},flagshipSearchIntent:SEARCH_SRP,queryParameters:(resultType:List(COMPANIES)),includeFiltersInResponse:false)&start={start}"

                try:
                    response = linkedin_session.get(company_search_url, headers=api_headers, timeout=15)

                    if response.status_code != 200:
                        self.print_warning(f"API returned status {response.status_code}")
                        break

                    data = response.json()
                    included = data.get('included', [])

                    if not included:
                        break

                    page_companies = []

                    # First pass: build a map of entity URNs to company data
                    company_map = {}
                    for item in included:
                        item_type = item.get('$type', '')
                        entity_urn = item.get('entityUrn', '')

                        if 'Company' in item_type or 'Organization' in item_type:
                            name = item.get('name', '')
                            universal_name = item.get('universalName', '')

                            if name and entity_urn:
                                company_map[entity_urn] = {
                                    'name': name,
                                    'slug': universal_name,
                                    'url': f"https://www.linkedin.com/company/{universal_name}" if universal_name else '',
                                    'entity_urn': entity_urn
                                }

                    # Second pass: extract from search results
                    for item in included:
                        title = item.get('title', {})
                        if isinstance(title, dict):
                            text = title.get('text', '')
                            if text and len(text) > 2 and len(text) < 100:
                                navigation = item.get('navigationUrl', '') or ''
                                if '/company/' in navigation:
                                    slug = navigation.split('/company/')[-1].split('/')[0].split('?')[0]
                                    if not any(c['slug'] == slug for c in page_companies):
                                        page_companies.append({
                                            'name': text,
                                            'slug': slug,
                                            'url': f"https://www.linkedin.com/company/{slug}"
                                        })

                        tracking = item.get('trackingUrn', '')
                        if 'company:' in tracking:
                            company_id = tracking.split('company:')[-1]
                            for urn, comp in company_map.items():
                                if company_id in urn and comp not in page_companies:
                                    page_companies.append(comp)

                    for urn, comp in company_map.items():
                        if not any(c['slug'] == comp['slug'] for c in page_companies) and comp['slug']:
                            page_companies.append(comp)

                    if not page_companies:
                        text = json.dumps(data)
                        slug_matches = re.findall(r'"universalName":\s*"([^"]+)"', text)
                        name_matches = re.findall(r'"name":\s*"([^"]{3,60})"', text)

                        for i, slug in enumerate(slug_matches):
                            if slug and not any(c['slug'] == slug for c in page_companies):
                                name = name_matches[i] if i < len(name_matches) else slug
                                page_companies.append({
                                    'name': name,
                                    'slug': slug,
                                    'url': f"https://www.linkedin.com/company/{slug}"
                                })

                    new_count = 0
                    for comp in page_companies:
                        if not any(c['slug'] == comp['slug'] and c['name'] == comp['name'] for c in all_companies):
                            all_companies.append(comp)
                            new_count += 1

                    self.print_info(f"  Page {start // page_size + 1}: Found {new_count} new companies")

                    if new_count == 0:
                        break

                    start += page_size
                    time.sleep(5)

                except Exception as e:
                    self.print_error(f"Error fetching companies: {e}")
                    break

            if all_companies:
                self.print_success(f"Found {len(all_companies)} total companies:")
                for company in all_companies:
                    self.print_info(f"  - {company['name']}")
                    if company.get('url'):
                        self.print_info(f"    {company['url']}")
                linkedin_intel['company_info'] = {'companies': all_companies}
            else:
                self.print_warning("No companies found")

            time.sleep(2)

            # =====================================================================
            # SEARCH 2: Find people (with pagination)
            # =====================================================================
            self.print_info(f"\n[2/2] Searching for people at: {search_term}")

            all_employees = []
            start = 0

            while start < max_employee_results:
                people_search_url = f"https://www.linkedin.com/voyager/api/voyagerSearchDashClusters?decorationId=com.linkedin.voyager.dash.deco.search.SearchClusterCollection-174&origin=SWITCH_SEARCH_VERTICAL&q=all&query=(keywords:{encoded_term},flagshipSearchIntent:SEARCH_SRP,queryParameters:(resultType:List(PEOPLE)),includeFiltersInResponse:false)&start={start}"

                try:
                    response = linkedin_session.get(people_search_url, headers=api_headers, timeout=15)

                    if response.status_code != 200:
                        self.print_warning(f"API returned status {response.status_code}")
                        break

                    data = response.json()
                    included = data.get('included', [])

                    if not included:
                        break

                    page_employees = []

                    # First pass: build map of profiles
                    profile_map = {}
                    for item in included:
                        item_type = item.get('$type', '')
                        entity_urn = item.get('entityUrn', '')

                        if 'Profile' in item_type or 'Member' in item_type or 'MiniProfile' in item_type:
                            first_name = item.get('firstName', '')
                            last_name = item.get('lastName', '')
                            headline = item.get('headline', '') or item.get('occupation', '')
                            public_id = item.get('publicIdentifier', '')

                            if first_name and last_name:
                                profile_map[entity_urn] = {
                                    'name': f"{first_name} {last_name}",
                                    'first_name': first_name,
                                    'last_name': last_name,
                                    'title': headline or 'Unknown',
                                    'profile_url': f"https://www.linkedin.com/in/{public_id}" if public_id else '',
                                    'public_id': public_id
                                }

                    # Second pass: extract from search results
                    for item in included:
                        title = item.get('title', {})
                        if isinstance(title, dict):
                            text = title.get('text', '')
                            if text and ' ' in text and len(text) > 4 and len(text) < 60:
                                navigation = item.get('navigationUrl', '') or ''
                                if '/in/' in navigation:
                                    public_id = navigation.split('/in/')[-1].split('/')[0].split('?')[0]

                                    headline = ''
                                    primary_subtitle = item.get('primarySubtitle', {})
                                    if isinstance(primary_subtitle, dict):
                                        headline = primary_subtitle.get('text', '')

                                    parts = text.split()
                                    if len(parts) >= 2:
                                        emp = {
                                            'name': text,
                                            'first_name': parts[0],
                                            'last_name': ' '.join(parts[1:]),
                                            'title': headline or 'Unknown',
                                            'profile_url': f"https://www.linkedin.com/in/{public_id}",
                                            'public_id': public_id
                                        }
                                        if not any(e['public_id'] == public_id for e in page_employees if e.get('public_id')):
                                            page_employees.append(emp)

                    # Add from profile map
                    for urn, profile in profile_map.items():
                        if profile['public_id'] and not any(e.get('public_id') == profile['public_id'] for e in page_employees):
                            page_employees.append(profile)

                    # Regex fallback
                    if not page_employees:
                        text = json.dumps(data)
                        name_matches = re.findall(r'"firstName":\s*"([^"]+)"[^}]*"lastName":\s*"([^"]+)"', text)
                        public_id_matches = re.findall(r'"publicIdentifier":\s*"([^"]+)"', text)
                        headline_matches = re.findall(r'"headline":\s*"([^"]+)"', text)

                        for i, (first, last) in enumerate(name_matches):
                            public_id = public_id_matches[i] if i < len(public_id_matches) else ''
                            headline = headline_matches[i] if i < len(headline_matches) else 'Unknown'

                            if public_id and not any(e.get('public_id') == public_id for e in page_employees):
                                page_employees.append({
                                    'name': f"{first} {last}",
                                    'first_name': first,
                                    'last_name': last,
                                    'title': headline,
                                    'profile_url': f"https://www.linkedin.com/in/{public_id}" if public_id else '',
                                    'public_id': public_id
                                })

                    new_count = 0
                    for emp in page_employees:
                        if not any(e.get('public_id') == emp.get('public_id') for e in all_employees if emp.get('public_id')):
                            all_employees.append(emp)
                            new_count += 1

                    self.print_info(f"  Page {start // page_size + 1}: Found {new_count} new employees (total: {len(all_employees)})")

                    if new_count == 0:
                        break

                    start += page_size
                    time.sleep(5)

                except Exception as e:
                    self.print_error(f"Error fetching people: {e}")
                    break

            self.print_success(f"Found {len(all_employees)} total employees")

            # =====================================================================
            # Process and store results
            # =====================================================================
            if all_employees:
                for emp in all_employees:
                    if emp.get('first_name') and emp.get('last_name'):
                        emails = self.results.get('email_addresses', [])
                        if emails:
                            sample = emails[0]
                            local = sample.split('@')[0]
                            if '.' in local:
                                emp['possible_email'] = f"{emp['first_name'].lower()}.{emp['last_name'].lower()}@{self.domain}"
                            else:
                                emp['possible_email'] = f"{emp['first_name'].lower()}{emp['last_name'].lower()}@{self.domain}"

                    linkedin_intel['employees'].append(emp)

                    if emp.get('title') and emp['title'] != 'Unknown':
                        title_lower = emp['title'].lower()
                        linkedin_intel['titles'][emp['title']] = linkedin_intel['titles'].get(emp['title'], 0) + 1

                        dept_keywords = {
                            'engineering': ['engineer', 'developer', 'architect', 'devops'],
                            'security': ['security', 'infosec', 'cybersecurity', 'ciso'],
                            'it': ['it ', 'sysadmin', 'infrastructure', 'network'],
                            'management': ['manager', 'director', 'vp', 'chief', 'ceo', 'cto'],
                            'sales': ['sales', 'account executive', 'business development'],
                            'marketing': ['marketing', 'communications'],
                            'hr': ['human resources', 'recruiter', 'talent'],
                            'finance': ['finance', 'accounting', 'tax', 'audit']
                        }

                        for dept, keywords in dept_keywords.items():
                            if any(kw in title_lower for kw in keywords):
                                linkedin_intel['departments'].add(dept)

                self.print_info("\nEmployees found:")
                for emp in linkedin_intel['employees']:
                    title_info = f" - {emp['title']}" if emp.get('title') and emp['title'] != 'Unknown' else ""
                    email_info = f" ({emp.get('possible_email', '')})" if emp.get('possible_email') else ""
                    self.print_success(f"  {emp['name']}{title_info}{email_info}")
                    if emp.get('profile_url'):
                        self.print_info(f"    {emp['profile_url']}")
            else:
                self.print_warning("No employees found")

            # Store results
            linkedin_intel['departments'] = list(linkedin_intel['departments'])
            self.results['linkedin_intel'] = linkedin_intel

            # Summary
            self.print_info(f"\nLinkedIn Summary:")
            if linkedin_intel.get('company_info', {}).get('companies'):
                self.print_info(f"  Companies: {len(linkedin_intel['company_info']['companies'])}")
            self.print_info(f"  Employees: {len(linkedin_intel['employees'])}")
            self.print_info(f"  Departments: {', '.join(linkedin_intel['departments']) if linkedin_intel['departments'] else 'None'}")

            if linkedin_intel['titles']:
                self.print_info(f"  Top titles:")
                sorted_titles = sorted(linkedin_intel['titles'].items(), key=lambda x: x[1], reverse=True)[:10]
                for title, count in sorted_titles:
                    self.print_info(f"    - {title} ({count})")

    def run_linkedin_only(self):
            """Run only LinkedIn enumeration for testing"""
            self.print_banner()

            if not self.config.get('linkedin_cookies'):
                print("\n" + "="*80)
                print("LINKEDIN COOKIES REQUIRED")
                print("="*80)
                print("[*] LinkedIn requires FULL cookie string from browser")
                print("    1. Open LinkedIn in your browser and log in")
                print("    2. Open Developer Tools (F12) -> Network tab")
                print("    3. Refresh the page, click any linkedin.com request")
                print("    4. In Request Headers, find 'Cookie:' and copy the ENTIRE value")
                cookies = input("    Enter full LinkedIn cookie string (or press Enter to skip): ").strip()
                if cookies:
                    self.config['linkedin_cookies'] = cookies
                    self.print_success("LinkedIn cookies configured")
                else:
                    self.print_error("LinkedIn cookies required. Exiting.")
                    return
                print("="*80 + "\n")

            try:
                self.linkedin_enumeration()

                self.print_section("LINKEDIN TEST COMPLETE")

                linkedin_data = self.results.get('linkedin_intel', {})
                if linkedin_data.get('employees'):
                    self.print_success("LinkedIn enumeration completed!")
                    json_file = self.output_dir / f"linkedin_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(json_file, 'w') as f:
                        json.dump(linkedin_data, f, indent=2)
                    self.print_success(f"Results saved to: {json_file}")
                else:
                    self.print_warning("No LinkedIn data collected")

            except KeyboardInterrupt:
                self.print_warning("\nLinkedIn test interrupted")
            except Exception as e:
                self.print_error(f"Error: {e}")
                import traceback
                traceback.print_exc()

    def _parse_whois(self, whois_output: str) -> Dict[str, str]:
        """Parse WHOIS output"""
        result = {}
        patterns = {
            'org': r'(?:OrgName|org-name|organization):\s*(.+)',
            'netrange': r'(?:NetRange|inetnum):\s*(.+)',
            'country': r'(?:Country):\s*(.+)',
            'created': r'(?:created|RegDate):\s*(.+)'
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, whois_output, re.IGNORECASE)
            if match:
                result[key] = match.group(1).strip()

        return result

    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS records for domain"""
        records = {'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': []}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']

        for rtype in record_types:
            output = self.run_command(['dig', '+short', domain, rtype])
            if output:
                records[rtype] = [line.strip() for line in output.split('\n') if line.strip()]

        return records

    def _is_ip_in_scope(self, ip: str) -> bool:
        """Check if IP is within authorized scope"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for ip_range in self.ip_ranges:
                network = ipaddress.ip_network(ip_range, strict=False)
                if ip_obj in network:
                    return True
        except:
            pass
        return False

    def asn_enumeration(self):
            """Enumerate ASN and associated IP ranges for the organization"""
            self.print_section("ASN ENUMERATION")

            asn_data = {
                'asn_numbers': [],
                'ip_ranges': [],
                'organization_names': set(),
                'related_domains': []
            }

            # Method 1: Get ASN from existing IP addresses
            self.print_info("Looking up ASN information from known IPs...")

            # Get IPs from DNS resolution
            dns_records = self.results.get('scope_validation', {}).get('dns_verification', {})
            known_ips = dns_records.get('A', [])

            # Also check resolved subdomains
            resolved_subdomains = self.results.get('dns_enumeration', {}).get('resolved', {})
            for subdomain, ips in resolved_subdomains.items():
                known_ips.extend(ips)

            known_ips = list(set(known_ips))  # Remove duplicates

            self.print_info(f"Checking ASN for {len(known_ips)} discovered IP addresses...")

            for ip in known_ips[:10]:  # Limit to first 10 to avoid excessive queries
                try:
                    # Use Team Cymru's IP to ASN service (DNS-based)
                    asn_info = self._lookup_asn_cymru(ip)

                    if asn_info:
                        if asn_info not in asn_data['asn_numbers']:
                            asn_data['asn_numbers'].append(asn_info)
                            self.print_success(f"Found ASN for {ip}: AS{asn_info['asn']} ({asn_info['owner']})")
                            asn_data['organization_names'].add(asn_info['owner'])

                    time.sleep(0.5)  # Rate limiting

                except Exception as e:
                    self.print_error(f"Error looking up ASN for {ip}: {e}")

            # Method 2: Get ASN from organization name via RIPEstat/RIPE API
            self.print_info("\nQuerying RIPE database for additional ASN information...")

            company_name = self.domain.split('.')[0]

            try:
                # Search RIPE for organization with increased timeout
                url = f"https://stat.ripe.net/data/searchcomplete/data.json?resource={company_name}"
                response = self.session.get(url, timeout=30)

                if response.status_code == 200:
                    data = response.json()

                    for category in data.get('data', {}).get('categories', []):
                        if category.get('category') == 'asns':
                            for suggestion in category.get('suggestions', []):
                                asn_num = suggestion.get('value', '').replace('AS', '')
                                asn_label = suggestion.get('label', '')

                                if asn_num and asn_num.isdigit():
                                    asn_exists = any(a['asn'] == asn_num for a in asn_data['asn_numbers'])
                                    if not asn_exists:
                                        asn_data['asn_numbers'].append({
                                            'asn': asn_num,
                                            'owner': asn_label,
                                            'source': 'ripe_search'
                                        })
                                        self.print_success(f"Found ASN from RIPE: AS{asn_num} ({asn_label})")

            except Exception as e:
                self.print_error(f"Error querying RIPE: {e}")

            # Method 3: For each ASN, get all associated IP prefixes with retry logic
            self.print_info("\nEnumerating IP ranges for discovered ASNs...")

            for asn_info in asn_data['asn_numbers']:
                asn_num = asn_info['asn']

                # Retry logic for RIPE API
                max_retries = 3
                retry_count = 0
                success = False

                while retry_count < max_retries and not success:
                    try:
                        # Use RIPE API to get prefixes for ASN with increased timeout
                        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
                        response = self.session.get(url, timeout=30)

                        if response.status_code == 200:
                            data = response.json()
                            prefixes = data.get('data', {}).get('prefixes', [])

                            self.print_info(f"AS{asn_num} announces {len(prefixes)} IP prefix(es)")

                            for prefix in prefixes:
                                prefix_str = prefix.get('prefix')
                                if prefix_str:
                                    asn_data['ip_ranges'].append({
                                        'prefix': prefix_str,
                                        'asn': asn_num,
                                        'in_scope': self._check_if_in_scope(prefix_str)
                                    })

                                    # Check if this range is in our authorized scope
                                    in_scope = self._check_if_in_scope(prefix_str)
                                    scope_marker = "[IN SCOPE]" if in_scope else "[OUT OF SCOPE]"

                                    self.print_info(f"  {prefix_str} - {scope_marker}")

                            success = True  # Mark as successful
                        else:
                            self.print_warning(f"RIPE API returned status {response.status_code} for AS{asn_num}")
                            retry_count += 1
                            if retry_count < max_retries:
                                self.print_info(f"Retrying... (attempt {retry_count + 1}/{max_retries})")
                                time.sleep(2)

                        time.sleep(5)  # Rate limiting

                    except requests.exceptions.Timeout:
                        retry_count += 1
                        if retry_count < max_retries:
                            self.print_warning(f"Request timed out for AS{asn_num}. Retrying... (attempt {retry_count + 1}/{max_retries})")
                            time.sleep(2)
                        else:
                            self.print_error(f"Failed to get prefixes for AS{asn_num} after {max_retries} attempts (timeout)")
                    except Exception as e:
                        retry_count += 1
                        if retry_count < max_retries:
                            self.print_warning(f"Error for AS{asn_num}: {e}. Retrying... (attempt {retry_count + 1}/{max_retries})")
                            time.sleep(2)
                        else:
                            self.print_error(f"Failed to get prefixes for AS{asn_num} after {max_retries} attempts: {e}")

            # Method 4: Reverse IP lookup to find related domains
            self.print_info("\nSearching for related domains on discovered IPs...")

            for ip in known_ips[:5]:  # Limit to first 5
                try:
                    # Simple reverse DNS
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        if hostname and hostname != ip:
                            asn_data['related_domains'].append({
                                'domain': hostname,
                                'ip': ip,
                                'source': 'reverse_dns'
                            })
                            self.print_success(f"Related domain: {hostname} ({ip})")
                    except:
                        pass

                except Exception as e:
                    pass

            # Store results
            self.results['asn_data'] = {
                'asn_numbers': asn_data['asn_numbers'],
                'ip_ranges': asn_data['ip_ranges'],
                'organization_names': list(asn_data['organization_names']),
                'related_domains': asn_data['related_domains']
            }

            # Summary
            self.print_info(f"\nASN Enumeration Summary:")
            self.print_info(f"  ASNs discovered: {len(asn_data['asn_numbers'])}")
            self.print_info(f"  Total IP ranges found: {len(asn_data['ip_ranges'])}")

            in_scope_ranges = [r for r in asn_data['ip_ranges'] if r['in_scope']]
            out_scope_ranges = [r for r in asn_data['ip_ranges'] if not r['in_scope']]

            self.print_info(f"  Ranges in authorized scope: {len(in_scope_ranges)}")
            self.print_warning(f"  Ranges OUT OF SCOPE (do not test): {len(out_scope_ranges)}")
            self.print_info(f"  Related domains found: {len(asn_data['related_domains'])}")

            if out_scope_ranges:
                self.print_warning("\n[!] WARNING: Additional IP ranges found that are NOT in authorized scope!")
                self.print_warning("These ranges belong to the organization but are not authorized for testing.")
                self.print_warning("Do NOT scan or test these ranges without explicit authorization.")

    def _lookup_asn_cymru(self, ip: str) -> Optional[Dict[str, str]]:
        """Lookup ASN using Team Cymru's IP to ASN service"""
        try:
            # Reverse IP for DNS query
            reversed_ip = '.'.join(ip.split('.')[::-1])
            query = f"{reversed_ip}.origin.asn.cymru.com"

            # Perform DNS TXT record lookup
            answers = dns.resolver.resolve(query, 'TXT')

            for rdata in answers:
                txt_data = str(rdata).strip('"')
                parts = [p.strip() for p in txt_data.split('|')]

                if len(parts) >= 5:
                    return {
                        'asn': parts[0],
                        'prefix': parts[1],
                        'country': parts[2],
                        'registry': parts[3],
                        'owner': parts[4] if len(parts) > 4 else 'Unknown'
                    }
        except Exception as e:
            return None

        return None

    def _check_if_in_scope(self, ip_range: str) -> bool:
        """Check if an IP range overlaps with authorized scope"""
        try:
            check_network = ipaddress.ip_network(ip_range, strict=False)

            for authorized_range in self.ip_ranges:
                authorized_network = ipaddress.ip_network(authorized_range, strict=False)

                # Check if networks overlap
                if (check_network.overlaps(authorized_network) or
                    check_network.subnet_of(authorized_network) or
                    authorized_network.subnet_of(check_network)):
                    return True

            return False
        except:
            return False

    def dns_enumeration(self):
            """Perform DNS enumeration to discover subdomains"""
            self.print_section("DNS ENUMERATION")

            subdomains = set()

            # Method 1: Certificate Transparency Logs
            self.print_info("Checking Certificate Transparency logs...")
            ct_domains = self._check_certificate_transparency()
            subdomains.update(ct_domains)
            self.print_success(f"Found {len(ct_domains)} domains from CT logs")

            # Method 2: DNS brute force with common names
            self.print_info("Performing DNS brute force...")
            brute_domains = self._dns_bruteforce()
            subdomains.update(brute_domains)
            self.print_success(f"Found {len(brute_domains)} domains from brute force")

            # Resolve all discovered subdomains
            self.print_info("Resolving discovered subdomains...")
            resolved = {}
            for subdomain in sorted(subdomains):
                ips = self._resolve_domain(subdomain)
                if ips:
                    resolved[subdomain] = ips
                    self.print_success(f"{subdomain} -> {', '.join(ips)}")

            self.results['dns_enumeration'] = {
                'total_discovered': len(subdomains),
                'ct_log_domains': sorted(list(ct_domains)),
                'bruteforce_domains': sorted(list(brute_domains)),
                'all_discovered': sorted(list(subdomains)),
                'resolved': resolved,
                'unresolved': sorted(list(subdomains - set(resolved.keys())))
            }

            self.print_info(f"Total unique subdomains discovered: {len(subdomains)}")
            self.print_info(f"  - From CT logs: {len(ct_domains)}")
            self.print_info(f"  - From brute force: {len(brute_domains)}")
            self.print_info(f"Successfully resolved: {len(resolved)}")

    def subdomain_takeover_detection(self):
            """Check for subdomain takeover vulnerabilities with validation"""
            self.print_section("SUBDOMAIN TAKEOVER DETECTION")

            # Fingerprints for various services that can be taken over
            takeover_fingerprints = {
                'github': {
                    'cname': ['github.io', 'github.map.fastly.net'],
                    'response': ['There isn\'t a GitHub Pages site here', 'For root URLs (like http://example.com/) you must provide an index.html file'],
                    'service': 'GitHub Pages',
                    'validation_url': '/.well-known/security.txt'  # Should 404 if unclaimed
                },
                'aws_s3': {
                    'cname': ['s3.amazonaws.com', 's3-website', 's3.dualstack'],
                    'response': ['NoSuchBucket', 'The specified bucket does not exist'],
                    'service': 'AWS S3',
                    'validation_url': None
                },
                'azure': {
                    'cname': ['azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com', 'trafficmanager.net', 'blob.core.windows.net'],
                    'response': ['404 Web Site not found', 'Error 404', 'The resource you are looking for has been removed'],
                    'service': 'Microsoft Azure',
                    'validation_url': None
                },
                'heroku': {
                    'cname': ['herokuapp.com'],
                    'response': ['No such app', 'There\'s nothing here', 'herokucdn.com/error-pages/no-such-app.html'],
                    'service': 'Heroku',
                    'validation_url': None
                },
                'bitbucket': {
                    'cname': ['bitbucket.io'],
                    'response': ['Repository not found'],
                    'service': 'Bitbucket',
                    'validation_url': None
                },
                'cloudfront': {
                    'cname': ['cloudfront.net'],
                    'response': ['Bad request', 'ERROR: The request could not be satisfied'],
                    'service': 'AWS CloudFront',
                    'validation_url': None
                },
            }

            vulnerable_subdomains = []

            # Get all resolved subdomains
            resolved_subdomains = self.results.get('dns_enumeration', {}).get('resolved', {})

            if not resolved_subdomains:
                self.print_warning("No subdomains to check. Run DNS enumeration first.")
                return

            self.print_info(f"Checking {len(resolved_subdomains)} subdomains for takeover vulnerabilities...")

            for subdomain, ips in resolved_subdomains.items():
                try:
                    # Get CNAME records
                    cname_records = []
                    try:
                        resolver = dns.resolver.Resolver()
                        try:
                            answers = resolver.resolve(subdomain, 'CNAME')
                        except AttributeError:
                            answers = resolver.query(subdomain, 'CNAME')

                        for rdata in answers:
                            cname_records.append(str(rdata.target).rstrip('.'))
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        pass
                    except Exception as e:
                        continue

                    # Check if CNAME points to a potentially vulnerable service
                    vulnerable = False
                    service_name = None
                    fingerprint_matched = None
                    confidence = "LOW"

                    for cname in cname_records:
                        for service, fingerprint in takeover_fingerprints.items():
                            # Check if CNAME matches known patterns
                            if any(pattern in cname.lower() for pattern in fingerprint['cname']):
                                # CNAME points to a potentially vulnerable service
                                # Now validate with multiple checks
                                validation_result = self._validate_subdomain_takeover(
                                    subdomain,
                                    cname,
                                    fingerprint['response'],
                                    fingerprint.get('validation_url')
                                )

                                if validation_result['is_vulnerable']:
                                    vulnerable = True
                                    service_name = fingerprint['service']
                                    fingerprint_matched = service
                                    confidence = validation_result['confidence']
                                    break

                        if vulnerable:
                            break

                    # Even without CNAME, check HTTP responses for known patterns (but lower confidence)
                    if not vulnerable and not cname_records:
                        for service, fingerprint in takeover_fingerprints.items():
                            validation_result = self._validate_subdomain_takeover(
                                subdomain,
                                None,
                                fingerprint['response'],
                                fingerprint.get('validation_url')
                            )

                            if validation_result['is_vulnerable']:
                                vulnerable = True
                                service_name = fingerprint['service']
                                fingerprint_matched = service
                                confidence = "LOW"  # No CNAME = lower confidence
                                break

                    if vulnerable:
                        vuln_info = {
                            'subdomain': subdomain,
                            'cname': cname_records,
                            'service': service_name,
                            'fingerprint': fingerprint_matched,
                            'ips': ips,
                            'confidence': confidence
                        }
                        vulnerable_subdomains.append(vuln_info)

                        if confidence == "HIGH":
                            self.print_warning(f"HIGH CONFIDENCE TAKEOVER: {subdomain}")
                        elif confidence == "MEDIUM":
                            self.print_warning(f"POSSIBLE TAKEOVER: {subdomain}")
                        else:
                            self.print_info(f"LOW CONFIDENCE: {subdomain}")

                        self.print_info(f"  Service: {service_name}")
                        if cname_records:
                            self.print_info(f"  CNAME: {', '.join(cname_records)}")
                        self.print_info(f"  Confidence: {confidence}")

                    time.sleep(0.5)  # Rate limiting

                except Exception as e:
                    self.print_error(f"Error checking {subdomain}: {e}")

            # Store results
            self.results['subdomain_takeovers'] = vulnerable_subdomains

            # Summary with confidence breakdown
            high_confidence = [v for v in vulnerable_subdomains if v['confidence'] == 'HIGH']
            medium_confidence = [v for v in vulnerable_subdomains if v['confidence'] == 'MEDIUM']
            low_confidence = [v for v in vulnerable_subdomains if v['confidence'] == 'LOW']

            self.print_info(f"\nSubdomain Takeover Detection Summary:")
            self.print_info(f"  Subdomains checked: {len(resolved_subdomains)}")
            self.print_info(f"  High confidence vulnerabilities: {len(high_confidence)}")
            self.print_info(f"  Medium confidence vulnerabilities: {len(medium_confidence)}")
            self.print_info(f"  Low confidence (needs verification): {len(low_confidence)}")

            if high_confidence:
                self.print_warning(f"\n[!] HIGH CONFIDENCE subdomain takeovers found:")
                for vuln in high_confidence:
                    self.print_warning(f"  - {vuln['subdomain']} ({vuln['service']})")
                    self.print_info(f"    Action: Attempt to claim this resource immediately")

            if medium_confidence:
                self.print_info(f"\n[!] MEDIUM CONFIDENCE potential takeovers:")
                for vuln in medium_confidence:
                    self.print_info(f"  - {vuln['subdomain']} ({vuln['service']})")

            if low_confidence:
                self.print_info(f"\n[!] LOW CONFIDENCE (manual verification recommended):")
                for vuln in low_confidence[:5]:  # Only show first 5
                    self.print_info(f"  - {vuln['subdomain']} ({vuln['service']})")

    def _validate_subdomain_takeover(self, subdomain: str, cname: str, response_patterns: List[str], validation_url: str = None) -> Dict[str, Any]:
        """Validate if a subdomain takeover is actually exploitable"""
        result = {
            'is_vulnerable': False,
            'confidence': 'LOW',
            'evidence': []
        }

        try:
            # Check both HTTPS and HTTP
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)

                    response_text = response.text.lower()
                    status_code = response.status_code

                    # Check for specific error patterns
                    pattern_matches = 0
                    for pattern in response_patterns:
                        if pattern.lower() in response_text:
                            pattern_matches += 1
                            result['evidence'].append(f"Found pattern: {pattern}")

                    # Must match at least one pattern
                    if pattern_matches == 0:
                        continue

                    # Additional validation checks
                    validation_score = 0

                    # Check 1: CNAME points to service (HIGH confidence indicator)
                    if cname:
                        validation_score += 2
                        result['evidence'].append(f"CNAME points to service: {cname}")

                    # Check 2: 404 status code
                    if status_code == 404:
                        validation_score += 1
                        result['evidence'].append(f"Returns 404 status")

                    # Check 3: Response size (real sites are usually larger)
                    if len(response.content) < 5000:  # Less than 5KB likely error page
                        validation_score += 1
                        result['evidence'].append(f"Small response size: {len(response.content)} bytes")

                    # Check 4: No active content (no scripts, forms, etc.)
                    if '<script' not in response_text and '<form' not in response_text:
                        validation_score += 1
                        result['evidence'].append("No active content (scripts/forms)")

                    # Check 5: Service-specific validation
                    if validation_url:
                        try:
                            val_response = self.session.get(f"{url}{validation_url}", timeout=5, verify=False)
                            if val_response.status_code == 404:
                                validation_score += 2
                                result['evidence'].append(f"Validation URL confirms: {validation_url}")
                        except:
                            pass

                    # Determine confidence based on validation score
                    if validation_score >= 5:
                        result['confidence'] = 'HIGH'
                        result['is_vulnerable'] = True
                    elif validation_score >= 3:
                        result['confidence'] = 'MEDIUM'
                        result['is_vulnerable'] = True
                    elif validation_score >= 2:
                        result['confidence'] = 'LOW'
                        result['is_vulnerable'] = True

                    # If we found something, no need to try HTTP
                    if result['is_vulnerable']:
                        break

                except requests.exceptions.SSLError:
                    continue
                except requests.exceptions.ConnectionError:
                    # Connection refused might mean unclaimed
                    if cname:  # But only if we have CNAME proof
                        result['is_vulnerable'] = True
                        result['confidence'] = 'MEDIUM'
                        result['evidence'].append("Connection refused but CNAME exists")
                    break
                except Exception as e:
                    continue

        except Exception as e:
            pass

        return result

    def _check_http_takeover(self, subdomain: str, response_patterns: List[str]) -> bool:
        """Check HTTP response for takeover indicators"""
        try:
            # Try HTTPS first, then HTTP
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)

                    # Check if any pattern matches the response
                    response_text = response.text.lower()

                    for pattern in response_patterns:
                        if pattern.lower() in response_text:
                            return True

                    # Also check status code
                    if response.status_code == 404:
                        # 404 with specific patterns often indicates takeover potential
                        return any(pattern.lower() in response_text for pattern in response_patterns)

                except requests.exceptions.SSLError:
                    # SSL error might indicate service exists but cert is wrong
                    continue
                except requests.exceptions.ConnectionError:
                    # Connection refused might mean service is unclaimed
                    return True
                except Exception as e:
                    continue

        except Exception as e:
            pass

        return False

    def _check_certificate_transparency(self) -> List[str]:
            """Check certificate transparency logs for subdomains"""
            domains = []

            self.print_info(f"Querying crt.sh for {self.domain}...")

            try:
                # Try crt.sh with proper timeout and headers
                url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }

                response = requests.get(url, timeout=30, headers=headers)

                self.print_info(f"crt.sh response status: {response.status_code}")

                if response.status_code == 200:
                    try:
                        data = response.json()
                        self.print_info(f"crt.sh returned {len(data)} certificate entries")

                        for entry in data:
                            name = entry.get('name_value', '')
                            # Handle multiple domains in one cert
                            for domain in name.split('\n'):
                                domain = domain.strip().lower()
                                # Skip wildcards and empty entries
                                if domain and '*' not in domain:
                                    domains.append(domain)

                        # Remove duplicates
                        domains = list(set(domains))
                        self.print_success(f"Extracted {len(domains)} unique domains from certificates")

                    except json.JSONDecodeError as e:
                        self.print_error(f"Failed to parse crt.sh JSON response: {e}")
                        self.print_info(f"Response preview: {response.text[:500]}")
                else:
                    self.print_warning(f"crt.sh returned status {response.status_code}")
                    self.print_info(f"Response: {response.text[:200]}")

            except requests.exceptions.Timeout:
                self.print_error("crt.sh request timed out after 30 seconds")
            except requests.exceptions.ConnectionError as e:
                self.print_error(f"Connection error to crt.sh: {e}")
            except Exception as e:
                self.print_error(f"CT log check failed: {e}")
                import traceback
                traceback.print_exc()

            # Try alternative CT log source if crt.sh failed
            if not domains:
                self.print_info("Trying alternative CT source (certspotter)...")
                try:
                    url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
                    response = requests.get(url, timeout=30)

                    if response.status_code == 200:
                        data = response.json()
                        self.print_info(f"certspotter returned {len(data)} entries")

                        for entry in data:
                            dns_names = entry.get('dns_names', [])
                            for name in dns_names:
                                name = name.strip().lower()
                                if name and '*' not in name:
                                    domains.append(name)

                        domains = list(set(domains))
                        self.print_success(f"Extracted {len(domains)} unique domains from certspotter")
                    else:
                        self.print_warning(f"certspotter returned status {response.status_code}")

                except Exception as e:
                    self.print_error(f"certspotter check failed: {e}")

            return list(set(domains))

    def _dns_bruteforce(self) -> List[str]:
        """Brute force common subdomain names"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
            'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
            'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
            'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email',
            'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
            'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat',
            'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store',
            'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
            'exchange', 'ipv4', 'prod', 'production', 'uat', 'qa', 'quality', 'stage'
        ]

        discovered = []

        def check_subdomain(sub):
            subdomain = f"{sub}.{self.domain}"
            if self._resolve_domain(subdomain):
                return subdomain
            return None

        # Use threading for faster brute force
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)

        return discovered

    def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            return ips
        except:
            return []

    def technology_stack_identification(self):
            """Identify technology stack of web services"""
            self.print_section("TECHNOLOGY STACK IDENTIFICATION")

            tech_stack = {}

            # Get resolved domains from DNS enumeration
            resolved_domains = self.results.get('dns_enumeration', {}).get('resolved', {})

            if not resolved_domains:
                self.print_warning("No resolved domains available for tech stack identification")
                return

            # Analyze ALL resolved domains, not just first 5
            targets = [self.domain] if self.domain not in resolved_domains else []
            targets.extend(list(resolved_domains.keys()))

            # Remove duplicates while preserving order
            seen = set()
            unique_targets = []
            for t in targets:
                if t not in seen:
                    seen.add(t)
                    unique_targets.append(t)

            self.print_info(f"Analyzing {len(unique_targets)} targets for technology stack...")

            # Use threading for faster scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_target = {
                    executor.submit(self._identify_technologies, target): target
                    for target in unique_targets
                }

                completed = 0
                for future in concurrent.futures.as_completed(future_to_target):
                    target = future_to_target[future]
                    completed += 1

                    try:
                        tech_info = future.result()
                        if tech_info:
                            tech_stack[target] = tech_info

                            # Print findings
                            self.print_info(f"[{completed}/{len(unique_targets)}] {target}")
                            if tech_info.get('server'):
                                self.print_success(f"  Server: {tech_info['server']}")
                            if tech_info.get('powered_by'):
                                self.print_info(f"  X-Powered-By: {tech_info['powered_by']}")
                            if tech_info.get('detected_technologies'):
                                self.print_info(f"  Technologies: {', '.join(tech_info['detected_technologies'])}")
                        else:
                            self.print_info(f"[{completed}/{len(unique_targets)}] {target} - No response")
                    except Exception as e:
                        self.print_warning(f"[{completed}/{len(unique_targets)}] {target} - Error: {e}")

            self.results['technology_stack'] = tech_stack
            self.print_success(f"\nTechnology stack identified for {len(tech_stack)} targets")

    def _identify_technologies(self, domain: str) -> Dict[str, Any]:
        """Identify technologies for a specific domain"""
        tech_info = {'headers': {}, 'server': None, 'powered_by': None}

        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=10, verify=False, allow_redirects=True)

                # Extract interesting headers
                interesting_headers = [
                    'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
                    'X-Generator', 'X-Drupal-Cache', 'X-Content-Type-Options',
                    'X-Frame-Options', 'Strict-Transport-Security'
                ]

                for header in interesting_headers:
                    if header in response.headers:
                        tech_info['headers'][header] = response.headers[header]
                        if header == 'Server':
                            tech_info['server'] = response.headers[header]
                        elif header == 'X-Powered-By':
                            tech_info['powered_by'] = response.headers[header]

                # Look for technology indicators in HTML
                html = response.text.lower()
                indicators = {
                    'wordpress': 'wp-content',
                    'drupal': 'drupal',
                    'joomla': 'joomla',
                    'sharepoint': 'sharepoint',
                    'asp.net': '__viewstate',
                    'php': '.php',
                    'apache': 'apache',
                    'nginx': 'nginx'
                }

                detected = []
                for tech, indicator in indicators.items():
                    if indicator in html:
                        detected.append(tech)

                if detected:
                    tech_info['detected_technologies'] = detected

                break  # If HTTPS works, no need to try HTTP

            except requests.exceptions.SSLError:
                continue
            except Exception as e:
                continue

        return tech_info if tech_info['headers'] or tech_info.get('detected_technologies') else None

    def email_harvesting(self):
            """Harvest email addresses from public sources"""
            self.print_section("EMAIL ADDRESS HARVESTING")

            emails = set()

            # Method 1: theHarvester (if installed)
            self.print_info("Running theHarvester...")
            harvester_emails = self._run_theharvester()
            emails.update(harvester_emails)

            # Method 2: Web scraping
            self.print_info("Scraping web pages for emails...")
            web_emails = self._scrape_emails_from_web()
            emails.update(web_emails)

            # Hardcoded exclusion list - known false positives
            excluded_addresses = {
                'cmartorella@edge-security.com',  # theHarvester author - shows up in tool output
            }

            # Filter to only valid-looking emails from target domain and related domains
            filtered_emails = []
            rejected_emails = []

            for email in emails:
                email_lower = email.lower()

                # Skip hardcoded exclusions
                if email_lower in excluded_addresses:
                    continue

                # Skip obvious garbage
                if len(email) > 100:  # Too long
                    rejected_emails.append((email, "too long"))
                    continue
                if email.count('@') != 1:  # Invalid format
                    rejected_emails.append((email, "invalid format"))
                    continue

                local, domain = email.split('@')

                # Skip hash/UUID-style emails (like sentry errors)
                if len(local) == 32 and all(c in '0123456789abcdef' for c in local):
                    rejected_emails.append((email, "looks like hash/UUID"))
                    continue

                domain_lower = domain.lower()
                target_domain_lower = self.domain.lower()

                if domain_lower == target_domain_lower or domain_lower.endswith(f'.{target_domain_lower}'):
                    filtered_emails.append(email)
                else:
                    rejected_emails.append((email, f"not from {self.domain} domain"))

            # Show what was rejected if we're getting no results
            if not filtered_emails and rejected_emails:
                self.print_warning(f"Found {len(rejected_emails)} email(s) but all were filtered out:")
                for email, reason in rejected_emails[:5]:
                    self.print_info(f"  Rejected: {email} ({reason})")

            # Store results
            self.results['email_addresses'] = sorted(filtered_emails)

            self.print_success(f"Total unique email addresses found: {len(filtered_emails)}")

            if filtered_emails:
                self.print_info(f"Emails from target domain ({self.domain}):")
                for email in sorted(filtered_emails):
                    self.print_info(f"  {email}")
            else:
                self.print_warning(f"No emails found for target domain ({self.domain})")

                # Show all emails found before filtering for debugging (exclude hardcoded exclusions)
                if emails:
                    debug_emails = [e for e in emails if e.lower() not in excluded_addresses]
                    if debug_emails:
                        self.print_info(f"All emails discovered (before filtering):")
                        for email in sorted(debug_emails)[:10]:
                            self.print_info(f"  {email}")

    def _run_theharvester(self) -> List[str]:
            """Run theHarvester tool"""
            emails = []

            if not self.theharvester_path:
                self.print_warning("theHarvester not found. Install it or add to PATH.")
                return emails

            try:
                # Use specific fast sources instead of 'all' to avoid timeout
                fast_sources = 'baidu,bing,certspotter,crtsh,duckduckgo,hackertarget,otx,rapiddns,threatcrowd,urlscan,yahoo'

                self.print_info("Running theHarvester with fast sources (this may take 2-3 minutes)...")

                # Build command based on whether it's a Python script or executable
                if self.theharvester_path.endswith('.py'):
                    command = ['python3', self.theharvester_path, '-d', self.domain, '-b', fast_sources, '-l', '500']
                else:
                    command = [self.theharvester_path, '-d', self.domain, '-b', fast_sources, '-l', '500']

                # Run with increased timeout and capture both stdout and stderr
                try:
                    result = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=300,
                        check=False
                    )

                    # theHarvester writes to both stdout and stderr, check both
                    output = result.stdout + result.stderr

                    if output:
                        # Extract emails from output
                        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                        emails = re.findall(email_pattern, output)

                        if emails:
                            self.print_success(f"theHarvester found {len(set(emails))} email(s)")
                        else:
                            self.print_warning("theHarvester completed but found no emails")
                            # Show a preview of output for debugging
                            if len(output) > 0:
                                self.print_info(f"Output preview: {output[:200]}")
                    else:
                        self.print_warning("theHarvester produced no output")

                except subprocess.TimeoutExpired:
                    self.print_error("theHarvester timed out after 5 minutes. Continuing with other sources...")

            except Exception as e:
                self.print_warning(f"theHarvester execution failed: {e}")

            return list(set(emails))  # Return unique emails

    def _locate_theharvester(self) -> Optional[str]:
            """Locate theHarvester installation using system tools"""
            # Try standard PATH lookup first
            for cmd in ['theHarvester.py', 'theHarvester', 'theharvester']:
                path = shutil.which(cmd)
                if path:
                    return path

            # Check if locate command exists, install if missing
            if not shutil.which('locate'):
                self.print_warning("'locate' command not found. Installing mlocate...")
                try:
                    # Try to install mlocate
                    install_result = subprocess.run(
                        ['sudo', 'apt-get', 'install', '-y', 'mlocate'],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    if install_result.returncode == 0:
                        self.print_success("mlocate installed successfully")
                        # Update the database
                        self.print_info("Updating mlocate database...")
                        subprocess.run(['sudo', 'updatedb'], timeout=60)
                        self.print_success("Database updated")
                    else:
                        self.print_error("Failed to install mlocate - falling back to find command")
                        # Fall back to find only if installation failed
                        return self._find_theharvester_with_find()
                except Exception as e:
                    self.print_error(f"mlocate installation failed: {e} - falling back to find command")
                    return self._find_theharvester_with_find()

            # Try locate command (either was already installed or just installed)
            try:
                output = self.run_command(['locate', 'theHarvester.py'], timeout=10)
                if output:
                    # Get first result that's executable or readable
                    for line in output.strip().split('\n'):
                        if line and Path(line).exists():
                            return line
            except Exception as e:
                self.print_warning(f"locate command failed: {e}")

            return None

    def _find_theharvester_with_find(self) -> Optional[str]:
        """Use find command to locate theHarvester (slow fallback method)"""
        self.print_info("Searching for theHarvester with find command (may be slow)...")
        try:
            for base_dir in ['/usr', '/opt', str(Path.home())]:
                output = self.run_command([
                    'find', base_dir,
                    '-name', 'theHarvester.py',
                    '-type', 'f',
                    '-readable'
                ], timeout=30)
                if output:
                    # Return first valid result
                    for line in output.strip().split('\n'):
                        if line and Path(line).exists():
                            return line
        except Exception as e:
            self.print_warning(f"find command failed: {e}")

        return None

    def _scrape_emails_from_web(self) -> List[str]:
        """Scrape emails from company website"""
        emails = []
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        try:
            # Try to get the main page
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{self.domain}"
                    response = requests.get(url, timeout=10, verify=False)
                    emails.extend(re.findall(email_pattern, response.text))

                    # Try common pages
                    common_pages = ['/contact', '/about', '/team', '/staff']
                    for page in common_pages:
                        try:
                            page_url = f"{url}{page}"
                            response = requests.get(page_url, timeout=5, verify=False)
                            emails.extend(re.findall(email_pattern, response.text))
                        except:
                            pass

                    break
                except:
                    continue
        except Exception as e:
            self.print_warning(f"Web scraping failed: {e}")

        return list(set(emails))

    def _is_real_secret(self, secret_type: str, matches: list, content: str) -> bool:
            """Determine if detected pattern is likely a real secret vs false positive"""

            # These patterns are high-confidence and rarely false positives
            high_confidence = {'aws_access_key', 'private_key', 'jwt_token', 'slack_token', 'google_api'}

            if secret_type in high_confidence:
                return True

            # For password patterns, check context to avoid false positives
            if secret_type == 'password':
                # Common false positives
                false_positive_contexts = [
                    'password:',  # Documentation
                    'password =',  # Example code
                    'password">',  # HTML
                    'your password',  # Instructions
                    'enter password',  # UI text
                    'password must',  # Validation rules
                    'password field',  # Documentation
                    'password input',  # UI reference
                    'password strength',  # Validation
                    'password policy',  # Documentation
                    'password requirements',  # Documentation
                    'example password',  # Documentation
                    'test password',  # Test data
                    'sample password',  # Example
                    'placeholder="password"',  # HTML
                    'type="password"'  # HTML
                ]

                content_lower = content.lower()
                # If any false positive context found, likely not a real secret
                if any(fp in content_lower for fp in false_positive_contexts):
                    return False

                # Check if it's in a comment
                for match in matches:
                    # Find the line containing the match
                    lines = content.split('\n')
                    for line in lines:
                        if match in line:
                            line_stripped = line.strip()
                            # Skip if it's a comment
                            if line_stripped.startswith('#') or line_stripped.startswith('//') or line_stripped.startswith('*'):
                                return False
                            # Skip if it's in documentation/markdown
                            if '```' in content or line.startswith('>'):
                                return False

            # For API keys, check if they look valid
            if secret_type == 'api_key':
                # Real API keys are usually longer and more random
                for match in matches:
                    if len(match) < 20:  # Too short to be real
                        return False
                    # Check for common placeholder patterns
                    if 'xxx' in match.lower() or 'your_api_key' in match.lower() or 'example' in match.lower():
                        return False

            # Database URLs in examples are common
            if secret_type == 'database_url':
                for match in matches:
                    if 'localhost' in match or '127.0.0.1' in match or 'example' in match:
                        return False

            # S3 buckets and cloud storage might be documentation
            if secret_type in {'s3_bucket', 'azure_storage', 'gcp_bucket'}:
                # If there are many matches, likely documentation
                if len(matches) > 5:
                    return False

            return True

    def s3_bucket_enumeration(self):
            """Perform S3 bucket enumeration"""
            self.print_section("S3 BUCKET ENUMERATION")

            # Get base domain - if 3+ parts, drop first (e.g., www.redcellsecurity.org -> redcellsecurity.org)
            domain_parts = self.domain.split('.')
            if len(domain_parts) > 2:
                base_domain = '.'.join(domain_parts[1:])
            else:
                base_domain = self.domain

            company_name = base_domain.split('.')[0]

            self.print_info(f"Searching for buckets matching: {company_name}")

            # Generate bucket name variations from domain
            bucket_candidates = set()

            # Basic domain variations
            bucket_candidates.add(base_domain)
            bucket_candidates.add(base_domain.replace('.', '-'))
            bucket_candidates.add(base_domain.replace('.', ''))

            # Add company name variations
            bucket_candidates.add(company_name)

            # Add variations from discovered subdomains
            resolved = self.results.get('dns_enumeration', {}).get('resolved', {})
            for subdomain in list(resolved.keys())[:20]:  # Limit to top 20
                # Extract subdomain part
                if subdomain.endswith(base_domain):
                    sub_part = subdomain.replace(f".{base_domain}", "").replace(f"{base_domain}", "")
                    if sub_part and '.' not in sub_part:
                        bucket_candidates.add(f"{sub_part}-{company_name}")
                        bucket_candidates.add(f"{company_name}-{sub_part}")

            # Add common prefixes/suffixes
            common_affixes = ['backup', 'backups', 'data', 'files', 'assets', 'static',
                            'uploads', 'images', 'docs', 'logs', 'dev', 'prod', 'staging']

            for affix in common_affixes:
                bucket_candidates.add(f"{company_name}-{affix}")
                bucket_candidates.add(f"{affix}-{company_name}")

            # Clean and limit bucket list
            bucket_candidates = [b.lower().strip() for b in bucket_candidates
                                if b and len(b) < 64 and b.replace('-', '').replace('.', '').isalnum()]

            self.print_info(f"Testing {len(bucket_candidates)} potential bucket names...")

            found_buckets = []

            # Check each bucket
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_bucket = {
                    executor.submit(self._check_s3_bucket, bucket): bucket
                    for bucket in bucket_candidates
                }

                for future in concurrent.futures.as_completed(future_to_bucket):
                    bucket_name = future_to_bucket[future]
                    try:
                        result = future.result()
                        if result:
                            found_buckets.append(result)
                            status = result['status']
                            if status == 'Public Read':
                                self.print_warning(f"PUBLICLY ACCESSIBLE: {bucket_name}")
                            elif status == 'Private (Exists)':
                                self.print_success(f"EXISTS (Private): {bucket_name}")
                            elif status == 'Redirect':
                                self.print_info(f"Redirects: {bucket_name}")
                    except Exception as e:
                        pass

            # Analyze accessible buckets AFTER discovery completes
            self.print_info(f"\nAnalyzing {len(found_buckets)} discovered buckets...")
            for bucket in found_buckets:
                if bucket['status'] in ['Public Read', 'Redirect']:
                    self.print_info(f"\n[*] Analyzing contents of {bucket['bucket']}...")
                    try:
                        self._analyze_s3_bucket_contents(bucket)
                    except Exception as e:
                        self.print_error(f"Analysis failed for {bucket['bucket']}: {e}")
                        import traceback
                        traceback.print_exc()

            self.results['s3_buckets'] = {
                'tested': len(bucket_candidates),
                'found': found_buckets,
                'public_count': len([b for b in found_buckets if b['status'] == 'Public Read']),
                'private_count': len([b for b in found_buckets if b['status'] == 'Private (Exists)'])
            }

            if found_buckets:
                self.print_warning(f"\nFound {len(found_buckets)} S3 buckets:")
                for bucket in found_buckets:
                    self.print_info(f"  {bucket['bucket']} - {bucket['status']}")
            else:
                self.print_success("No S3 buckets found")

    def _check_s3_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Check if S3 bucket exists"""
        urls_to_try = [
            f"https://s3.amazonaws.com/{bucket_name}/",
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.us-east-1.amazonaws.com/{bucket_name}/",
            f"https://s3.us-west-2.amazonaws.com/{bucket_name}/",
        ]

        for url in urls_to_try:
            try:
                response = self.session.get(url, timeout=5)

                if response.status_code == 200:
                    return {
                        'bucket': bucket_name,
                        'url': url,
                        'status': 'Public Read',
                        'response_length': len(response.content)
                    }
                elif response.status_code == 403:
                    return {
                        'bucket': bucket_name,
                        'url': url,
                        'status': 'Private (Exists)'
                    }
                elif response.status_code in [301, 302, 307, 308]:
                    return {
                        'bucket': bucket_name,
                        'url': url,
                        'status': 'Redirect',
                        'redirect_location': response.headers.get('Location', 'Unknown')
                    }
            except:
                continue

        return None

    def _analyze_s3_bucket_contents(self, bucket_info: Dict[str, Any]):
            """Analyze S3 bucket contents and download sensitive files only"""
            bucket_name = bucket_info.get('bucket', 'unknown')
            bucket_url = bucket_info.get('url', '')

            self.print_info(f"Fetching bucket listing from: {bucket_url}")

            try:
                response = self.session.get(bucket_url, timeout=10, verify=False)
                self.print_info(f"Response status: {response.status_code}")

                if response.status_code != 200:
                    self.print_warning(f"Cannot list bucket contents (status {response.status_code})")
                    return

                content = response.text
                self.print_info(f"Response length: {len(content)} bytes")

                files = []

                # Parse XML listing
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(content)

                    # Try S3 namespace
                    for contents in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
                        key = contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key')
                        size = contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size')
                        modified = contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}LastModified')

                        if key is not None:
                            file_url = f"https://{bucket_name}.s3.amazonaws.com/{key.text}"
                            files.append({
                                'key': key.text,
                                'size': int(size.text) if size is not None else 0,
                                'last_modified': modified.text if modified is not None else 'Unknown',
                                'url': file_url
                            })

                    # Try without namespace if nothing found
                    if not files:
                        for contents in root.findall('.//Contents'):
                            key = contents.find('Key')
                            size = contents.find('Size')
                            modified = contents.find('LastModified')

                            if key is not None:
                                file_url = f"https://{bucket_name}.s3.amazonaws.com/{key.text}"
                                files.append({
                                    'key': key.text,
                                    'size': int(size.text) if size is not None else 0,
                                    'last_modified': modified.text if modified is not None else 'Unknown',
                                    'url': file_url
                                })

                except ET.ParseError as e:
                    self.print_warning(f"XML parsing failed: {e}")
                    # Fallback regex
                    keys = re.findall(r'<Key>([^<]+)</Key>', content)
                    self.print_info(f"Regex found {len(keys)} keys")
                    for k in keys:
                        file_url = f"https://{bucket_name}.s3.amazonaws.com/{k}"
                        files.append({'key': k, 'size': 0, 'last_modified': 'Unknown', 'url': file_url})

                bucket_info['files'] = files
                bucket_info['file_count'] = len(files)

                if not files:
                    self.print_warning(f"  No files found in bucket (may be empty or misconfigured)")
                    self.print_info(f"  Response preview: {content[:500]}")
                    return

                total_size = sum(f['size'] for f in files) / 1024  # KB
                self.print_success(f"  Found {len(files)} files ({total_size:.1f}KB total)")

                # Filter files by sensitivity using inline logic
                sensitive_files = []
                excluded_files = []

                # Define exclusion and interest patterns
                exclude_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico',
                                    '.tiff', '.tif', '.heic', '.heif', '.mp4', '.mp3', '.avi', '.mov',
                                    '.wav', '.flac', '.woff', '.woff2', '.ttf', '.eot', '.otf'}

                high_interest_extensions = {'.env', '.config', '.conf', '.cfg', '.ini', '.yaml', '.yml',
                                        '.key', '.pem', '.p12', '.pfx', '.cer', '.crt', '.ppk',
                                        '.keystore', '.jks', '.kdbx', '.sql', '.db', '.sqlite',
                                        '.bak', '.backup', '.old'}

                medium_interest_extensions = {'.json', '.xml', '.properties', '.log', '.txt', '.csv',
                                            '.xlsx', '.xls', '.doc', '.docx', '.pdf', '.pcap', '.cap',
                                            '.py', '.js', '.php', '.sh', '.bash', '.ps1', '.bat'}

                sensitive_keywords = ['password', 'passwd', 'secret', 'credential', 'apikey', 'api_key',
                                    'private', 'confidential', 'backup', 'dump', 'export', 'users',
                                    'accounts', 'token', 'auth', 'config', 'settings', 'id_rsa',
                                    'wallet', 'shadow', 'htpasswd']

                for f in files:
                    filename_lower = f['key'].lower()
                    is_sensitive = False
                    reason = 'EXCLUDED'

                    # Check if excluded
                    if any(filename_lower.endswith(ext) for ext in exclude_extensions):
                        excluded_files.append(f)
                        continue

                    # Check high interest extensions
                    for ext in high_interest_extensions:
                        if filename_lower.endswith(ext):
                            is_sensitive = True
                            reason = f'HIGH: {ext} file'
                            break

                    # Check sensitive keywords in filename
                    if not is_sensitive:
                        for keyword in sensitive_keywords:
                            if keyword in filename_lower:
                                is_sensitive = True
                                reason = f'HIGH: Contains "{keyword}"'
                                break

                    # Check medium interest extensions
                    if not is_sensitive:
                        for ext in medium_interest_extensions:
                            if filename_lower.endswith(ext):
                                is_sensitive = True
                                reason = f'MEDIUM: {ext} file'
                                break

                    # If still not categorized, include as unknown (might be interesting)
                    if not is_sensitive and not any(filename_lower.endswith(ext) for ext in exclude_extensions):
                        is_sensitive = True
                        reason = 'UNKNOWN: Unknown file type'

                    if is_sensitive:
                        sensitive_files.append((f, reason))
                    else:
                        excluded_files.append(f)

                self.print_info(f"  Files breakdown: {len(sensitive_files)} sensitive/interesting, {len(excluded_files)} excluded")

                if not sensitive_files:
                    self.print_warning(f"  No sensitive files identified for download")
                    return

                # Show what we're downloading and why
                self.print_info(f"  Files identified for download:")
                for f, reason in sensitive_files[:10]:
                    self.print_info(f"    - {f['key']} ({f['size']/1024:.1f}KB) - {reason}")
                if len(sensitive_files) > 10:
                    self.print_info(f"    ... and {len(sensitive_files)-10} more")

                # Create download directory
                download_dir = self.output_dir / 's3_downloads' / bucket_name
                download_dir.mkdir(parents=True, exist_ok=True)
                self.print_info(f"  Download directory: {download_dir}")

                # Download sensitive files only (limit to first 100 sensitive files and 10MB each)
                downloaded_count = 0
                for f, reason in sensitive_files[:100]:
                    file_name = f['key'].split('/')[-1]
                    if not file_name:  # Skip directories
                        continue

                    output_path = download_dir / file_name
                    self.print_info(f"    Downloading: {f['key']} ({f['size']/1024:.1f}KB) - {reason}")

                    if self._download_file(f['url'], output_path):
                        downloaded_count += 1
                        self.print_success(f"      Saved to: {output_path}")

                    time.sleep(0.5)  # Rate limiting

                if len(sensitive_files) > 100:
                    self.print_warning(f"    Only downloaded first 100 files (total sensitive: {len(sensitive_files)})")

                if downloaded_count > 0:
                    self.print_success(f"  Downloaded {downloaded_count} sensitive files to {download_dir}")
                else:
                    self.print_warning(f"  No files were downloaded (check permissions or size limits)")

            except Exception as e:
                self.print_error(f"Error analyzing bucket {bucket_name}: {e}")
                import traceback
                traceback.print_exc()

    def azure_storage_enumeration(self):
            """Enumerate Azure Blob Storage containers"""
            self.print_section("AZURE STORAGE ENUMERATION")

            # Get base domain - if 3+ parts, drop first (e.g., www.redcellsecurity.org -> redcellsecurity.org)
            domain_parts = self.domain.split('.')
            if len(domain_parts) > 2:
                base_domain = '.'.join(domain_parts[1:])
            else:
                base_domain = self.domain

            company_name = base_domain.split('.')[0]

            self.print_info(f"Searching for storage accounts matching: {company_name}")

            # Generate Azure storage account name variations
            storage_candidates = set()

            # Basic domain variations
            storage_candidates.add(company_name)
            storage_candidates.add(base_domain.replace('.', ''))

            # Add variations from discovered subdomains
            resolved = self.results.get('dns_enumeration', {}).get('resolved', {})
            for subdomain in list(resolved.keys())[:20]:
                if subdomain.endswith(base_domain):
                    sub_part = subdomain.replace(f".{base_domain}", "").replace(f"{base_domain}", "")
                    if sub_part and '.' not in sub_part:
                        storage_candidates.add(f"{company_name}{sub_part}".replace('-', '').replace('_', ''))

            # Add common affixes
            common_affixes = ['backup', 'backups', 'data', 'files', 'storage', 'assets',
                            'static', 'uploads', 'images', 'docs', 'logs', 'dev', 'prod',
                            'staging', 'test', 'blob', 'store']

            for affix in common_affixes:
                storage_candidates.add(f"{company_name}{affix}".replace('-', '').replace('_', ''))
                storage_candidates.add(f"{affix}{company_name}".replace('-', '').replace('_', ''))

            # Clean candidates - Azure storage names must be 3-24 chars, lowercase, alphanumeric
            storage_candidates = [
                name.lower().replace('-', '').replace('_', '')
                for name in storage_candidates
                if name and 3 <= len(name.replace('-', '').replace('_', '')) <= 24
            ]
            storage_candidates = list(set(storage_candidates))

            self.print_info(f"Testing {len(storage_candidates)} potential Azure storage account names...")

            found_storage = []

            # Check each storage account
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_storage = {
                    executor.submit(self._check_azure_storage, account): account
                    for account in storage_candidates
                }

                for future in concurrent.futures.as_completed(future_to_storage):
                    account_name = future_to_storage[future]
                    try:
                        result = future.result()
                        if result:
                            found_storage.append(result)
                            status = result['status']
                            if status == 'Public Read':
                                self.print_warning(f"PUBLICLY ACCESSIBLE: {account_name}")
                            elif status == 'Private (Exists)':
                                self.print_success(f"EXISTS (Private): {account_name}")
                    except Exception as e:
                        pass

            # Summary FIRST
            self.results['azure_storage'] = {
                'tested': len(storage_candidates),
                'found': found_storage,
                'public_count': len([s for s in found_storage if s['status'] == 'Public Read']),
                'private_count': len([s for s in found_storage if s['status'] == 'Private (Exists)'])
            }

            if found_storage:
                self.print_warning(f"\nFound {len(found_storage)} Azure storage accounts:")
                for storage in found_storage:
                    self.print_info(f"  {storage['account']} - {storage['status']}")
            else:
                self.print_success("No Azure storage accounts found")

            # Analyze accessible storage accounts AFTER summary
            public_storage = [s for s in found_storage if s['status'] == 'Public Read']
            if public_storage:
                self.print_info(f"\n[*] Analyzing {len(public_storage)} publicly accessible storage accounts...")
                for storage in public_storage:
                    self.print_info(f"\n[*] Analyzing contents of {storage['account']}...")
                    try:
                        self._analyze_azure_storage_contents(storage)
                    except Exception as e:
                        self.print_error(f"Analysis failed for {storage['account']}: {e}")
                        import traceback
                        traceback.print_exc()

    def _check_azure_storage(self, account_name: str) -> Optional[Dict[str, Any]]:
        """Check if Azure storage account exists"""
        # Try different container names
        container_names = ['$web', 'public', 'files', 'assets', 'data', 'backup', 'images']

        for container in container_names:
            urls_to_try = [
                f"https://{account_name}.blob.core.windows.net/{container}?restype=container&comp=list",
                f"https://{account_name}.blob.core.windows.net/{container}/",
            ]

            for url in urls_to_try:
                try:
                    response = self.session.get(url, timeout=5)

                    if response.status_code == 200:
                        return {
                            'account': account_name,
                            'container': container,
                            'url': url,
                            'status': 'Public Read',
                            'response_length': len(response.content)
                        }
                    elif response.status_code == 403:
                        return {
                            'account': account_name,
                            'container': container,
                            'url': url,
                            'status': 'Private (Exists)'
                        }
                    elif response.status_code == 404:
                        # Container doesn't exist, but account might
                        continue

                except Exception as e:
                    continue

        return None

    def _analyze_azure_storage_contents(self, storage_info: Dict[str, Any]):
            """Analyze Azure storage container contents"""
            account_name = storage_info.get('account', 'unknown')
            container = storage_info.get('container', 'unknown')
            storage_url = storage_info.get('url', '')

            self.print_info(f"Fetching container listing from: {storage_url}")

            try:
                response = self.session.get(storage_url, timeout=10, verify=False)
                self.print_info(f"Response status: {response.status_code}")

                if response.status_code != 200:
                    self.print_warning(f"Cannot list container contents (status {response.status_code})")
                    return

                content = response.text
                self.print_info(f"Response length: {len(content)} bytes")
                files = []

                # Parse Azure XML listing
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(content)

                    # Azure uses different namespace
                    for blob in root.findall('.//{http://schemas.microsoft.com/ado/2007/08/dataservices}Name'):
                        file_url = f"https://{account_name}.blob.core.windows.net/{container}/{blob.text}"
                        file_info = {
                            'name': blob.text,
                            'url': file_url
                        }
                        files.append(file_info)

                    # Also try without namespace
                    if not files:
                        for blob in root.findall('.//Name'):
                            file_url = f"https://{account_name}.blob.core.windows.net/{container}/{blob.text}"
                            file_info = {
                                'name': blob.text,
                                'url': file_url
                            }
                            files.append(file_info)

                except ET.ParseError as e:
                    self.print_warning(f"XML parsing failed: {e}")
                    # Fallback regex parsing
                    names = re.findall(r'<Name>([^<]+)</Name>', content)
                    self.print_info(f"Regex found {len(names)} names")
                    for name in names:
                        file_url = f"https://{account_name}.blob.core.windows.net/{container}/{name}"
                        files.append({
                            'name': name,
                            'url': file_url
                        })

                storage_info['files'] = files
                storage_info['file_count'] = len(files)

                if not files:
                    self.print_warning(f"  No files found in container (may be empty or misconfigured)")
                    self.print_info(f"  Response preview: {content[:500]}")
                    return

                self.print_success(f"  Found {len(files)} blob(s)")

                # Show sample files
                self.print_info(f"  Sample blobs:")
                for f in files[:5]:
                    self.print_info(f"    - {f['name']}")
                if len(files) > 5:
                    self.print_info(f"    ... and {len(files)-5} more")

                # Create download directory
                download_dir = self.output_dir / 'azure_downloads' / f"{account_name}_{container}"
                download_dir.mkdir(parents=True, exist_ok=True)
                self.print_info(f"  Download directory: {download_dir}")

                # Download files (limit to first 50 files)
                downloaded_count = 0
                for f in files[:50]:
                    file_name = f['name'].split('/')[-1]
                    if not file_name:  # Skip directories
                        continue

                    output_path = download_dir / file_name
                    self.print_info(f"    Downloading: {f['name']}")

                    if self._download_file(f['url'], output_path):
                        downloaded_count += 1
                        self.print_success(f"      Saved to: {output_path}")

                    time.sleep(0.5)  # Rate limiting

                if len(files) > 50:
                    self.print_warning(f"    Only downloaded first 50 files (total: {len(files)})")

                if downloaded_count > 0:
                    self.print_success(f"  Downloaded {downloaded_count} files to {download_dir}")
                else:
                    self.print_warning(f"  No files were downloaded (check permissions or size limits)")

            except Exception as e:
                self.print_error(f"Error analyzing Azure storage {account_name}: {e}")
                import traceback
                traceback.print_exc()

    def gcp_storage_enumeration(self):
            """Enumerate Google Cloud Platform (GCP) Storage buckets"""
            self.print_section("GCP STORAGE ENUMERATION")

            # Get base domain - if 3+ parts, drop first (e.g., www.redcellsecurity.org -> redcellsecurity.org)
            domain_parts = self.domain.split('.')
            if len(domain_parts) > 2:
                base_domain = '.'.join(domain_parts[1:])
            else:
                base_domain = self.domain

            company_name = base_domain.split('.')[0]

            self.print_info(f"Searching for buckets matching: {company_name}")

            # Generate GCP bucket name variations
            bucket_candidates = set()

            # Basic domain variations
            bucket_candidates.add(base_domain)
            bucket_candidates.add(base_domain.replace('.', '-'))
            bucket_candidates.add(base_domain.replace('.', '_'))
            bucket_candidates.add(base_domain.replace('.', ''))
            bucket_candidates.add(company_name)

            # Add variations from discovered subdomains
            resolved = self.results.get('dns_enumeration', {}).get('resolved', {})
            for subdomain in list(resolved.keys())[:20]:
                if subdomain.endswith(base_domain):
                    sub_part = subdomain.replace(f".{base_domain}", "").replace(f"{base_domain}", "")
                    if sub_part and '.' not in sub_part:
                        bucket_candidates.add(f"{sub_part}-{company_name}")
                        bucket_candidates.add(f"{company_name}-{sub_part}")

            # Add common affixes
            common_affixes = ['backup', 'backups', 'data', 'files', 'storage', 'assets',
                            'static', 'uploads', 'images', 'docs', 'logs', 'dev', 'prod',
                            'staging', 'test', 'bucket', 'gcs', 'gcp']

            for affix in common_affixes:
                bucket_candidates.add(f"{company_name}-{affix}")
                bucket_candidates.add(f"{affix}-{company_name}")
                bucket_candidates.add(f"{company_name}_{affix}")
                bucket_candidates.add(f"{affix}_{company_name}")

            # Clean candidates - GCP bucket names: 3-63 chars, lowercase letters, numbers, hyphens, underscores, dots
            bucket_candidates = [
                name.lower().strip()
                for name in bucket_candidates
                if name and 3 <= len(name) <= 63 and re.match(r'^[a-z0-9][a-z0-9._-]*[a-z0-9]$', name.lower())
            ]
            bucket_candidates = list(set(bucket_candidates))

            self.print_info(f"Testing {len(bucket_candidates)} potential GCP bucket names...")

            found_buckets = []

            # Check each bucket
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_bucket = {
                    executor.submit(self._check_gcp_bucket, bucket): bucket
                    for bucket in bucket_candidates
                }

                for future in concurrent.futures.as_completed(future_to_bucket):
                    bucket_name = future_to_bucket[future]
                    try:
                        result = future.result()
                        if result:
                            found_buckets.append(result)
                            status = result['status']
                            if status == 'Public Read':
                                self.print_warning(f"PUBLICLY ACCESSIBLE: {bucket_name}")
                            elif status == 'Private (Exists)':
                                self.print_success(f"EXISTS (Private): {bucket_name}")
                    except Exception as e:
                        pass

            # Summary FIRST
            self.results['gcp_storage'] = {
                'tested': len(bucket_candidates),
                'found': found_buckets,
                'public_count': len([b for b in found_buckets if b['status'] == 'Public Read']),
                'private_count': len([b for b in found_buckets if b['status'] == 'Private (Exists)'])
            }

            if found_buckets:
                self.print_warning(f"\nFound {len(found_buckets)} GCP storage buckets:")
                for bucket in found_buckets:
                    self.print_info(f"  {bucket['bucket']} - {bucket['status']}")
            else:
                self.print_success("No GCP storage buckets found")

            # Analyze accessible buckets AFTER summary
            public_buckets = [b for b in found_buckets if b['status'] == 'Public Read']
            if public_buckets:
                self.print_info(f"\n[*] Analyzing {len(public_buckets)} publicly accessible buckets...")
                for bucket in public_buckets:
                    self.print_info(f"\n[*] Analyzing contents of {bucket['bucket']}...")
                    try:
                        self._analyze_gcp_bucket_contents(bucket)
                    except Exception as e:
                        self.print_error(f"Analysis failed for {bucket['bucket']}: {e}")
                        import traceback
                        traceback.print_exc()

    def _check_gcp_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
            """Check if GCP storage bucket exists"""
            urls_to_try = [
                f"https://storage.googleapis.com/{bucket_name}/",
                f"https://{bucket_name}.storage.googleapis.com/",
                f"https://storage.cloud.google.com/{bucket_name}/",
            ]

            for url in urls_to_try:
                try:
                    response = self.session.get(url, timeout=5, allow_redirects=False)

                    if response.status_code == 200:
                        # Check if response is actually XML (not HTML login page)
                        content_type = response.headers.get('Content-Type', '')
                        content = response.text[:1000]  # Check first 1000 chars

                        # If it's HTML or contains login/signin, it's not actually public
                        if 'text/html' in content_type or 'accounts.google.com' in content or '<html' in content.lower():
                            # This is a redirect to login page, bucket exists but is private
                            return {
                                'bucket': bucket_name,
                                'url': url,
                                'status': 'Private (Exists)'
                            }

                        # Check if it's valid XML
                        if 'xml' in content_type or '<?xml' in content or '<ListBucketResult' in content:
                            return {
                                'bucket': bucket_name,
                                'url': url,
                                'status': 'Public Read',
                                'response_length': len(response.content)
                            }
                        else:
                            # Unknown response type, mark as exists but unclear status
                            return {
                                'bucket': bucket_name,
                                'url': url,
                                'status': 'Private (Exists)'
                            }

                    elif response.status_code == 403:
                        # Check if it's a "bucket exists but private" vs "access denied"
                        if 'Access denied' in response.text or 'does not have permission' in response.text:
                            return {
                                'bucket': bucket_name,
                                'url': url,
                                'status': 'Private (Exists)'
                            }
                    elif response.status_code in [301, 302, 307, 308]:
                        # Check redirect location
                        location = response.headers.get('Location', '')
                        if 'accounts.google.com' in location:
                            # Redirecting to login, so bucket exists but is private
                            return {
                                'bucket': bucket_name,
                                'url': url,
                                'status': 'Private (Exists)'
                            }
                    elif response.status_code == 404:
                        # Bucket doesn't exist
                        continue

                except Exception as e:
                    continue

            return None

    def _analyze_gcp_bucket_contents(self, bucket_info: Dict[str, Any]):
            """Analyze GCP storage bucket contents"""
            bucket_name = bucket_info.get('bucket', 'unknown')
            bucket_url = bucket_info.get('url', '')

            self.print_info(f"Fetching bucket listing from: {bucket_url}")

            try:
                response = self.session.get(bucket_url, timeout=10, verify=False, allow_redirects=False)
                self.print_info(f"Response status: {response.status_code}")

                if response.status_code != 200:
                    self.print_warning(f"Cannot list bucket contents (status {response.status_code})")
                    return

                content = response.text
                content_type = response.headers.get('Content-Type', '')

                # Check if response is HTML instead of XML
                if 'text/html' in content_type or '<html' in content[:1000].lower():
                    self.print_warning(f"Bucket returned HTML instead of XML (likely requires authentication)")
                    self.print_warning(f"This bucket is NOT actually publicly accessible")
                    # Update the bucket status
                    bucket_info['status'] = 'Private (Exists)'
                    return

                self.print_info(f"Response length: {len(content)} bytes")
                self.print_info(f"Content-Type: {content_type}")

                files = []

                # Parse GCP XML listing
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(content)

                    # GCP uses similar structure to S3
                    for contents in root.findall('.//{http://doc.s3.amazonaws.com/2006-03-01}Contents'):
                        key = contents.find('{http://doc.s3.amazonaws.com/2006-03-01}Key')
                        size = contents.find('{http://doc.s3.amazonaws.com/2006-03-01}Size')
                        modified = contents.find('{http://doc.s3.amazonaws.com/2006-03-01}LastModified')

                        if key is not None:
                            file_url = f"https://storage.googleapis.com/{bucket_name}/{key.text}"
                            file_info = {
                                'key': key.text,
                                'size': int(size.text) if size is not None else 0,
                                'last_modified': modified.text if modified is not None else 'Unknown',
                                'url': file_url
                            }
                            files.append(file_info)

                    # Also try without namespace
                    if not files:
                        for contents in root.findall('.//Contents'):
                            key = contents.find('Key')
                            size = contents.find('Size')
                            modified = contents.find('LastModified')

                            if key is not None:
                                file_url = f"https://storage.googleapis.com/{bucket_name}/{key.text}"
                                file_info = {
                                    'key': key.text,
                                    'size': int(size.text) if size is not None else 0,
                                    'last_modified': modified.text if modified is not None else 'Unknown',
                                    'url': file_url
                                }
                                files.append(file_info)

                except ET.ParseError as e:
                    self.print_warning(f"XML parsing failed: {e}")
                    # Check if content looks like XML at all
                    if not content.strip().startswith('<?xml') and not content.strip().startswith('<'):
                        self.print_warning("Response doesn't appear to be XML")
                        return

                    # Fallback regex parsing
                    keys = re.findall(r'<Key>([^<]+)</Key>', content)
                    sizes = re.findall(r'<Size>([^<]+)</Size>', content)
                    self.print_info(f"Regex found {len(keys)} keys")

                    for i, key in enumerate(keys):
                        size = int(sizes[i]) if i < len(sizes) and sizes[i].isdigit() else 0
                        file_url = f"https://storage.googleapis.com/{bucket_name}/{key}"
                        files.append({
                            'key': key,
                            'size': size,
                            'last_modified': 'Unknown',
                            'url': file_url
                        })

                bucket_info['files'] = files
                bucket_info['file_count'] = len(files)

                if not files:
                    self.print_warning(f"  No files found in bucket (bucket may be empty)")
                    return

                total_size = sum(f['size'] for f in files) / 1024  # KB
                self.print_success(f"  Found {len(files)} file(s) ({total_size:.1f}KB total)")

                # Show sample files
                self.print_info(f"  Sample files:")
                for f in files[:5]:
                    self.print_info(f"    - {f['key']} ({f['size']/1024:.1f}KB)")
                if len(files) > 5:
                    self.print_info(f"    ... and {len(files)-5} more")

                # Create download directory
                download_dir = self.output_dir / 'gcp_downloads' / bucket_name
                download_dir.mkdir(parents=True, exist_ok=True)
                self.print_info(f"  Download directory: {download_dir}")

                # Download files (limit to first 50 files and 10MB each)
                downloaded_count = 0
                for f in files[:50]:
                    file_name = f['key'].split('/')[-1]
                    if not file_name:  # Skip directories
                        continue

                    output_path = download_dir / file_name
                    self.print_info(f"    Downloading: {f['key']} ({f['size']/1024:.1f}KB)")

                    if self._download_file(f['url'], output_path):
                        downloaded_count += 1
                        self.print_success(f"      Saved to: {output_path}")

                    time.sleep(0.5)  # Rate limiting

                if len(files) > 50:
                    self.print_warning(f"    Only downloaded first 50 files (total: {len(files)})")

                if downloaded_count > 0:
                    self.print_success(f"  Downloaded {downloaded_count} files to {download_dir}")
                else:
                    self.print_warning(f"  No files were downloaded (check permissions or size limits)")

            except Exception as e:
                self.print_error(f"Error analyzing GCP bucket {bucket_name}: {e}")
                import traceback
                traceback.print_exc()

    def breach_database_check(self):
            """Check for compromised credentials in breach databases"""
            self.print_section("BREACH DATABASE CHECK")

            # Only check emails from target domain
            all_emails = self.results.get('email_addresses', [])
            target_emails = [e for e in all_emails if self.domain in e]

            if not target_emails:
                self.print_warning(f"No email addresses from target domain ({self.domain}) to check.")
                return

            breach_results = {}

            self.print_info("Checking Have I Been Pwned (HIBP) API...")
            self.print_info(f"Note: HIBP now requires an API key for full access")

            for email in target_emails[:10]:  # Limit to first 10 to avoid rate limits
                breaches = self._check_hibp(email)
                if breaches:
                    breach_results[email] = breaches
                    self.print_warning(f"{email}: Found in {len(breaches)} breach(es)")
                else:
                    self.print_success(f"{email}: No breaches found")

                time.sleep(1.5)  # Rate limiting

            self.results['breach_data'] = breach_results

            if breach_results:
                self.print_warning(f"\nTotal accounts with breaches: {len(breach_results)}")
                for email, breaches in breach_results.items():
                    self.print_warning(f"  {email}:")
                    for breach in breaches[:5]:  # Show first 5
                        self.print_info(f"    - {breach}")
            else:
                self.print_success("No compromised credentials found in breach databases")

    def _check_hibp(self, email: str) -> List[str]:
            """Check email against Have I Been Pwned API"""
            breaches = []
            try:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                headers = {
                    'User-Agent': 'Penetration-Testing-Reconnaissance-Tool',
                    'hibp-api-key': self.config.get('hibp_api_key', '')  # Optional API key
                }
                response = requests.get(url, headers=headers, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    breaches = [breach['Name'] for breach in data]
                elif response.status_code == 404:
                    # No breaches found (good news)
                    pass
                elif response.status_code == 401:
                    # API key required or invalid
                    if not self.config.get('hibp_api_key'):
                        self.print_warning("HIBP API requires a key for reliable access. Get one at https://haveibeenpwned.com/API/Key")
                        self.print_info("Continuing with limited/public API access...")
                    else:
                        self.print_warning("HIBP API key is invalid")
                elif response.status_code == 429:
                    self.print_warning(f"HIBP rate limit hit for {email}")
                else:
                    self.print_warning(f"HIBP API returned status {response.status_code} for {email}")
            except Exception as e:
                self.print_warning(f"HIBP check failed for {email}: {e}")

            return breaches

    def network_enumeration(self):
            """Perform network scanning on in-scope IP ranges"""
            self.print_section("NETWORK ENUMERATION")

            # Skip if no IP ranges provided
            if not self.ip_ranges:
                self.print_warning("Skipping network enumeration (no IP ranges provided)")
                return

            self.print_info("Starting network scan (this may take a while)...")

            scan_results = {}

            for ip_range in self.ip_ranges:
                self.print_info(f"Scanning {ip_range}...")

                # Quick host discovery
                live_hosts = self._host_discovery(ip_range)
                self.print_success(f"Found {len(live_hosts)} live hosts in {ip_range}")

                # Port scan live hosts
                for host in live_hosts:
                    self.print_info(f"Port scanning {host}...")
                    ports = self._port_scan(host)
                    if ports:
                        scan_results[host] = ports
                        self.print_success(f"{host}: {len(ports)} open ports")

            self.results['network_scan'] = scan_results

            self.print_success(f"Network scan complete. {len(scan_results)} hosts with open ports")

    def _host_discovery(self, ip_range: str) -> List[str]:
        """Discover live hosts in IP range"""
        live_hosts = []

        try:
            output = self.run_command([
                'nmap',
                '-sn',  # Ping scan only
                '-T4',  # Aggressive timing
                '--min-rate', '1000',
                ip_range
            ], timeout=300)

            if output:
                # Parse nmap output for live hosts
                lines = output.split('\n')
                for line in lines:
                    if 'Nmap scan report for' in line:
                        # Extract IP address
                        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                        if match:
                            live_hosts.append(match.group(1))
        except Exception as e:
            self.print_error(f"Host discovery failed: {e}")

        return live_hosts

    def _port_scan(self, host: str) -> Dict[int, Dict[str, str]]:
        """Scan ports on a host"""
        ports = {}

        try:
            output = self.run_command([
                'nmap',
                '-sV',  # Service version detection
                '-T4',  # Aggressive timing
                '--top-ports', '1000',  # Scan top 1000 ports
                '--min-rate', '1000',
                host
            ], timeout=300)

            if output:
                # Parse nmap output
                lines = output.split('\n')
                for line in lines:
                    if '/tcp' in line or '/udp' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_proto = parts[0]
                            port_num = int(port_proto.split('/')[0])
                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else 'unknown'

                            if state == 'open':
                                ports[port_num] = {
                                    'state': state,
                                    'service': service,
                                    'version': ' '.join(parts[3:]) if len(parts) > 3 else ''
                                }
        except Exception as e:
            self.print_error(f"Port scan failed for {host}: {e}")

        return ports

    def generate_report(self):
        """Generate comprehensive report"""
        self.print_section("GENERATING REPORT")

        # Save JSON results
        json_file = self.output_dir / f"recon_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        self.print_success(f"JSON results saved to: {json_file}")

        # Generate markdown report
        md_file = self.output_dir / f"recon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        self._generate_markdown_report(md_file)
        self.print_success(f"Markdown report saved to: {md_file}")

        # Generate report template content
        template_file = self.output_dir / f"report_template_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self._generate_report_template(template_file)
        self.print_success(f"Report template saved to: {template_file}")

    def _generate_markdown_report(self, filepath: Path):
            """Generate markdown format report"""
            with open(filepath, 'w') as f:
                f.write(f"# Penetration Testing Reconnaissance Report\n\n")
                f.write(f"**Client:** {self.client_name}\n\n")
                f.write(f"**Domain:** {self.domain}\n\n")
                f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"---\n\n")

                # Scope Validation
                f.write(f"## Scope Validation\n\n")
                whois = self.results.get('scope_validation', {}).get('whois', {})
                for ip_range, info in whois.items():
                    f.write(f"### {ip_range}\n")
                    f.write(f"- **Organization:** {info.get('org', 'N/A')}\n")
                    f.write(f"- **Net Range:** {info.get('netrange', 'N/A')}\n")
                    f.write(f"- **Country:** {info.get('country', 'N/A')}\n\n")

                # DNS Enumeration
                f.write(f"## DNS Enumeration\n\n")
                dns = self.results.get('dns_enumeration', {})
                f.write(f"**Total Subdomains Discovered:** {dns.get('total_discovered', 0)}\n\n")

                # CT Log domains
                ct_domains = dns.get('ct_log_domains', [])
                if ct_domains:
                    f.write(f"### Certificate Transparency Log Domains ({len(ct_domains)})\n\n")
                    f.write(f"Domains discovered via crt.sh and certificate transparency logs:\n\n")
                    for domain in ct_domains:
                        f.write(f"- `{domain}`\n")
                    f.write(f"\n")

                # Bruteforce domains
                brute_domains = dns.get('bruteforce_domains', [])
                if brute_domains:
                    f.write(f"### DNS Bruteforce Domains ({len(brute_domains)})\n\n")
                    f.write(f"Domains discovered via DNS bruteforce enumeration:\n\n")
                    for domain in brute_domains:
                        f.write(f"- `{domain}`\n")
                    f.write(f"\n")

                # Resolved subdomains
                resolved = dns.get('resolved', {})
                if resolved:
                    f.write(f"### Resolved Subdomains ({len(resolved)})\n\n")
                    f.write(f"Subdomains that successfully resolved to IP addresses:\n\n")
                    for subdomain, ips in sorted(resolved.items()):
                        f.write(f"- `{subdomain}` → {', '.join(ips)}\n")
                    f.write(f"\n")

                # Unresolved domains
                unresolved = dns.get('unresolved', [])
                if unresolved:
                    f.write(f"### Unresolved Domains ({len(unresolved)})\n\n")
                    f.write(f"Domains that did not resolve (may be expired, internal, or misconfigured):\n\n")
                    for domain in unresolved[:100]:
                        f.write(f"- `{domain}`\n")
                    if len(unresolved) > 100:
                        f.write(f"- ... and {len(unresolved) - 100} more\n")
                    f.write(f"\n")

                # Subdomain Takeover
                f.write(f"## Subdomain Takeover Vulnerabilities\n\n")
                takeovers = self.results.get('subdomain_takeovers', [])
                if takeovers:
                    f.write(f"**Potentially Vulnerable Subdomains:** {len(takeovers)}\n\n")
                    for vuln in takeovers:
                        f.write(f"### {vuln['subdomain']}\n")
                        f.write(f"- **Service:** {vuln['service']}\n")
                        f.write(f"- **Confidence:** {vuln.get('confidence', 'Unknown')}\n")
                        if vuln.get('cname'):
                            f.write(f"- **CNAME:** {', '.join(vuln['cname'])}\n")
                        f.write(f"- **Risk:** Subdomain may be claimable by attacker\n\n")
                else:
                    f.write(f"No subdomain takeover vulnerabilities detected.\n\n")

                # Technology Stack
                f.write(f"## Technology Stack\n\n")
                tech = self.results.get('technology_stack', {})
                if tech:
                    f.write(f"**Systems Analyzed:** {len(tech)}\n\n")
                    for domain, info in sorted(tech.items()):
                        f.write(f"### {domain}\n")
                        if info.get('server'):
                            f.write(f"- **Server:** {info['server']}\n")
                        if info.get('powered_by'):
                            f.write(f"- **Powered By:** {info['powered_by']}\n")
                        if info.get('detected_technologies'):
                            f.write(f"- **Technologies:** {', '.join(info['detected_technologies'])}\n")
                        if info.get('headers'):
                            f.write(f"- **Security Headers:**\n")
                            for header, value in info['headers'].items():
                                if header not in ['Server', 'X-Powered-By']:
                                    f.write(f"  - {header}: {value}\n")
                        f.write(f"\n")
                else:
                    f.write(f"No technology stack information collected.\n\n")

                # LinkedIn Intelligence
                f.write(f"## LinkedIn Intelligence\n\n")
                linkedin = self.results.get('linkedin_intel', {})

                # New format with companies and employees
                companies = linkedin.get('company_info', {}).get('companies', [])
                employees = linkedin.get('employees', [])

                f.write(f"**Companies Found:** {len(companies)}\n")
                f.write(f"**Employees Found:** {len(employees)}\n\n")

                if companies:
                    f.write(f"### Companies\n\n")
                    for company in companies:
                        f.write(f"- **{company['name']}**\n")
                        if company.get('url'):
                            f.write(f"  - {company['url']}\n")
                    f.write(f"\n")

                if employees:
                    f.write(f"### Employees\n\n")
                    for emp in employees:
                        title_info = f" - {emp['title']}" if emp.get('title') and emp['title'] != 'Unknown' else ""
                        f.write(f"- **{emp['name']}**{title_info}\n")
                        if emp.get('profile_url'):
                            f.write(f"  - Profile: {emp['profile_url']}\n")
                        if emp.get('possible_email'):
                            f.write(f"  - Possible Email: {emp['possible_email']}\n")
                    f.write(f"\n")

                departments = linkedin.get('departments', [])
                if departments:
                    f.write(f"### Departments Identified\n\n")
                    for dept in departments:
                        f.write(f"- {dept.title()}\n")
                    f.write(f"\n")

                titles = linkedin.get('titles', {})
                if titles:
                    f.write(f"### Top Job Titles\n\n")
                    sorted_titles = sorted(titles.items(), key=lambda x: x[1], reverse=True)[:15]
                    for title, count in sorted_titles:
                        f.write(f"- {title} ({count})\n")
                    f.write(f"\n")

                # Legacy support for old format
                google_results = linkedin.get('google_dork_results', [])
                inferred = linkedin.get('inferred_employees', [])

                if google_results or inferred:
                    f.write(f"### Legacy Data\n\n")
                    f.write(f"**Profiles Found (Google):** {len(google_results)}\n")
                    f.write(f"**Employees Inferred:** {len(inferred)}\n\n")

                    if linkedin.get('email_patterns'):
                        pattern = linkedin['email_patterns'].get('likely_pattern', 'Unknown')
                        confidence = linkedin['email_patterns'].get('confidence', 0)
                        f.write(f"**Email Pattern:** {pattern} ({confidence:.0f}% confidence)\n\n")

                    if inferred:
                        f.write(f"#### Inferred Employees (Sample)\n\n")
                        for emp in inferred[:10]:
                            f.write(f"- {emp['name']} ({emp['email']})\n")
                        if len(inferred) > 10:
                            f.write(f"- ... and {len(inferred) - 10} more\n")
                        f.write(f"\n")

                # Email Addresses
                f.write(f"## Email Addresses\n\n")
                emails = self.results.get('email_addresses', [])
                f.write(f"**Total Found:** {len(emails)}\n\n")
                for email in emails:
                    f.write(f"- {email}\n")
                f.write(f"\n")

                # Breach Data
                f.write(f"## Breach Database Results\n\n")
                breaches = self.results.get('breach_data', {})
                if breaches:
                    f.write(f"**Accounts with Breaches:** {len(breaches)}\n\n")
                    for email, breach_list in breaches.items():
                        f.write(f"### {email}\n")
                        for breach in breach_list:
                            f.write(f"- {breach}\n")
                        f.write(f"\n")
                else:
                    f.write(f"No compromised credentials found.\n\n")

                # GitHub Secret Scanning
                f.write(f"## GitHub Secret Scanning\n\n")
                github = self.results.get('github_secrets', {})

                if github.get('total_secrets_found', 0) > 0:
                    f.write(f"**Total Secrets Detected:** {github['total_secrets_found']}\n\n")

                    repos = github.get('repositories', [])
                    if repos:
                        f.write(f"### Repositories with Secrets ({len(repos)})\n\n")
                        for repo in repos:
                            f.write(f"#### {repo['repository']}\n")
                            f.write(f"- **File:** {repo['file_path']}\n")
                            f.write(f"- **URL:** {repo['html_url']}\n")
                            f.write(f"- **Secrets Found:**\n")
                            for secret in repo['secrets_found']:
                                f.write(f"  - {secret['type']}: {secret['count']} match(es)\n")
                            f.write(f"\n")

                    issues = github.get('issues', [])
                    if issues:
                        f.write(f"### Issues with Secrets ({len(issues)})\n\n")
                        for issue in issues:
                            f.write(f"- **{issue['title']}**\n")
                            f.write(f"  - URL: {issue['html_url']}\n")
                            f.write(f"  - State: {issue['state']}\n\n")
                else:
                    f.write(f"No secrets found in GitHub repositories.\n\n")

                # ASN Data
                f.write(f"## ASN Enumeration\n\n")
                asn_data = self.results.get('asn_data', {})

                asns = asn_data.get('asn_numbers', [])
                if asns:
                    f.write(f"**ASNs Discovered:** {len(asns)}\n\n")
                    for asn in asns:
                        f.write(f"### AS{asn['asn']}\n")
                        f.write(f"- **Owner:** {asn['owner']}\n")
                        if asn.get('country'):
                            f.write(f"- **Country:** {asn['country']}\n")
                        f.write(f"\n")

                ip_ranges = asn_data.get('ip_ranges', [])
                if ip_ranges:
                    f.write(f"### IP Ranges ({len(ip_ranges)})\n\n")
                    in_scope = [r for r in ip_ranges if r['in_scope']]
                    out_scope = [r for r in ip_ranges if not r['in_scope']]

                    if in_scope:
                        f.write(f"#### In Authorized Scope ({len(in_scope)})\n\n")
                        for r in in_scope:
                            f.write(f"- {r['prefix']} (AS{r['asn']})\n")
                        f.write(f"\n")

                    if out_scope:
                        f.write(f"#### Out of Scope - DO NOT TEST ({len(out_scope)})\n\n")
                        for r in out_scope:
                            f.write(f"- {r['prefix']} (AS{r['asn']})\n")
                        f.write(f"\n")

                # S3 Buckets
                f.write(f"## AWS S3 Buckets\n\n")
                s3 = self.results.get('s3_buckets', {})
                found_s3 = s3.get('found', [])

                if found_s3:
                    public_s3 = [b for b in found_s3 if b['status'] == 'Public Read']
                    private_s3 = [b for b in found_s3 if b['status'] == 'Private (Exists)']

                    f.write(f"**Buckets Found:** {len(found_s3)}\n")
                    f.write(f"**Public:** {len(public_s3)} | **Private:** {len(private_s3)}\n\n")

                    if public_s3:
                        f.write(f"### Public S3 Buckets\n\n")
                        for bucket in public_s3:
                            f.write(f"#### {bucket['bucket']}\n")
                            f.write(f"- **URL:** {bucket['url']}\n")
                            if bucket.get('file_count'):
                                f.write(f"- **Files:** {bucket['file_count']}\n")
                            f.write(f"\n")
                else:
                    f.write(f"No S3 buckets found.\n\n")

                # Azure Storage
                f.write(f"## Azure Storage\n\n")
                azure = self.results.get('azure_storage', {})
                found_azure = azure.get('found', [])

                if found_azure:
                    f.write(f"**Storage Accounts Found:** {len(found_azure)}\n\n")
                    for storage in found_azure:
                        f.write(f"### {storage.get('account', 'Unknown')}\n")
                        f.write(f"- **Container:** {storage.get('container', 'N/A')}\n")
                        f.write(f"- **Status:** {storage.get('status', 'N/A')}\n")
                        if storage.get('url'):
                            f.write(f"- **URL:** {storage['url']}\n")
                        f.write(f"\n")
                else:
                    f.write(f"No Azure storage accounts found.\n\n")

                # GCP Storage
                f.write(f"## GCP Storage\n\n")
                gcp = self.results.get('gcp_storage', {})
                found_gcp = gcp.get('found', [])

                if found_gcp:
                    f.write(f"**Buckets Found:** {len(found_gcp)}\n\n")
                    for bucket in found_gcp:
                        f.write(f"### {bucket.get('bucket', 'Unknown')}\n")
                        f.write(f"- **Status:** {bucket.get('status', 'N/A')}\n")
                        if bucket.get('url'):
                            f.write(f"- **URL:** {bucket['url']}\n")
                        f.write(f"\n")
                else:
                    f.write(f"No GCP storage buckets found.\n\n")

    def _generate_report_template(self, filepath: Path):
        """Generate report template with findings"""
        with open(filepath, 'w') as f:
            f.write(f"# Report Template Content - {self.client_name}\n\n")

            # Ownership Verification
            f.write("### Ownership Verification\n")
            whois = self.results.get('scope_validation', {}).get('whois', {})
            for ip_range, info in whois.items():
                org = info.get('org', 'Unknown')
                f.write(f"• {ip_range} - Confirmed owned by {org}\n")
            f.write("\n")

            # DNS Enumeration Section
            f.write("## Reconnaissance and OSINT\n\n")
            f.write("### Finding the External Footprint\n\n")

            dns = self.results.get('dns_enumeration', {})
            total = dns.get('total_discovered', 0)
            resolved = dns.get('resolved', {})

            f.write(f"DNS enumeration revealed {total} subdomains. This mapped out what was reachable from the internet.\n\n")

            if resolved:
                f.write("Key subdomains identified:\n")
                for subdomain in sorted(resolved.keys())[:10]:  # Top 10
                    ips = resolved[subdomain]
                    f.write(f"• {subdomain} ({', '.join(ips)})\n")
                f.write("\n")

            # Subdomain Takeover
            takeovers = self.results.get('subdomain_takeovers', [])
            if takeovers:
                f.write("### Subdomain Takeover Vulnerabilities\n\n")
                f.write(f"Analysis identified {len(takeovers)} subdomain(s) potentially vulnerable to takeover attacks:\n\n")
                for vuln in takeovers:
                    f.write(f"• {vuln['subdomain']} - Points to unclaimed {vuln['service']} resource\n")
                f.write("\n")
                f.write("Subdomain takeover allows attackers to host malicious content on the organization's domain, ")
                f.write("enabling phishing campaigns, malware distribution, or reputation damage. These subdomains should be ")
                f.write("either claimed by the organization or removed from DNS records.\n\n")

            # Technology Stack Section
            f.write("### Understanding the Technology Stack\n\n")
            tech = self.results.get('technology_stack', {})

            if tech:
                f.write("Public sources and SSL certificates revealed the organization uses:\n")
                all_tech = set()
                all_servers = set()

                for domain, info in tech.items():
                    if info.get('server'):
                        all_servers.add(info['server'])
                    if info.get('detected_technologies'):
                        all_tech.update(info['detected_technologies'])

                if all_servers:
                    f.write(f"• Web Servers: {', '.join(all_servers)}\n")
                if all_tech:
                    f.write(f"• Technologies: {', '.join(all_tech)}\n")
                f.write("\n")

            # LinkedIn Intelligence
            f.write("### Employee Enumeration via LinkedIn\n\n")
            linkedin = self.results.get('linkedin_intel', {})

            google_results = linkedin.get('google_dork_results', [])
            inferred = linkedin.get('inferred_employees', [])

            total_employees = len(google_results) + len(inferred)

            if total_employees > 0:
                f.write(f"LinkedIn reconnaissance identified {total_employees} employee accounts associated with the organization.\n\n")

                if linkedin.get('email_patterns'):
                    pattern = linkedin['email_patterns'].get('likely_pattern', 'Unknown')
                    confidence = linkedin['email_patterns'].get('confidence', 0)
                    f.write(f"Email pattern analysis suggests the organization uses: {pattern} ({confidence:.0f}% confidence)\n\n")

                f.write("This intelligence enables targeted phishing campaigns and password spraying attacks against valid accounts. ")
                f.write("The identified email pattern can be used to generate username lists for authentication testing.\n\n")
            else:
                f.write("Limited employee information was gathered through public LinkedIn sources.\n\n")

            # Email Addresses Section
            f.write("### Identifying Valid User Accounts\n\n")
            emails = self.results.get('email_addresses', [])

            if emails:
                f.write(f"Public sources revealed {len(emails)} employee email addresses following the format ")

                # Infer email format
                if emails:
                    example = emails[0]
                    local_part = example.split('@')[0]
                    if '.' in local_part:
                        f.write("firstname.lastname@domain.com\n")
                    else:
                        f.write("firstnamelastname@domain.com\n")

                f.write("\nSample email addresses identified:\n")
                for email in emails[:5]:  # First 5
                    f.write(f"• {email}\n")
                f.write("\n")

            # Breach Data Section
            f.write("### Searching for Compromised Credentials\n\n")
            breaches = self.results.get('breach_data', {})

            if breaches:
                f.write(f"Breach databases were checked for client email addresses. {len(breaches)} accounts were found with exposed passwords:\n\n")
                for email, breach_list in list(breaches.items())[:5]:  # First 5
                    f.write(f"• {email} - Found in: {', '.join(breach_list[:3])}\n")
                f.write("\n")
                f.write("These credentials became immediate testing priorities as users frequently reuse passwords across work and personal accounts.\n\n")
            else:
                f.write("No exposed credentials were found in available breach databases.\n\n")

            # GitHub Secret Scanning
            f.write("### GitHub Secret Exposure\n\n")
            github = self.results.get('github_secrets', {})

            if github.get('total_secrets_found', 0) > 0:
                repos = github.get('repositories', [])
                issues = github.get('issues', [])
                commits = github.get('commits', [])

                f.write(f"GitHub scanning identified {github['total_secrets_found']} potential secrets across {len(repos)} repositories, ")
                f.write(f"{len(issues)} issues, and {len(commits)} commits.\n\n")

                if repos:
                    f.write("Repositories containing sensitive data:\n")
                    for repo in repos[:5]:
                        f.write(f"• {repo['repository']}/{repo['file_path']}\n")
                    f.write("\n")

                f.write("Exposed secrets in public repositories represent critical security vulnerabilities, potentially providing ")
                f.write("direct access to infrastructure, databases, and third-party services.\n\n")
            else:
                f.write("No secrets were discovered in public GitHub repositories associated with the organization.\n\n")

            # ASN Enumeration
            f.write("### Network Infrastructure (ASN Enumeration)\n\n")
            asn_data = self.results.get('asn_data', {})

            asns = asn_data.get('asn_numbers', [])
            ip_ranges = asn_data.get('ip_ranges', [])

            if asns:
                f.write(f"ASN enumeration identified {len(asns)} autonomous system(s) associated with the organization:\n\n")
                for asn in asns:
                    f.write(f"• AS{asn['asn']} - {asn['owner']}\n")
                f.write("\n")

            if ip_ranges:
                in_scope = [r for r in ip_ranges if r['in_scope']]
                out_scope = [r for r in ip_ranges if not r['in_scope']]

                f.write(f"Total IP ranges discovered: {len(ip_ranges)}\n")
                f.write(f"• Ranges within authorized scope: {len(in_scope)}\n")
                f.write(f"• Ranges outside authorized scope: {len(out_scope)}\n\n")

                if out_scope:
                    f.write("Additional IP ranges were identified that belong to the organization but fall outside the authorized testing scope. ")
                    f.write("These ranges were documented but not tested.\n\n")

            # Cloud Storage Enumeration Section
            f.write("### Cloud Storage Enumeration\n\n")

            s3 = self.results.get('s3_buckets', {})
            azure = self.results.get('azure_storage', {})
            gcp = self.results.get('gcp_storage', {})

            found_s3 = s3.get('found', [])
            found_azure = azure.get('found', [])
            found_gcp = gcp.get('found', [])

            total_cloud = len(found_s3) + len(found_azure) + len(found_gcp)

            if total_cloud > 0:
                public_s3 = [b for b in found_s3 if b['status'] == 'Public Read']
                public_azure = [s for s in found_azure if s['status'] == 'Public Read']
                public_gcp = [b for b in found_gcp if b['status'] == 'Public Read']
                total_public = len(public_s3) + len(public_azure) + len(public_gcp)

                f.write(f"Cloud storage enumeration discovered {total_cloud} storage resource(s):\n")
                f.write(f"• AWS S3: {len(found_s3)} ({len(public_s3)} public)\n")
                f.write(f"• Azure Storage: {len(found_azure)} ({len(public_azure)} public)\n")
                f.write(f"• GCP Storage: {len(found_gcp)} ({len(public_gcp)} public)\n\n")

                if total_public > 0:
                    f.write(f"**{total_public} publicly accessible cloud storage resource(s) identified:**\n\n")

                    for bucket in public_s3:
                        f.write(f"• AWS S3: {bucket['bucket']}\n")
                        f.write(f"  URL: {bucket['url']}\n")
                        if bucket.get('file_count'):
                            f.write(f"  Contents: {bucket['file_count']} files\n")
                        f.write("\n")

                    for storage in public_azure:
                        f.write(f"• Azure: {storage['account']}/{storage['container']}\n")
                        f.write(f"  URL: {storage['url']}\n")
                        if storage.get('file_count'):
                            f.write(f"  Contents: {storage['file_count']} files\n")
                        f.write("\n")

                    for bucket in public_gcp:
                        f.write(f"• GCP: {bucket['bucket']}\n")
                        f.write(f"  URL: {bucket['url']}\n")
                        if bucket.get('file_count'):
                            f.write(f"  Contents: {bucket['file_count']} files\n")
                        f.write("\n")

                    f.write("Public cloud storage represents a critical data exposure risk. Unauthenticated access allows ")
                    f.write("any internet user to view, and potentially download, sensitive organizational data.\n\n")
                else:
                    f.write("While cloud storage resources were discovered, all were properly configured with private access controls.\n\n")
            else:
                f.write("No cloud storage resources were discovered during enumeration.\n\n")

            # Network Enumeration Section
            f.write("## Enumeration and Mapping\n\n")
            scan = self.results.get('network_scan', {})

            if scan:
                total_hosts = len(scan)
                total_ports = sum(len(ports) for ports in scan.values())

                f.write(f"Network scanning revealed {total_hosts} live hosts with {total_ports} open ports.\n\n")

                # Categorize services
                interesting_services = []
                for host, ports in scan.items():
                    for port_num, port_info in ports.items():
                        service = port_info.get('service', 'unknown')
                        if any(keyword in service.lower() for keyword in ['vpn', 'ssh', 'rdp', 'http', 'ftp', 'smtp']):
                            interesting_services.append(f"{host}:{port_num} ({service})")

                if interesting_services:
                    f.write("Most promising targets for further investigation:\n")
                    for service in interesting_services[:10]:  # Top 10
                        f.write(f"• {service}\n")
                    f.write("\n")

    def run_all(self):
            """Run all reconnaissance modules"""
            self.print_banner()

            # Prompt for API keys at startup
            self.prompt_for_api_keys()

            try:
                # Phase 1: Basic reconnaissance
                self.scope_validation()
                self.dns_enumeration()
                self.technology_stack_identification()

                # Phase 2: OSINT and intelligence gathering
                # LinkedIn enumeration - runs if cookies were provided
                if self.config.get('linkedin_cookies'):
                    self.linkedin_enumeration()
                else:
                    self.print_info("Skipping LinkedIn enumeration (no cookies provided)")

                self.email_harvesting()

                if not self.args.skip_breach_check:
                    self.breach_database_check()

                # Phase 3: Advanced enumeration
                if not self.args.skip_github:
                    self.github_secret_scanning()

                if not self.args.skip_asn:
                    self.asn_enumeration()

                if not self.args.skip_subdomain_takeover:
                    self.subdomain_takeover_detection()

                # Phase 4: Cloud storage enumeration
                if not self.args.skip_s3:
                    self.s3_bucket_enumeration()

                if not self.args.skip_azure:
                    self.azure_storage_enumeration()

                if not self.args.skip_gcp:
                    self.gcp_storage_enumeration()

                # Phase 5: Generate reports
                self.generate_report()

                self.print_section("RECONNAISSANCE COMPLETE")
                self.print_success(f"All results saved to: {self.output_dir}")

            except KeyboardInterrupt:
                self.print_warning("\nReconnaissance interrupted by user")
                self.print_info("Partial results may be available in output directory")
            except Exception as e:
                self.print_error(f"Error during reconnaissance: {e}")
                import traceback
                traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(
        description='Penetration Testing Reconnaissance Automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Basic scan:
    python3 quick_recon.py -d example.com -i 192.168.1.0/24 -c "Acme Corp"

  Multiple IP ranges:
    python3 quick_recon.py -d example.com -i 10.0.0.0/24 172.16.0.0/16 -c "Acme Corp"

  IP ranges from file:
    python3 quick_recon.py -d example.com -f targets.txt -c "Acme Corp"

  Combine file and command line:
    python3 quick_recon.py -d example.com -f targets.txt -i 10.0.0.0/24 -c "Acme Corp"

  Custom output directory:
    python3 quick_recon.py -d example.com -i 192.168.1.0/24 -o /tmp/recon -c "Acme Corp"

  Skip specific modules:
    python3 quick_recon.py -d example.com -i 192.168.1.0/24 -c "Acme Corp" --skip-s3 --skip-scan

  Test LinkedIn enumeration only:
    python3 quick_recon.py -d example.com -c "Acme Corp" --linkedin-only

  Skip all OSINT modules:
    python3 quick_recon.py -d example.com -i 192.168.1.0/24 -c "Acme Corp" --skip-osint
        '''
    )

    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-i', '--ip-ranges', nargs='+', help='In-scope IP ranges (e.g., 192.168.1.0/24)')
    parser.add_argument('-f', '--file', help='File containing IP ranges (one CIDR per line)')
    parser.add_argument('-c', '--client', required=True, help='Client name for reporting')
    parser.add_argument('-o', '--output', help='Output directory (default: ./<client_name>_recon)')

    # Module control flags
    parser.add_argument('--skip-breach-check', action='store_true', help='Skip breach database checking')
    parser.add_argument('--skip-scan', action='store_true', help='Skip network scanning')
    parser.add_argument('--skip-s3', action='store_true', help='Skip S3 bucket enumeration')
    parser.add_argument('--skip-azure', action='store_true', help='Skip Azure storage enumeration')
    parser.add_argument('--skip-gcp', action='store_true', help='Skip GCP storage enumeration')
    parser.add_argument('--skip-github', action='store_true', help='Skip GitHub secret scanning')
    parser.add_argument('--skip-asn', action='store_true', help='Skip ASN enumeration')
    parser.add_argument('--skip-subdomain-takeover', action='store_true', help='Skip subdomain takeover detection')
    parser.add_argument('--skip-osint', action='store_true', help='Skip all OSINT modules (GitHub, LinkedIn)')
    parser.add_argument('--linkedin-max-results', type=int, default=100, help='Maximum LinkedIn employee results to fetch (default: 100)')

    # Testing flags
    parser.add_argument('--linkedin-only', action='store_true', help='Run only LinkedIn enumeration (for testing)')

    args = parser.parse_args()

    # Apply skip-osint flag
    if args.skip_osint:
        args.skip_github = True

    # Set output directory based on client name if not specified
    if not args.output:
        # Sanitize client name for use as directory name
        safe_client_name = re.sub(r'[^\w\s-]', '', args.client).strip().replace(' ', '_')
        args.output = f"./{safe_client_name}_recon"

    # Check for LinkedIn-only mode BEFORE processing IP ranges
    if args.linkedin_only:
        print(f"{Colors.OKCYAN}[i] Running in LinkedIn-only test mode{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[i] Output directory: {args.output}{Colors.ENDC}")

        # Create minimal recon instance
        recon = ReconAutomation(
            domain=args.domain,
            ip_ranges=[],  # Not needed for LinkedIn-only
            output_dir=args.output,
            client_name=args.client
        )

        # Run LinkedIn-only test
        recon.run_linkedin_only()
        sys.exit(0)

    # Parse IP ranges from command line and/or file (only for non-LinkedIn-only mode)
    ip_ranges = []

    # Add command line IP ranges
    if args.ip_ranges:
        ip_ranges.extend(args.ip_ranges)

    # Add IP ranges from file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        ip_ranges.append(line)
            print(f"{Colors.OKGREEN}[+] Loaded {len([r for r in ip_ranges if r not in (args.ip_ranges or [])])} IP ranges from {args.file}{Colors.ENDC}")
        except FileNotFoundError:
            print(f"{Colors.FAIL}[-] Error: File '{args.file}' not found{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error reading file: {e}{Colors.ENDC}")
            sys.exit(1)

    # Allow OSINT-only mode if no IP ranges provided
    if not ip_ranges:
        print(f"{Colors.WARNING}[!] No IP ranges specified - running in OSINT-only mode{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Network scanning and IP-based validation will be skipped{Colors.ENDC}")

    # Remove duplicates while preserving order
    seen = set()
    unique_ranges = []
    for ip_range in ip_ranges:
        if ip_range not in seen:
            seen.add(ip_range)
            unique_ranges.append(ip_range)

    if len(ip_ranges) != len(unique_ranges):
        print(f"{Colors.WARNING}[!] Removed {len(ip_ranges) - len(unique_ranges)} duplicate IP range(s){Colors.ENDC}")

    # Show output directory
    print(f"{Colors.OKCYAN}[i] Output directory: {args.output}{Colors.ENDC}")

    # Create recon automation instance
    recon = ReconAutomation(
        domain=args.domain,
        ip_ranges=unique_ranges,
        output_dir=args.output,
        client_name=args.client
    )

    # Store args reference for run_all method
    recon.args = args

    # Run all reconnaissance
    recon.run_all()

if __name__ == '__main__':
    main()
