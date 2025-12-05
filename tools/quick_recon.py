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
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
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
        """Multi-method LinkedIn intelligence gathering"""
        self.print_section("LinkedIn Information Gathering")

        linkedin_intel = {
            'google_dork_results': [],
            'theharvester_names': [],
            'inferred_employees': [],
            'search_urls': [],
            'email_patterns': {}
        }

        company_name = self.domain.split('.')[0].title()

        # Method 1: Google Dorking LinkedIn
        self.print_info("Performing Google dorks on LinkedIn...")
        google_dork_patterns = [
            f'site:linkedin.com/in "{company_name}"',
            f'site:linkedin.com/in "{company_name}" "security"',
            f'site:linkedin.com/in "{company_name}" "engineer"',
            f'site:linkedin.com/in "{company_name}" "developer"',
            f'site:linkedin.com/in "{company_name}" "admin"',
            f'site:linkedin.com/in "{company_name}" "manager"'
        ]

        for dork in google_dork_patterns:
            try:
                # Use Google search (with caution for rate limiting)
                search_url = f"https://www.google.com/search?q={dork.replace(' ', '+')}&num=10"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }

                response = self.session.get(search_url, headers=headers, timeout=10)

                if response.status_code == 200:
                    # Extract LinkedIn profile URLs
                    linkedin_urls = re.findall(r'https://[a-z]{2,3}\.linkedin\.com/in/([a-zA-Z0-9-]+)', response.text)

                    for profile_slug in set(linkedin_urls):
                        profile_info = {
                            'profile_url': f"https://www.linkedin.com/in/{profile_slug}",
                            'profile_slug': profile_slug,
                            'source': 'google_dork'
                        }

                        # Try to extract name from slug
                        name_parts = profile_slug.replace('-', ' ').title()
                        if len(name_parts.split()) >= 2:
                            profile_info['inferred_name'] = name_parts

                        linkedin_intel['google_dork_results'].append(profile_info)
                        self.print_success(f"Found profile: {profile_slug}")

                    time.sleep(3)  # Rate limiting for Google
                else:
                    self.print_warning(f"Google search returned status {response.status_code}")

            except Exception as e:
                self.print_error(f"Error with Google dork: {e}")

        # Method 2: Parse theHarvester results for names
        self.print_info("Extracting employee information from theHarvester results...")
        emails = self.results.get('email_addresses', [])

        if emails:
            for email in emails:
                # Extract name from email
                local_part = email.split('@')[0]

                # Common patterns: firstname.lastname, firstnamelastname, first.last
                if '.' in local_part:
                    parts = local_part.split('.')
                    if len(parts) == 2:
                        first_name = parts[0].title()
                        last_name = parts[1].title()
                        full_name = f"{first_name} {last_name}"

                        linkedin_intel['inferred_employees'].append({
                            'name': full_name,
                            'email': email,
                            'first_name': first_name,
                            'last_name': last_name,
                            'source': 'email_parsing'
                        })

                        self.print_success(f"Inferred employee: {full_name}")

        # Method 3: Generate manual search URLs
        self.print_info("Generating LinkedIn search URLs for manual review...")

        search_urls = [
            f"https://www.linkedin.com/search/results/people/?keywords={company_name.replace(' ', '%20')}",
            f"https://www.linkedin.com/search/results/people/?keywords={company_name.replace(' ', '%20')}%20security",
            f"https://www.linkedin.com/search/results/people/?keywords={company_name.replace(' ', '%20')}%20engineer",
            f"https://www.linkedin.com/search/results/people/?keywords={company_name.replace(' ', '%20')}%20IT",
            f"https://www.linkedin.com/search/results/people/?keywords={company_name.replace(' ', '%20')}%20admin",
            f"https://www.linkedin.com/search/results/people/?keywords={self.domain.replace('.', '%20')}",
        ]

        linkedin_intel['search_urls'] = search_urls

        self.print_info("\nManual LinkedIn Search URLs:")
        for url in search_urls:
            self.print_info(f"  {url}")

        # Method 4: Email pattern inference
        self.print_info("\nInferring email patterns from discovered addresses...")

        if len(emails) >= 2:
            patterns = {
                'firstname.lastname@domain': 0,
                'firstnamelastname@domain': 0,
                'first.last@domain': 0,
                'flastname@domain': 0,
                'firstnamel@domain': 0
            }

            for email in emails:
                local = email.split('@')[0]

                if '.' in local and len(local.split('.')) == 2:
                    patterns['firstname.lastname@domain'] += 1
                elif '.' not in local and len(local) > 3:
                    patterns['firstnamelastname@domain'] += 1

            # Determine most likely pattern
            likely_pattern = max(patterns, key=patterns.get)
            confidence = patterns[likely_pattern] / len(emails) * 100 if emails else 0

            linkedin_intel['email_patterns'] = {
                'likely_pattern': likely_pattern,
                'confidence': confidence,
                'sample_emails': emails[:5]
            }

            self.print_success(f"Inferred email pattern: {likely_pattern} ({confidence:.0f}% confidence)")
            self.print_info("This pattern can be used to generate username lists for authentication testing")

        # Store results
        self.results['linkedin_intel'] = linkedin_intel

        # Summary
        total_profiles = len(linkedin_intel['google_dork_results'])
        total_inferred = len(linkedin_intel['inferred_employees'])

        self.print_info(f"\nLinkedIn Intelligence Summary:")
        self.print_info(f"  Profiles found via Google: {total_profiles}")
        self.print_info(f"  Employees inferred from emails: {total_inferred}")
        self.print_info(f"  Manual search URLs generated: {len(linkedin_intel['search_urls'])}")

        if linkedin_intel.get('email_patterns'):
            self.print_info(f"  Email pattern identified: {linkedin_intel['email_patterns']['likely_pattern']}")

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

                        time.sleep(1)  # Rate limiting

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
            'resolved': resolved,
            'unresolved': list(subdomains - set(resolved.keys()))
        }

        self.print_info(f"Total unique subdomains discovered: {len(subdomains)}")
        self.print_info(f"Successfully resolved: {len(resolved)}")

    def subdomain_takeover_detection(self):
            """Check for subdomain takeover vulnerabilities"""
            self.print_section("SUBDOMAIN TAKEOVER DETECTION")

            # Fingerprints for various services that can be taken over
            takeover_fingerprints = {
                'github': {
                    'cname': ['github.io', 'github.map.fastly.net'],
                    'response': ['There isn\'t a GitHub Pages site here', 'For root URLs (like http://example.com/) you must provide an index.html file'],
                    'service': 'GitHub Pages'
                },
                'aws_s3': {
                    'cname': ['s3.amazonaws.com', 's3-website', 's3.dualstack'],
                    'response': ['NoSuchBucket', 'The specified bucket does not exist'],
                    'service': 'AWS S3'
                },
                'azure': {
                    'cname': ['azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com', 'trafficmanager.net', 'blob.core.windows.net'],
                    'response': ['404 Web Site not found', 'Error 404', 'The resource you are looking for has been removed'],
                    'service': 'Microsoft Azure'
                },
                'bitbucket': {
                    'cname': ['bitbucket.io'],
                    'response': ['Repository not found'],
                    'service': 'Bitbucket'
                },
                'google': {
                    'cname': ['appspot.com', 'withgoogle.com', 'withyoutube.com'],
                    'response': ['The requested URL was not found on this server', 'Error 404'],
                    'service': 'Google Cloud'
                },
                'wordpress': {
                    'cname': ['wordpress.com'],
                    'response': ['Do you want to register'],
                    'service': 'WordPress.com'
                },
                'cloudfront': {
                    'cname': ['cloudfront.net'],
                    'response': ['Bad request', 'ERROR: The request could not be satisfied'],
                    'service': 'AWS CloudFront'
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
                        # Handle both old and new dnspython versions
                        resolver = dns.resolver.Resolver()
                        try:
                            # Try new API (dnspython 2.0+)
                            answers = resolver.resolve(subdomain, 'CNAME')
                        except AttributeError:
                            # Fall back to old API (dnspython 1.x)
                            answers = resolver.query(subdomain, 'CNAME')

                        for rdata in answers:
                            cname_records.append(str(rdata.target).rstrip('.'))
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        # No CNAME, check A record behavior
                        pass
                    except Exception as e:
                        self.print_error(f"DNS error for {subdomain}: {e}")
                        continue

                    # Check if CNAME points to a vulnerable service
                    vulnerable = False
                    service_name = None
                    fingerprint_matched = None

                    for cname in cname_records:
                        for service, fingerprint in takeover_fingerprints.items():
                            # Check if CNAME matches known patterns
                            if any(pattern in cname.lower() for pattern in fingerprint['cname']):
                                # CNAME points to a potentially vulnerable service
                                # Now check HTTP response
                                http_vulnerable = self._check_http_takeover(subdomain, fingerprint['response'])

                                if http_vulnerable:
                                    vulnerable = True
                                    service_name = fingerprint['service']
                                    fingerprint_matched = service
                                    break

                        if vulnerable:
                            break

                    # Even without CNAME, check HTTP responses for known patterns
                    if not vulnerable and not cname_records:
                        for service, fingerprint in takeover_fingerprints.items():
                            http_vulnerable = self._check_http_takeover(subdomain, fingerprint['response'])
                            if http_vulnerable:
                                vulnerable = True
                                service_name = fingerprint['service']
                                fingerprint_matched = service
                                break

                    if vulnerable:
                        vuln_info = {
                            'subdomain': subdomain,
                            'cname': cname_records,
                            'service': service_name,
                            'fingerprint': fingerprint_matched,
                            'ips': ips
                        }
                        vulnerable_subdomains.append(vuln_info)

                        self.print_warning(f"POTENTIAL TAKEOVER: {subdomain}")
                        self.print_info(f"  Service: {service_name}")
                        if cname_records:
                            self.print_info(f"  CNAME: {', '.join(cname_records)}")
                        self.print_info(f"  Recommendation: Verify if service account exists and claim if vulnerable")

                    time.sleep(0.5)  # Rate limiting

                except Exception as e:
                    self.print_error(f"Error checking {subdomain}: {e}")

            # Store results
            self.results['subdomain_takeovers'] = vulnerable_subdomains

            # Summary
            self.print_info(f"\nSubdomain Takeover Detection Summary:")
            self.print_info(f"  Subdomains checked: {len(resolved_subdomains)}")
            self.print_info(f"  Potentially vulnerable: {len(vulnerable_subdomains)}")

            if vulnerable_subdomains:
                self.print_warning(f"\n[!] Found {len(vulnerable_subdomains)} potential subdomain takeover(s)!")
                self.print_warning("Manual verification required - check if you can claim these services:")
                for vuln in vulnerable_subdomains:
                    self.print_warning(f"  - {vuln['subdomain']} ({vuln['service']})")

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
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle multiple domains in one cert
                    for domain in name.split('\n'):
                        domain = domain.strip()
                        if domain and '*' not in domain:
                            domains.append(domain)
        except Exception as e:
            self.print_error(f"CT log check failed: {e}")

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

        # Check main domain and a few key subdomains
        targets = [self.domain]
        for subdomain in list(resolved_domains.keys())[:5]:  # Limit to first 5
            targets.append(subdomain)

        for target in targets:
            self.print_info(f"Analyzing {target}...")
            tech_info = self._identify_technologies(target)
            if tech_info:
                tech_stack[target] = tech_info

                # Print findings
                if tech_info.get('server'):
                    self.print_success(f"Server: {tech_info['server']}")
                if tech_info.get('headers'):
                    for key, value in tech_info['headers'].items():
                        self.print_info(f"  {key}: {value}")

        self.results['technology_stack'] = tech_stack

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

        # Store results
        self.results['email_addresses'] = sorted(list(emails))

        self.print_success(f"Total unique email addresses found: {len(emails)}")
        for email in sorted(emails):
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

            # Generate bucket name variations from domain
            bucket_candidates = set()

            # Basic domain variations
            bucket_candidates.add(self.domain)
            bucket_candidates.add(self.domain.replace('.', '-'))
            bucket_candidates.add(self.domain.replace('.', ''))

            # Add company name variations
            company_name = self.domain.split('.')[0]
            bucket_candidates.add(company_name)

            # Add variations from discovered subdomains
            resolved = self.results.get('dns_enumeration', {}).get('resolved', {})
            for subdomain in list(resolved.keys())[:20]:  # Limit to top 20
                # Extract subdomain part
                if subdomain.endswith(self.domain):
                    sub_part = subdomain.replace(f".{self.domain}", "").replace(f"{self.domain}", "")
                    if sub_part and '.' not in sub_part:
                        bucket_candidates.add(sub_part)
                        bucket_candidates.add(f"{sub_part}-{company_name}")
                        bucket_candidates.add(f"{company_name}-{sub_part}")

            # Add common prefixes/suffixes
            common_affixes = ['backup', 'backups', 'data', 'files', 'assets', 'static',
                            'uploads', 'images', 'docs', 'logs', 'dev', 'prod', 'staging']

            base_names = [company_name, self.domain.replace('.', '-')]
            for base in base_names:
                for affix in common_affixes:
                    bucket_candidates.add(f"{base}-{affix}")
                    bucket_candidates.add(f"{affix}-{base}")

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

            # Generate Azure storage account name variations
            storage_candidates = set()

            # Basic domain variations
            company_name = self.domain.split('.')[0]
            storage_candidates.add(company_name)
            storage_candidates.add(self.domain.replace('.', ''))
            storage_candidates.add(self.domain.replace('.', '-'))

            # Add variations from discovered subdomains
            resolved = self.results.get('dns_enumeration', {}).get('resolved', {})
            for subdomain in list(resolved.keys())[:20]:
                if subdomain.endswith(self.domain):
                    sub_part = subdomain.replace(f".{self.domain}", "").replace(f"{self.domain}", "")
                    if sub_part and '.' not in sub_part:
                        storage_candidates.add(sub_part.replace('-', '').replace('_', ''))
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

            # Generate GCP bucket name variations
            bucket_candidates = set()

            # Basic domain variations
            company_name = self.domain.split('.')[0]
            bucket_candidates.add(self.domain)
            bucket_candidates.add(self.domain.replace('.', '-'))
            bucket_candidates.add(self.domain.replace('.', '_'))
            bucket_candidates.add(self.domain.replace('.', ''))
            bucket_candidates.add(company_name)

            # Add variations from discovered subdomains
            resolved = self.results.get('dns_enumeration', {}).get('resolved', {})
            for subdomain in list(resolved.keys())[:20]:
                if subdomain.endswith(self.domain):
                    sub_part = subdomain.replace(f".{self.domain}", "").replace(f"{self.domain}", "")
                    if sub_part and '.' not in sub_part:
                        bucket_candidates.add(sub_part)
                        bucket_candidates.add(f"{sub_part}-{company_name}")
                        bucket_candidates.add(f"{company_name}-{sub_part}")
                        bucket_candidates.add(sub_part.replace('-', '_'))

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

        if not self.results.get('email_addresses'):
            self.print_warning("No email addresses to check. Run email harvesting first.")
            return

        breach_results = {}

        self.print_info("Checking Have I Been Pwned (HIBP) API...")

        for email in self.results['email_addresses'][:10]:  # Limit to first 10 to avoid rate limits
            breaches = self._check_hibp(email)
            if breaches:
                breach_results[email] = breaches
                self.print_warning(f"{email}: Found in {len(breaches)} breach(es)")
            else:
                self.print_success(f"{email}: No breaches found")

        self.results['breach_data'] = breach_results

        if breach_results:
            self.print_warning(f"Total accounts with breaches: {len(breach_results)}")
        else:
            self.print_success("No compromised credentials found in breach databases")

    def _check_hibp(self, email: str) -> List[str]:
        """Check email against Have I Been Pwned API"""
        breaches = []
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                'User-Agent': 'Penetration-Testing-Reconnaissance-Tool'
            }
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                breaches = [breach['Name'] for breach in data]
            elif response.status_code == 404:
                # No breaches found
                pass
            else:
                self.print_warning(f"HIBP API returned status {response.status_code}")
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

            resolved = dns.get('resolved', {})
            if resolved:
                f.write(f"### Resolved Subdomains ({len(resolved)})\n\n")
                for subdomain, ips in sorted(resolved.items()):
                    f.write(f"- `{subdomain}` → {', '.join(ips)}\n")
                f.write(f"\n")

            # Subdomain Takeover
            f.write(f"## Subdomain Takeover Vulnerabilities\n\n")
            takeovers = self.results.get('subdomain_takeovers', [])
            if takeovers:
                f.write(f"**Potentially Vulnerable Subdomains:** {len(takeovers)}\n\n")
                for vuln in takeovers:
                    f.write(f"### {vuln['subdomain']}\n")
                    f.write(f"- **Service:** {vuln['service']}\n")
                    if vuln.get('cname'):
                        f.write(f"- **CNAME:** {', '.join(vuln['cname'])}\n")
                    f.write(f"- **Risk:** Subdomain may be claimable by attacker\n\n")
            else:
                f.write(f"No subdomain takeover vulnerabilities detected.\n\n")

            # Technology Stack
            f.write(f"## Technology Stack\n\n")
            tech = self.results.get('technology_stack', {})
            for domain, info in tech.items():
                f.write(f"### {domain}\n")
                if info.get('server'):
                    f.write(f"- **Server:** {info['server']}\n")
                if info.get('powered_by'):
                    f.write(f"- **Powered By:** {info['powered_by']}\n")
                if info.get('detected_technologies'):
                    f.write(f"- **Technologies:** {', '.join(info['detected_technologies'])}\n")
                f.write(f"\n")

            # LinkedIn Intelligence
            f.write(f"## LinkedIn Intelligence\n\n")
            linkedin = self.results.get('linkedin_intel', {})

            google_results = linkedin.get('google_dork_results', [])
            inferred = linkedin.get('inferred_employees', [])

            f.write(f"**Profiles Found (Google):** {len(google_results)}\n")
            f.write(f"**Employees Inferred:** {len(inferred)}\n\n")

            if linkedin.get('email_patterns'):
                pattern = linkedin['email_patterns'].get('likely_pattern', 'Unknown')
                confidence = linkedin['email_patterns'].get('confidence', 0)
                f.write(f"**Email Pattern:** {pattern} ({confidence:.0f}% confidence)\n\n")

            if inferred:
                f.write(f"### Inferred Employees (Sample)\n\n")
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
                public_azure = [s for s in found_azure if s['status'] == 'Public Read']
                private_azure = [s for s in found_azure if s['status'] == 'Private (Exists)']

                f.write(f"**Storage Accounts Found:** {len(found_azure)}\n")
                f.write(f"**Public:** {len(public_azure)} | **Private:** {len(private_azure)}\n\n")

                if public_azure:
                    f.write(f"### Public Azure Storage\n\n")
                    for storage in public_azure:
                        f.write(f"#### {storage['account']}\n")
                        f.write(f"- **Container:** {storage['container']}\n")
                        f.write(f"- **URL:** {storage['url']}\n")
                        if storage.get('file_count'):
                            f.write(f"- **Files:** {storage['file_count']}\n")
                        f.write(f"\n")
            else:
                f.write(f"No Azure storage accounts found.\n\n")

            # GCP Storage
            f.write(f"## GCP Storage\n\n")
            gcp = self.results.get('gcp_storage', {})
            found_gcp = gcp.get('found', [])

            if found_gcp:
                public_gcp = [b for b in found_gcp if b['status'] == 'Public Read']
                private_gcp = [b for b in found_gcp if b['status'] == 'Private (Exists)']

                f.write(f"**Buckets Found:** {len(found_gcp)}\n")
                f.write(f"**Public:** {len(public_gcp)} | **Private:** {len(private_gcp)}\n\n")

                if public_gcp:
                    f.write(f"### Public GCP Buckets\n\n")
                    for bucket in public_gcp:
                        f.write(f"#### {bucket['bucket']}\n")
                        f.write(f"- **URL:** {bucket['url']}\n")
                        if bucket.get('file_count'):
                            f.write(f"- **Files:** {bucket['file_count']}\n")
                        f.write(f"\n")
            else:
                f.write(f"No GCP buckets found.\n\n")

            # Network Scan
            f.write(f"## Network Enumeration\n\n")
            scan = self.results.get('network_scan', {})
            f.write(f"**Hosts with Open Ports:** {len(scan)}\n\n")

            for host, ports in scan.items():
                f.write(f"### {host}\n")
                f.write(f"**Open Ports:** {len(ports)}\n\n")
                f.write(f"| Port | Service | Version |\n")
                f.write(f"|------|---------|--------|\n")
                for port_num, port_info in sorted(ports.items()):
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', '')
                    f.write(f"| {port_num} | {service} | {version} |\n")
                f.write(f"\n")

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
            if not self.args.skip_linkedin:
                self.linkedin_enumeration()

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

            # Phase 5: Network enumeration (last due to time)
            if not self.args.skip_scan:
                self.network_enumeration()

            # Generate reports
            self.generate_report()

            self.print_section("RECONNAISSANCE COMPLETE")
            self.print_success("All modules completed successfully!")
            self.print_info(f"Results saved to: {self.output_dir}")

        except KeyboardInterrupt:
            self.print_warning("\nReconnaissance interrupted by user")
            self.generate_report()
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
    python3 pentest_recon.py -d example.com -i 192.168.1.0/24 -c "Acme Corp"

  Multiple IP ranges:
    python3 pentest_recon.py -d example.com -i 10.0.0.0/24 172.16.0.0/16 -c "Acme Corp"

  IP ranges from file:
    python3 pentest_recon.py -d example.com -f targets.txt -c "Acme Corp"

  Combine file and command line:
    python3 pentest_recon.py -d example.com -f targets.txt -i 10.0.0.0/24 -c "Acme Corp"

  Custom output directory:
    python3 pentest_recon.py -d example.com -i 192.168.1.0/24 -o /tmp/recon -c "Acme Corp"

  Skip specific modules:
    python3 pentest_recon.py -d example.com -i 192.168.1.0/24 -c "Acme Corp" --skip-s3 --skip-scan

  Skip all OSINT modules:
    python3 pentest_recon.py -d example.com -i 192.168.1.0/24 -c "Acme Corp" --skip-osint
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
    parser.add_argument('--skip-linkedin', action='store_true', help='Skip LinkedIn enumeration')
    parser.add_argument('--skip-asn', action='store_true', help='Skip ASN enumeration')
    parser.add_argument('--skip-subdomain-takeover', action='store_true', help='Skip subdomain takeover detection')
    parser.add_argument('--skip-osint', action='store_true', help='Skip all OSINT modules (GitHub, LinkedIn)')

    args = parser.parse_args()

    # Apply skip-osint flag
    if args.skip_osint:
        args.skip_github = True
        args.skip_linkedin = True

    # Set output directory based on client name if not specified
    if not args.output:
        # Sanitize client name for use as directory name
        safe_client_name = re.sub(r'[^\w\s-]', '', args.client).strip().replace(' ', '_')
        args.output = f"./{safe_client_name}_recon"

    # Parse IP ranges from command line and/or file
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
