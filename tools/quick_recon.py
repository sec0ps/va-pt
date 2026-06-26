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
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
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
import tempfile
import urllib3
import dns.resolver
import time
import base64
import signal
import hashlib
import atexit
import random

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
    # Shared secret-detection regexes (used by GitHub scanning and cloud content scanning)
    SENSITIVE_PATTERNS = {
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

    # Max unknown-type files to pull per bucket when download_unknown_files is enabled
    UNKNOWN_DOWNLOAD_CAP = 10

    def __init__(self, domain, ip_ranges: List[str], output_dir: str, client_name: str, auto_resume: bool = False):
                # domain may be a single string or a list of domains
                if isinstance(domain, str):
                    domain = [domain]
                self.domains = domain
                self.domain = self.domains[0]
                self.current_domain = self.domains[0]
                self.ip_ranges = ip_ranges
                self.output_dir = Path(output_dir)
                self.client_name = client_name
                self.auto_resume = auto_resume

                # Cloud storage: pull unknown-type files only when enabled, capped
                # at UNKNOWN_DOWNLOAD_CAP per bucket. Off by default so unknowns are
                # logged to the manifest for manual review rather than bulk-downloaded.
                self.download_unknown_files = False

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

                # Per-domain result slices and client-level results
                self.all_results = {d: self._fresh_results(d) for d in self.domains}
                self.client_results = {
                    'ip_ranges': self.ip_ranges,
                    'client': self.client_name,
                    'network_scan': {}
                }
                self.results = self.all_results[self.domain]

                # Create output directory
                self.output_dir.mkdir(parents=True, exist_ok=True)

                # Initialize state tracking
                self.init_state()

                # Check for existing state and handle resume
                self._handle_existing_state()

                # Setup signal handlers for graceful shutdown
                self.setup_signal_handlers()

    def _fresh_results(self, domain: str) -> Dict[str, Any]:
                """Return a fresh per-domain results slice"""
                return {
                    'timestamp': datetime.now().isoformat(),
                    'domain': domain,
                    'client': self.client_name,
                    'scope_validation': {},
                    'm365_tenant': {},
                    'adfs': {},
                    'email_security': {},
                    'dns_enumeration': {},
                    'post_dns_whois': {},
                    'technology_stack': {},
                    'email_addresses': [],
                    'breach_data': {},
                    's3_buckets': {},
                    'azure_storage': {},
                    'gcp_storage': {},
                    'github_secrets': {},
                    'linkedin_intel': {},
                    'asn_data': {},
                    'subdomain_takeovers': []
                }

    def _handle_existing_state(self):
        """Check for existing state file and handle resume logic"""
        if self.load_state():
            # Valid state file exists
            if self.prompt_resume():
                # User chose to resume
                self.print_success("Resuming from previous state")
                # Results were already restored in load_state()
            else:
                # User chose fresh start - state was reset in prompt_resume()
                pass
        else:
            # No valid state file - fresh start
            self.state['session']['started_at'] = datetime.now().isoformat()
            self.save_state()

    def print_banner(self):
        """Print script banner"""
        banner = f"""
{Colors.HEADER}{'='*80}
    PENETRATION TESTING RECONNAISSANCE AUTOMATION
    Client: {self.client_name}
    Domains: {', '.join(self.domains)}
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

    def _write_unknown_manifest(self, source: str, location: str, unknown_files: list) -> None:
            """Append unknown-type filenames to a run-level manifest for manual review.

            Writes self.output_dir/unknown_files_manifest.csv with a header on
            first use. Each entry is a file dict from any cloud analyzer; the
            filename is read from 'key' or 'name' and size/url default safely so
            the same call works for S3, GCP, and Azure listings.
            """
            if not unknown_files:
                return

            import csv

            manifest_path = self.output_dir / 'unknown_files_manifest.csv'
            write_header = not manifest_path.exists()

            try:
                with open(manifest_path, 'a', newline='', encoding='utf-8') as fh:
                    writer = csv.writer(fh)
                    if write_header:
                        writer.writerow(['source', 'location', 'filename', 'size_kb', 'url'])

                    for entry in unknown_files:
                        filename = entry.get('key') or entry.get('name') or ''
                        size_kb = entry.get('size', 0) / 1024
                        url = entry.get('url', '')
                        writer.writerow([source, location, filename, f'{size_kb:.1f}', url])

                self.print_info(f"  Logged {len(unknown_files)} unknown file(s) to {manifest_path}")
            except Exception as e:
                self.print_error(f"Failed to write unknown-file manifest: {e}")


    def _is_sensitive_file(self, filename: str) -> tuple[bool, str, str]:
            """Classify a file by extension and name patterns.

            Returns (should_download, category, reason). Category is one of
            HIGH, MEDIUM, EXCLUDED, UNKNOWN. Unknown types are not downloaded
            by default; the caller decides whether to pull them under a
            per-bucket cap and logs them to the unknown-file manifest regardless.
            """
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
                    return (False, 'EXCLUDED', ext)

            # Check high interest extensions
            for ext, reason in high_interest.items():
                if filename_lower.endswith(ext):
                    return (True, 'HIGH', reason)

            # Check sensitive patterns in filename
            for pattern, reason in sensitive_patterns.items():
                if pattern in filename_lower:
                    return (True, 'HIGH', reason)

            # Check medium interest extensions
            for ext, reason in medium_interest.items():
                if filename_lower.endswith(ext):
                    return (True, 'MEDIUM', reason)

            # Check code extensions (medium interest, but lower priority)
            for ext, reason in code_extensions.items():
                if filename_lower.endswith(ext):
                    return (True, 'MEDIUM', reason)

            # Unknown file type: do not download by default, log for manual review
            return (False, 'UNKNOWN', 'Unknown file type')

    def scope_validation(self):
                """Perform scope validation including WHOIS and DNS verification"""
                self.print_section("SCOPE VALIDATION")

                # =====================================================================
                # Domain WHOIS lookup
                # =====================================================================
                self.print_info(f"Performing domain WHOIS lookup for {self.domain}...")

                domain_whois = {}

                try:
                    output = self.run_command(['whois', self.domain], timeout=30)
                    if output:
                        domain_whois = self._parse_whois(output, whois_type='domain')

                        if domain_whois.get('privacy_protected'):
                            self.print_warning("Domain uses privacy protection - contact info may be masked")

                        # Display found organizations
                        for org in domain_whois.get('organizations', []):
                            self.print_success(f"  Organization: {org}")

                        # Display found emails
                        for email in domain_whois.get('emails', []):
                            self.print_success(f"  Email: {email}")

                        # Display found phones
                        for phone in domain_whois.get('phones', []):
                            self.print_success(f"  Phone: {phone}")

                        # Display found addresses
                        for addr in domain_whois.get('addresses', []):
                            self.print_success(f"  Address ({addr['source']}): {addr['street']}, {addr['city']}, {addr['state']} {addr['postal_code']}, {addr['country']}")

                        # Display name servers
                        if domain_whois.get('name_servers'):
                            self.print_info(f"  Name Servers: {', '.join(domain_whois['name_servers'])}")

                        if not any([domain_whois.get('emails'), domain_whois.get('addresses'), domain_whois.get('phones')]):
                            self.print_warning("No usable contact information found (likely privacy protected)")

                except Exception as e:
                    self.print_error(f"Domain WHOIS failed: {e}")

                self.results['scope_validation']['domain_whois'] = domain_whois

                # Add discovered emails to main email list
                if domain_whois.get('emails'):
                    existing_emails = self.results.get('email_addresses', [])
                    for email in domain_whois['emails']:
                        if email not in existing_emails:
                            existing_emails.append(email)
                    self.results['email_addresses'] = existing_emails

                # =====================================================================
                # IP WHOIS lookups (if IP ranges provided)
                # =====================================================================
                whois_results = {}

                if self.ip_ranges:
                    self.print_info("\nPerforming WHOIS lookups for IP ranges...")
                    for ip_range in self.ip_ranges:
                        try:
                            if '/' in ip_range:
                                ip = str(ipaddress.ip_network(ip_range, strict=False).network_address)
                            else:
                                ip = ip_range

                            output = self.run_command(['whois', ip])
                            if output:
                                whois_results[ip_range] = self._parse_whois(output, whois_type='ip')
                                org = whois_results[ip_range].get('org', 'Unknown')
                                self.print_success(f"{ip_range} - Organization: {org}")
                        except Exception as e:
                            self.print_error(f"WHOIS failed for {ip_range}: {e}")
                else:
                    self.print_info("\nSkipping IP WHOIS lookups (no IP ranges provided)")

                self.results['scope_validation']['whois'] = whois_results

                # =====================================================================
                # DNS verification
                # =====================================================================
                self.print_info(f"\nVerifying DNS records for {self.domain}...")
                dns_records = self._get_dns_records(self.domain)
                self.results['scope_validation']['dns_verification'] = dns_records

                if dns_records.get('A'):
                    self.print_success(f"Domain resolves to: {', '.join(dns_records['A'])}")

                    if self.ip_ranges:
                        for ip in dns_records['A']:
                            in_scope = self._is_ip_in_scope(ip)
                            if in_scope:
                                self.print_success(f"✓ {ip} is within authorized scope")
                            else:
                                self.print_warning(f"✗ {ip} is NOT in provided scope ranges")

    def m365_tenant_attribution(self):
                """Identify M365/Azure AD tenant attribution and federation posture"""
                self.print_section("M365/AZURE AD TENANT ATTRIBUTION")

                # Restore from checkpoint if exists
                resume_data = self.get_resume_data('m365_tenant')
                progress = resume_data.get('progress', {})

                m365_data = progress.get('m365_data', {
                    'is_m365': False,
                    'tenant_id': '',
                    'tenant_region': '',
                    'cloud_instance': '',
                    'namespace_type': '',
                    'federation_brand': '',
                    'auth_url': '',
                    'federation_host': ''
                })

                # Skip if already complete from checkpoint
                if progress.get('complete'):
                    self.print_info("Restored M365 tenant data from checkpoint")
                    if m365_data.get('is_m365'):
                        self.print_success(f"Tenant ID: {m365_data['tenant_id']}")
                    self.results['m365_tenant'] = m365_data
                    return

                # Endpoint 1: openid-configuration (domain-only, no username required)
                self.print_info(f"Querying openid-configuration for {self.domain}...")

                try:
                    url = f"https://login.microsoftonline.com/{self.domain}/.well-known/openid-configuration"
                    response = self.session.get(url, timeout=15, verify=False)

                    if response.status_code == 200:
                        data = response.json()
                        m365_data['is_m365'] = True

                        # Extract tenant ID from issuer (format: https://sts.windows.net/<tenant-id>/)
                        issuer = data.get('issuer', '')
                        match = re.search(r'/([0-9a-f-]{36})/?', issuer)
                        if match:
                            m365_data['tenant_id'] = match.group(1)
                            self.print_success(f"Tenant ID: {m365_data['tenant_id']}")

                        m365_data['tenant_region'] = data.get('tenant_region_scope', '')
                        m365_data['cloud_instance'] = data.get('cloud_instance_name', '')

                        if m365_data['tenant_region']:
                            self.print_info(f"Tenant Region: {m365_data['tenant_region']}")
                        if m365_data['cloud_instance']:
                            self.print_info(f"Cloud Instance: {m365_data['cloud_instance']}")

                    elif response.status_code == 400:
                        # Likely AADSTS90002 - tenant not found
                        body = response.text.lower()
                        if 'aadsts90002' in body or 'not found' in body:
                            self.print_info(f"Domain {self.domain} is not an M365 tenant")
                            m365_data['is_m365'] = False
                            self.results['m365_tenant'] = m365_data
                            self.checkpoint('m365_tenant', 'm365_data', m365_data)
                            self.checkpoint('m365_tenant', 'complete', True)
                            return
                        else:
                            self.print_warning(f"openid-configuration returned 400: {response.text[:200]}")
                    else:
                        self.print_warning(f"openid-configuration returned status {response.status_code}")

                except Exception as e:
                    self.print_error(f"openid-configuration query failed: {e}")

                # Endpoint 2: GetUserRealm via modern userrealm API
                self.print_info(f"Querying userrealm API for federation posture...")

                realm_endpoints = [
                    f"https://login.microsoftonline.com/common/userrealm/aaaaaa@{self.domain}?api-version=2.1",
                    f"https://login.microsoftonline.com/GetUserRealm.srf?login=aaaaaa@{self.domain}",
                    f"https://login.microsoftonline.com/getuserrealm.srf?login=aaaaaa@{self.domain}&xml=1"
                ]

                realm_data = None
                for url in realm_endpoints:
                    try:
                        response = self.session.get(
                            url,
                            headers={'Accept': 'application/json'},
                            timeout=15,
                            verify=False
                        )

                        if response.status_code == 200:
                            # XML endpoint returns text/xml, JSON endpoints return application/json
                            if 'xml' in response.headers.get('Content-Type', '').lower() or response.text.strip().startswith('<'):
                                # Parse XML response
                                ns_match = re.search(r'<NameSpaceType>([^<]+)</NameSpaceType>', response.text)
                                brand_match = re.search(r'<FederationBrandName>([^<]+)</FederationBrandName>', response.text)
                                auth_match = re.search(r'<AuthURL>([^<]+)</AuthURL>', response.text)
                                cloud_match = re.search(r'<CloudInstanceName>([^<]+)</CloudInstanceName>', response.text)

                                realm_data = {
                                    'NameSpaceType': ns_match.group(1) if ns_match else '',
                                    'FederationBrandName': brand_match.group(1) if brand_match else '',
                                    'AuthURL': auth_match.group(1) if auth_match else '',
                                    'CloudInstanceName': cloud_match.group(1) if cloud_match else ''
                                }
                            else:
                                realm_data = response.json()

                            if realm_data.get('NameSpaceType'):
                                break  # Got useful data, stop trying endpoints

                    except Exception as e:
                        continue

                if realm_data:
                    m365_data['namespace_type'] = realm_data.get('NameSpaceType', '')
                    m365_data['federation_brand'] = realm_data.get('FederationBrandName', '')
                    m365_data['auth_url'] = realm_data.get('AuthURL', '') or ''

                    if not m365_data.get('cloud_instance'):
                        m365_data['cloud_instance'] = realm_data.get('CloudInstanceName', '')

                    # If federated, extract host for Task 2 (ADFS discovery)
                    if m365_data['auth_url']:
                        match = re.search(r'https?://([^/]+)', m365_data['auth_url'])
                        if match:
                            m365_data['federation_host'] = match.group(1)

                    if m365_data['namespace_type']:
                        if m365_data['namespace_type'] == 'Federated':
                            self.print_warning(f"Namespace Type: Federated (ADFS or 3rd-party IdP)")
                            if m365_data['federation_host']:
                                self.print_success(f"Federation Host: {m365_data['federation_host']}")
                        elif m365_data['namespace_type'] == 'Managed':
                            self.print_success(f"Namespace Type: Managed (cloud-native auth)")
                        else:
                            self.print_info(f"Namespace Type: {m365_data['namespace_type']}")

                    if m365_data['federation_brand']:
                        self.print_success(f"Brand: {m365_data['federation_brand']}")
                else:
                    self.print_warning("Could not determine federation posture from any realm endpoint")

                # Store final results
                self.results['m365_tenant'] = m365_data
                self.checkpoint('m365_tenant', 'm365_data', m365_data)
                self.checkpoint('m365_tenant', 'complete', True)

                # Summary
                if m365_data['is_m365']:
                    self.print_info(f"\nM365 Tenant Summary:")
                    self.print_info(f"  Tenant ID: {m365_data.get('tenant_id', 'Unknown')}")
                    self.print_info(f"  Namespace: {m365_data.get('namespace_type') or 'Unknown'}")
                    self.print_info(f"  Brand: {m365_data.get('federation_brand') or 'Unknown'}")
                else:
                    self.print_info("Domain does not appear to be an M365 tenant")

    def adfs_endpoint_discovery(self):
                """Discover and fingerprint ADFS endpoints for federated M365 tenants"""
                self.print_section("ADFS ENDPOINT DISCOVERY")

                # Restore from checkpoint if exists
                resume_data = self.get_resume_data('adfs')
                progress = resume_data.get('progress', {})

                adfs_data = progress.get('adfs_data', {
                    'hosts_probed': [],
                    'endpoints_found': {},
                    'version_info': {},
                    'federation_metadata': {},
                    'supported_endpoints': [],
                    'token_signing_cert': {}
                })

                # Skip if already complete from checkpoint
                if progress.get('complete'):
                    self.print_info("Restored ADFS data from checkpoint")
                    self.results['adfs'] = adfs_data
                    return

                # Gate: only run for federated M365 tenants
                m365 = self.results.get('m365_tenant', {})
                if not m365.get('is_m365'):
                    self.print_info("Skipping ADFS discovery (not an M365 tenant)")
                    self.results['adfs'] = adfs_data
                    self.checkpoint('adfs', 'complete', True)
                    return

                if m365.get('namespace_type') != 'Federated':
                    self.print_info(f"Skipping ADFS discovery (tenant is {m365.get('namespace_type', 'Unknown')}, not Federated)")
                    self.results['adfs'] = adfs_data
                    self.checkpoint('adfs', 'complete', True)
                    return

                # Build target host list
                target_hosts = set()
                federation_host = m365.get('federation_host', '')
                if federation_host:
                    target_hosts.add(federation_host)

                adfs_guess = f"adfs.{self.domain}"
                if adfs_guess != federation_host:
                    target_hosts.add(adfs_guess)

                if not target_hosts:
                    self.print_warning("No ADFS hosts to probe")
                    self.results['adfs'] = adfs_data
                    self.checkpoint('adfs', 'complete', True)
                    return

                self.print_info(f"Probing {len(target_hosts)} ADFS host(s)")

                # Endpoints to probe per host
                endpoints = [
                    ('idpinitiatedsignon', '/adfs/ls/idpinitiatedsignon.aspx'),
                    ('federation_metadata', '/FederationMetadata/2007-06/FederationMetadata.xml'),
                    ('ls_base', '/adfs/ls/'),
                    ('ws_trust_mex', '/adfs/services/trust/mex'),
                    ('oauth2_authorize', '/adfs/oauth2/authorize')
                ]

                for host in sorted(target_hosts):
                    self.print_info(f"\nProbing {host}...")

                    host_results = {
                        'host': host,
                        'reachable': False,
                        'endpoints': {}
                    }

                    for endpoint_name, path in endpoints:
                        url = f"https://{host}{path}"

                        try:
                            response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
                            host_results['reachable'] = True

                            endpoint_result = {
                                'url': url,
                                'status_code': response.status_code,
                                'present': response.status_code in [200, 302, 401, 403]
                            }

                            # Extract data per endpoint type
                            if endpoint_name == 'idpinitiatedsignon' and response.status_code == 200:
                                # ADFS version disclosure in page content
                                content = response.text

                                # Page title
                                title_match = re.search(r'<title>([^<]+)</title>', content, re.IGNORECASE)
                                if title_match:
                                    endpoint_result['page_title'] = title_match.group(1).strip()

                                # Build number in script references
                                build_match = re.search(r'/adfs/portal/(\d+\.\d+\.\d+\.\d+)/', content)
                                if build_match:
                                    endpoint_result['build_number'] = build_match.group(1)
                                    adfs_data['version_info']['build_number'] = build_match.group(1)
                                    self.print_success(f"  ADFS Build Number: {build_match.group(1)}")

                                # Copyright year
                                copyright_match = re.search(r'(?:Copyright|©|&copy;)[^<]*?(\d{4})', content)
                                if copyright_match:
                                    endpoint_result['copyright_year'] = copyright_match.group(1)

                                # ADFS version inference from build number
                                if build_match:
                                    build = build_match.group(1)
                                    if build.startswith('6.'):
                                        adfs_data['version_info']['adfs_version'] = 'ADFS 4.0 (Server 2016)'
                                    elif build.startswith('10.0.14'):
                                        adfs_data['version_info']['adfs_version'] = 'ADFS 2019 (Server 2019)'
                                    elif build.startswith('10.0.17') or build.startswith('10.0.20'):
                                        adfs_data['version_info']['adfs_version'] = 'ADFS 2022 (Server 2022)'

                                self.print_success(f"  Sign-on page reachable (status 200)")

                            elif endpoint_name == 'federation_metadata' and response.status_code == 200:
                                # Parse FederationMetadata.xml for endpoints and certs
                                content = response.text

                                # Entity ID
                                entity_match = re.search(r'entityID="([^"]+)"', content)
                                if entity_match:
                                    endpoint_result['entity_id'] = entity_match.group(1)
                                    adfs_data['federation_metadata']['entity_id'] = entity_match.group(1)
                                    self.print_success(f"  Entity ID: {entity_match.group(1)}")

                                # Role descriptors
                                role_descriptors = re.findall(r'<RoleDescriptor[^>]+xsi:type="[^:]*:([^"]+)"', content)
                                if role_descriptors:
                                    endpoint_result['role_descriptors'] = list(set(role_descriptors))

                                # Supported endpoint types
                                supported = []
                                if 'SingleSignOnService' in content:
                                    supported.append('SAML2 SSO')
                                if 'PassiveRequestorEndpoint' in content:
                                    supported.append('WS-Federation Passive')
                                if 'SecurityTokenServiceEndpoint' in content:
                                    supported.append('WS-Trust STS')
                                if 'wsFedellingService' in content or 'WSFederation' in content:
                                    supported.append('WS-Federation')

                                # Extract all binding URLs
                                binding_urls = re.findall(r'Location="(https://[^"]+)"', content)
                                if binding_urls:
                                    endpoint_result['binding_urls'] = list(set(binding_urls))[:20]
                                    adfs_data['supported_endpoints'] = list(set(binding_urls))[:20]

                                if supported:
                                    endpoint_result['supported_protocols'] = supported
                                    self.print_success(f"  Supported: {', '.join(supported)}")

                                # Token signing certificate details
                                cert_match = re.search(r'<X509Certificate>([^<]+)</X509Certificate>', content)
                                if cert_match:
                                    cert_b64 = cert_match.group(1).strip()
                                    endpoint_result['signing_cert_present'] = True
                                    adfs_data['token_signing_cert']['present'] = True
                                    adfs_data['token_signing_cert']['cert_b64_truncated'] = cert_b64[:200]

                                    # Try to decode and extract cert details
                                    try:
                                        cert_der = base64.b64decode(cert_b64)
                                        # Extract validity dates via regex on the decoded cert (ASN.1 parsing without external libs)
                                        # Look for common cert patterns - this is best-effort
                                        endpoint_result['signing_cert_size_bytes'] = len(cert_der)
                                        self.print_success(f"  Token signing cert present ({len(cert_der)} bytes)")
                                    except Exception:
                                        pass

                                self.print_success(f"  Federation metadata retrieved")

                            elif endpoint_name == 'ws_trust_mex' and response.status_code == 200:
                                # WS-Trust MEX endpoint - confirms WS-Trust support
                                content_type = response.headers.get('Content-Type', '')
                                if 'xml' in content_type.lower() or '<wsdl' in response.text.lower():
                                    endpoint_result['ws_trust_supported'] = True
                                    self.print_success(f"  WS-Trust MEX endpoint active")

                                    # Extract WS-Trust binding URLs
                                    trust_urls = re.findall(r'address="(https://[^"]*trust[^"]*)"', response.text, re.IGNORECASE)
                                    if trust_urls:
                                        endpoint_result['ws_trust_endpoints'] = list(set(trust_urls))

                            elif endpoint_name == 'oauth2_authorize':
                                # OAuth2 endpoint presence (ADFS 3.0+)
                                if response.status_code in [200, 302, 400]:
                                    endpoint_result['oauth2_supported'] = True
                                    if 'oauth' in response.text.lower() or response.status_code == 302:
                                        self.print_success(f"  OAuth2 endpoint active (ADFS 3.0+)")
                                        adfs_data['version_info']['oauth2_supported'] = True

                            elif endpoint_name == 'ls_base':
                                # Base LS endpoint - status code tells us about presence
                                if response.status_code in [200, 302, 401, 403]:
                                    self.print_success(f"  Base /adfs/ls/ endpoint present (status {response.status_code})")

                            # Capture server header if present
                            if 'Server' in response.headers:
                                endpoint_result['server_header'] = response.headers['Server']

                            host_results['endpoints'][endpoint_name] = endpoint_result

                        except requests.exceptions.SSLError as e:
                            host_results['endpoints'][endpoint_name] = {
                                'url': url,
                                'error': 'SSL Error',
                                'present': False
                            }
                        except requests.exceptions.ConnectionError:
                            host_results['endpoints'][endpoint_name] = {
                                'url': url,
                                'error': 'Connection refused',
                                'present': False
                            }
                        except requests.exceptions.Timeout:
                            host_results['endpoints'][endpoint_name] = {
                                'url': url,
                                'error': 'Timeout',
                                'present': False
                            }
                        except Exception as e:
                            host_results['endpoints'][endpoint_name] = {
                                'url': url,
                                'error': str(e)[:100],
                                'present': False
                            }

                        time.sleep(0.5)

                    if not host_results['reachable']:
                        self.print_warning(f"  Host {host} not reachable on any endpoint")

                    adfs_data['hosts_probed'].append(host_results)
                    adfs_data['endpoints_found'][host] = host_results['endpoints']

                    # Checkpoint per host
                    self.checkpoint('adfs', 'adfs_data', adfs_data)

                # Store final results
                self.results['adfs'] = adfs_data
                self.checkpoint('adfs', 'adfs_data', adfs_data)
                self.checkpoint('adfs', 'complete', True)

                # Summary
                reachable_hosts = [h for h in adfs_data['hosts_probed'] if h.get('reachable')]
                self.print_info(f"\nADFS Discovery Summary:")
                self.print_info(f"  Hosts probed: {len(adfs_data['hosts_probed'])}")
                self.print_info(f"  Hosts reachable: {len(reachable_hosts)}")
                if adfs_data['version_info'].get('adfs_version'):
                    self.print_success(f"  ADFS Version: {adfs_data['version_info']['adfs_version']}")
                if adfs_data['version_info'].get('build_number'):
                    self.print_info(f"  Build: {adfs_data['version_info']['build_number']}")
                if adfs_data['version_info'].get('oauth2_supported'):
                    self.print_info(f"  OAuth2: Supported")
                if adfs_data['federation_metadata'].get('entity_id'):
                    self.print_info(f"  Entity ID: {adfs_data['federation_metadata']['entity_id']}")

    def email_security_posture(self):
                """Assess SPF, DKIM, and DMARC posture for the target domain"""
                self.print_section("EMAIL SECURITY POSTURE (SPF/DKIM/DMARC)")

                results = {
                    'domain': self.domain,
                    'spf': {
                        'present': False,
                        'record': None,
                        'multiple_records': False,
                        'qualifier': None,
                        'dns_lookup_count': 0,
                        'mechanisms': [],
                        'includes': [],
                        'findings': []
                    },
                    'dmarc': {
                        'present': False,
                        'record': None,
                        'policy': None,
                        'subdomain_policy': None,
                        'pct': None,
                        'rua': [],
                        'ruf': [],
                        'aspf': None,
                        'adkim': None,
                        'findings': []
                    },
                    'dkim': {
                        'selectors_checked': [],
                        'selectors_found': [],
                        'records': {},
                        'findings': []
                    },
                    'overall_severity': 'Low'
                }

                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10

                # =====================================================================
                # SPF Analysis
                # =====================================================================
                self.print_info(f"Checking SPF record for {self.domain}...")

                try:
                    txt_answers = resolver.resolve(self.domain, 'TXT')
                    spf_records = []

                    for rdata in txt_answers:
                        record_text = ''.join(s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings)
                        if record_text.lower().startswith('v=spf1'):
                            spf_records.append(record_text)

                    if not spf_records:
                        results['spf']['findings'].append({
                            'severity': 'High',
                            'finding': 'No SPF record present',
                            'detail': 'Without SPF, any sender can claim to send mail from this domain. Anti-spoofing protection depends on SPF being in place and enforced.'
                        })
                        self.print_warning("  No SPF record found")
                    else:
                        results['spf']['present'] = True

                        if len(spf_records) > 1:
                            results['spf']['multiple_records'] = True
                            results['spf']['findings'].append({
                                'severity': 'High',
                                'finding': f'{len(spf_records)} SPF records present (RFC 7208 violation)',
                                'detail': 'Multiple SPF records on the same domain cause receiving servers to return a permerror. SPF validation fails completely, effectively disabling SPF protection.'
                            })
                            self.print_warning(f"  Multiple SPF records found ({len(spf_records)}) - RFC violation")

                        spf_record = spf_records[0]
                        results['spf']['record'] = spf_record

                        # Parse mechanisms
                        parts = spf_record.split()
                        mechanisms = []
                        includes = []
                        dns_lookup_count = 0
                        qualifier = None

                        for part in parts[1:]:  # skip v=spf1
                            part_lower = part.lower()
                            mechanisms.append(part)

                            # Each include, a, mx, exists, redirect counts as 1 DNS lookup
                            if part_lower.startswith('include:'):
                                dns_lookup_count += 1
                                includes.append(part[8:])
                            elif part_lower.startswith('a:') or part_lower == 'a':
                                dns_lookup_count += 1
                            elif part_lower.startswith('mx:') or part_lower == 'mx':
                                dns_lookup_count += 1
                            elif part_lower.startswith('exists:'):
                                dns_lookup_count += 1
                            elif part_lower.startswith('redirect='):
                                dns_lookup_count += 1
                            elif part_lower.startswith('ptr:') or part_lower == 'ptr':
                                dns_lookup_count += 1

                            # Capture the all qualifier
                            if part_lower.endswith('all'):
                                if part_lower == 'all' or part_lower == '+all':
                                    qualifier = '+all'
                                elif part_lower == '-all':
                                    qualifier = '-all'
                                elif part_lower == '~all':
                                    qualifier = '~all'
                                elif part_lower == '?all':
                                    qualifier = '?all'

                        results['spf']['mechanisms'] = mechanisms
                        results['spf']['includes'] = includes
                        results['spf']['dns_lookup_count'] = dns_lookup_count
                        results['spf']['qualifier'] = qualifier

                        # Findings based on qualifier
                        if qualifier == '+all':
                            results['spf']['findings'].append({
                                'severity': 'Critical',
                                'finding': 'SPF record uses +all (permit all senders)',
                                'detail': 'The +all qualifier instructs receivers to accept mail from any source as legitimate. This completely defeats the purpose of SPF and allows unrestricted domain spoofing.'
                            })
                            self.print_error(f"  SPF qualifier: +all (CRITICAL - permits any sender)")
                        elif qualifier == '?all':
                            results['spf']['findings'].append({
                                'severity': 'Medium',
                                'finding': 'SPF record uses ?all (neutral, no enforcement)',
                                'detail': 'The ?all qualifier provides no guidance to receivers on how to handle mail from non-authorized sources. Effectively no spoofing protection.'
                            })
                            self.print_warning(f"  SPF qualifier: ?all (no enforcement)")
                        elif qualifier == '~all':
                            results['spf']['findings'].append({
                                'severity': 'Low',
                                'finding': 'SPF record uses ~all (soft fail)',
                                'detail': 'The ~all qualifier marks unauthorized mail as suspicious but typically still delivers it. -all (hard fail) is recommended once SPF deployment is validated.'
                            })
                            self.print_info(f"  SPF qualifier: ~all (soft fail)")
                        elif qualifier == '-all':
                            self.print_success(f"  SPF qualifier: -all (hard fail - enforced)")
                        elif qualifier is None:
                            results['spf']['findings'].append({
                                'severity': 'High',
                                'finding': 'SPF record missing all qualifier',
                                'detail': 'Without a terminating all qualifier, the SPF record provides no default handling for non-listed sources. Behavior is unpredictable across receivers.'
                            })
                            self.print_warning(f"  SPF qualifier: missing (no default policy)")

                        # DNS lookup limit findings
                        if dns_lookup_count > 10:
                            results['spf']['findings'].append({
                                'severity': 'High',
                                'finding': f'SPF DNS lookup limit exceeded ({dns_lookup_count} lookups, RFC limit is 10)',
                                'detail': 'When SPF requires more than 10 DNS lookups, receivers return permerror and SPF validation fails completely. The domain has no working SPF enforcement.'
                            })
                            self.print_error(f"  SPF DNS lookups: {dns_lookup_count} (EXCEEDS RFC LIMIT)")
                        elif dns_lookup_count >= 8:
                            results['spf']['findings'].append({
                                'severity': 'Low',
                                'finding': f'SPF DNS lookup count approaching limit ({dns_lookup_count}/10)',
                                'detail': 'SPF is close to the 10-lookup RFC limit. Adding additional mail senders could push the record over the limit and break authentication.'
                            })
                            self.print_warning(f"  SPF DNS lookups: {dns_lookup_count}/10 (approaching limit)")
                        else:
                            self.print_info(f"  SPF DNS lookups: {dns_lookup_count}/10")

                        if includes:
                            self.print_info(f"  SPF includes: {', '.join(includes[:5])}")
                            if len(includes) > 5:
                                self.print_info(f"  ... and {len(includes) - 5} more")

                except dns.resolver.NoAnswer:
                    results['spf']['findings'].append({
                        'severity': 'High',
                        'finding': 'No TXT records found for domain',
                        'detail': 'Domain has no TXT records, including no SPF record. Anti-spoofing protection is absent.'
                    })
                    self.print_warning("  No TXT records found")
                except dns.resolver.NXDOMAIN:
                    self.print_error(f"  Domain {self.domain} does not exist in DNS")
                except Exception as e:
                    self.print_error(f"  SPF lookup failed: {e}")

                # =====================================================================
                # DMARC Analysis
                # =====================================================================
                dmarc_domain = f"_dmarc.{self.domain}"
                self.print_info(f"\nChecking DMARC record at {dmarc_domain}...")

                try:
                    dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
                    dmarc_records = []

                    for rdata in dmarc_answers:
                        record_text = ''.join(s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings)
                        if record_text.lower().startswith('v=dmarc1'):
                            dmarc_records.append(record_text)

                    if not dmarc_records:
                        results['dmarc']['findings'].append({
                            'severity': 'High',
                            'finding': 'No DMARC record present',
                            'detail': 'Without DMARC, receivers have no instruction on how to handle SPF/DKIM authentication failures. Spoofed mail is more likely to be delivered.'
                        })
                        self.print_warning("  No DMARC record found")
                    else:
                        results['dmarc']['present'] = True
                        dmarc_record = dmarc_records[0]
                        results['dmarc']['record'] = dmarc_record

                        # Parse DMARC tags
                        tags = {}
                        for tag_pair in dmarc_record.split(';'):
                            tag_pair = tag_pair.strip()
                            if '=' in tag_pair:
                                key, value = tag_pair.split('=', 1)
                                tags[key.strip().lower()] = value.strip()

                        policy = tags.get('p', '').lower()
                        sp = tags.get('sp', '').lower()
                        pct = tags.get('pct', '100')
                        rua = tags.get('rua', '')
                        ruf = tags.get('ruf', '')
                        aspf = tags.get('aspf', 'r').lower()
                        adkim = tags.get('adkim', 'r').lower()

                        results['dmarc']['policy'] = policy if policy else None
                        results['dmarc']['subdomain_policy'] = sp if sp else None
                        results['dmarc']['pct'] = pct
                        results['dmarc']['rua'] = [addr.strip() for addr in rua.replace('mailto:', '').split(',') if addr.strip()] if rua else []
                        results['dmarc']['ruf'] = [addr.strip() for addr in ruf.replace('mailto:', '').split(',') if addr.strip()] if ruf else []
                        results['dmarc']['aspf'] = aspf
                        results['dmarc']['adkim'] = adkim

                        # Findings based on policy
                        if policy == 'none':
                            results['dmarc']['findings'].append({
                                'severity': 'High',
                                'finding': 'DMARC policy set to p=none (monitor mode only)',
                                'detail': 'With p=none, DMARC provides reporting but no enforcement. Mail failing SPF/DKIM authentication is still delivered. This is a transitional posture not suitable for ongoing operation.'
                            })
                            self.print_warning(f"  DMARC policy: p=none (no enforcement)")
                        elif policy == 'quarantine':
                            try:
                                pct_val = int(pct)
                                if pct_val < 100:
                                    results['dmarc']['findings'].append({
                                        'severity': 'Medium',
                                        'finding': f'DMARC quarantine policy applied to only {pct_val}% of mail',
                                        'detail': f'The pct={pct_val} tag means only {pct_val}% of failing mail is subject to the quarantine policy. The remaining {100 - pct_val}% is delivered normally despite failing authentication.'
                                    })
                                    self.print_warning(f"  DMARC policy: p=quarantine, pct={pct_val} (partial enforcement)")
                                else:
                                    self.print_success(f"  DMARC policy: p=quarantine (full enforcement)")
                            except ValueError:
                                self.print_warning(f"  DMARC policy: p=quarantine, pct={pct} (could not parse pct)")
                        elif policy == 'reject':
                            try:
                                pct_val = int(pct)
                                if pct_val < 100:
                                    results['dmarc']['findings'].append({
                                        'severity': 'Low',
                                        'finding': f'DMARC reject policy applied to only {pct_val}% of mail',
                                        'detail': f'pct={pct_val} means {100 - pct_val}% of failing mail bypasses the reject policy.'
                                    })
                                    self.print_warning(f"  DMARC policy: p=reject, pct={pct_val}")
                                else:
                                    self.print_success(f"  DMARC policy: p=reject (strongest enforcement)")
                            except ValueError:
                                self.print_info(f"  DMARC policy: p=reject")
                        else:
                            results['dmarc']['findings'].append({
                                'severity': 'High',
                                'finding': f'DMARC policy missing or unrecognized: p={policy}',
                                'detail': 'DMARC record exists but the policy tag is invalid. Receivers will not apply any enforcement.'
                            })

                        # Subdomain policy findings
                        if not sp and policy in ('quarantine', 'reject'):
                            results['dmarc']['findings'].append({
                                'severity': 'Medium',
                                'finding': 'No explicit DMARC subdomain policy (sp=)',
                                'detail': 'Without an explicit sp= tag, subdomains inherit the apex policy. This is often acceptable, but for organizations with many subdomains, explicit sp=reject is recommended to prevent subdomain spoofing if any subdomain has weaker authentication.'
                            })
                        elif sp == 'none' and policy != 'none':
                            results['dmarc']['findings'].append({
                                'severity': 'High',
                                'finding': f'DMARC subdomain policy weaker than apex (sp=none, p={policy})',
                                'detail': 'Subdomains are exempt from DMARC enforcement while the apex domain is protected. Subdomain spoofing is permitted.'
                            })

                        # Reporting findings
                        if not results['dmarc']['rua']:
                            results['dmarc']['findings'].append({
                                'severity': 'Low',
                                'finding': 'No DMARC aggregate reporting address (rua=)',
                                'detail': 'Without rua= reporting, the organization has no visibility into mail authentication failures or spoofing attempts against the domain.'
                            })

                        if results['dmarc']['rua']:
                            self.print_info(f"  DMARC aggregate reports: {', '.join(results['dmarc']['rua'])}")

                except dns.resolver.NoAnswer:
                    results['dmarc']['findings'].append({
                        'severity': 'High',
                        'finding': 'No DMARC record present',
                        'detail': 'No TXT record at _dmarc subdomain. DMARC enforcement is absent.'
                    })
                    self.print_warning("  No DMARC record found")
                except dns.resolver.NXDOMAIN:
                    results['dmarc']['findings'].append({
                        'severity': 'High',
                        'finding': 'No DMARC record present',
                        'detail': '_dmarc subdomain does not exist. DMARC enforcement is absent.'
                    })
                    self.print_warning("  No DMARC record (NXDOMAIN on _dmarc)")
                except Exception as e:
                    self.print_error(f"  DMARC lookup failed: {e}")

                # =====================================================================
                # DKIM Analysis (common selector probing)
                # =====================================================================
                self.print_info(f"\nProbing common DKIM selectors...")

                common_selectors = [
                    'google', 'selector1', 'selector2', 'mail', 'default',
                    'k1', 'k2', 'dkim', 'mxvault', 'mandrill'
                ]

                results['dkim']['selectors_checked'] = common_selectors

                for selector in common_selectors:
                    dkim_domain = f"{selector}._domainkey.{self.domain}"
                    try:
                        dkim_answers = resolver.resolve(dkim_domain, 'TXT')

                        for rdata in dkim_answers:
                            record_text = ''.join(s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings)

                            if 'k=' in record_text.lower() or 'p=' in record_text.lower():
                                results['dkim']['selectors_found'].append(selector)

                                # Parse DKIM tags
                                tags = {}
                                for tag_pair in record_text.split(';'):
                                    tag_pair = tag_pair.strip()
                                    if '=' in tag_pair:
                                        key, value = tag_pair.split('=', 1)
                                        tags[key.strip().lower()] = value.strip()

                                dkim_data = {
                                    'selector': selector,
                                    'record': record_text,
                                    'key_type': tags.get('k', 'rsa'),
                                    'key_present': bool(tags.get('p', '').strip()),
                                    'public_key': tags.get('p', ''),
                                    'hash_algorithms': tags.get('h', 'sha1,sha256'),
                                    'service_type': tags.get('s', '*'),
                                    'key_length': None
                                }

                                # Estimate key length from base64 public key
                                pubkey = tags.get('p', '').strip()
                                if pubkey:
                                    try:
                                        import base64
                                        decoded = base64.b64decode(pubkey + '=' * (4 - len(pubkey) % 4))
                                        # RSA key length: roughly decoded_length * 8 / 1.4 for DER-encoded keys
                                        # More accurate: extract from ASN.1 structure
                                        # Quick estimate based on base64 length
                                        if len(pubkey) > 600:
                                            dkim_data['key_length'] = 4096
                                        elif len(pubkey) > 350:
                                            dkim_data['key_length'] = 2048
                                        elif len(pubkey) > 200:
                                            dkim_data['key_length'] = 1024
                                        elif len(pubkey) > 100:
                                            dkim_data['key_length'] = 512
                                        else:
                                            dkim_data['key_length'] = 'unknown'
                                    except Exception:
                                        dkim_data['key_length'] = 'unknown'
                                else:
                                    # Revoked DKIM key
                                    results['dkim']['findings'].append({
                                        'severity': 'Info',
                                        'finding': f'DKIM selector {selector} has empty public key (revoked)',
                                        'detail': 'An empty p= tag is the correct way to retire a DKIM selector. This is informational only.'
                                    })

                                results['dkim']['records'][selector] = dkim_data

                                # Findings based on key length
                                if isinstance(dkim_data['key_length'], int):
                                    if dkim_data['key_length'] < 1024:
                                        results['dkim']['findings'].append({
                                            'severity': 'Critical',
                                            'finding': f'DKIM selector {selector} uses {dkim_data["key_length"]}-bit key',
                                            'detail': f'RSA keys below 1024 bits are trivially broken. DKIM signatures from this selector provide no security guarantee.'
                                        })
                                    elif dkim_data['key_length'] == 1024:
                                        results['dkim']['findings'].append({
                                            'severity': 'Medium',
                                            'finding': f'DKIM selector {selector} uses 1024-bit key (deprecated)',
                                            'detail': 'NIST and RFC 8301 recommend 2048-bit RSA keys as minimum. 1024-bit DKIM keys are considered weak and should be upgraded.'
                                        })
                                        self.print_warning(f"  DKIM {selector}: 1024-bit key (deprecated)")
                                    else:
                                        self.print_success(f"  DKIM {selector}: {dkim_data['key_length']}-bit key")

                                # Hash algorithm findings
                                if 'sha1' in dkim_data['hash_algorithms'].lower() and 'sha256' not in dkim_data['hash_algorithms'].lower():
                                    results['dkim']['findings'].append({
                                        'severity': 'Medium',
                                        'finding': f'DKIM selector {selector} only supports sha1 hashing',
                                        'detail': 'SHA-1 is deprecated for cryptographic signatures. DKIM records should advertise sha256 support.'
                                    })

                    except dns.resolver.NXDOMAIN:
                        continue
                    except dns.resolver.NoAnswer:
                        continue
                    except Exception:
                        continue

                if not results['dkim']['selectors_found']:
                    results['dkim']['findings'].append({
                        'severity': 'Medium',
                        'finding': 'No DKIM selectors detected with common selector names',
                        'detail': f'Probed {len(common_selectors)} common DKIM selector names with no hits. The domain may not be signing outbound mail with DKIM, or may be using non-standard selector names. Verify by examining headers of received mail from this domain.'
                    })
                    self.print_warning(f"  No DKIM records found for common selectors")
                else:
                    self.print_success(f"\n  DKIM selectors found: {', '.join(results['dkim']['selectors_found'])}")

                # =====================================================================
                # Overall severity calculation
                # =====================================================================
                all_findings = (results['spf']['findings'] +
                            results['dmarc']['findings'] +
                            results['dkim']['findings'])

                severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
                highest = max([severity_order.get(f['severity'], 0) for f in all_findings] or [0])
                severity_map = {4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Informational'}
                results['overall_severity'] = severity_map[highest]

                # Summary output
                self.print_info(f"\nEmail Security Posture Summary:")
                self.print_info(f"  Total findings: {len(all_findings)}")
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    count = sum(1 for f in all_findings if f['severity'] == severity)
                    if count > 0:
                        if severity == 'Critical':
                            self.print_error(f"  {severity}: {count}")
                        elif severity == 'High':
                            self.print_warning(f"  {severity}: {count}")
                        else:
                            self.print_info(f"  {severity}: {count}")

                self.print_info(f"  Overall severity: {results['overall_severity']}")

                self.results['email_security'] = results
                self.mark_module_status('email_security', 'complete')

    def load_config(self) -> Dict[str, str]:
            """Load configuration from file"""
            default_config = {
                'github_token': '',
                'shodan_api_key': '',
                'censys_api_id': '',
                'censys_api_secret': '',
                'hibp_api_key': '',
                'linkedin_cookies': ''
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
                    # Ensure we're saving all keys including linkedin_cookies
                    config_to_save = {
                        'github_token': self.config.get('github_token', ''),
                        'shodan_api_key': self.config.get('shodan_api_key', ''),
                        'censys_api_id': self.config.get('censys_api_id', ''),
                        'censys_api_secret': self.config.get('censys_api_secret', ''),
                        'hibp_api_key': self.config.get('hibp_api_key', ''),
                        'linkedin_cookies': self.config.get('linkedin_cookies', '')
                    }

                    with open(self.config_file, 'w') as f:
                        json.dump(config_to_save, f, indent=2)

                    # Secure the config file - owner read/write only
                    self.config_file.chmod(0o600)

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
                    # Validate existing token
                    self.print_info("Validating existing GitHub token...")
                    if self._validate_api_token('github'):
                        self.print_success("GitHub token is valid")
                    else:
                        if self._handle_invalid_token('github'):
                            updated = True

                print("")

                # LinkedIn Cookies
                print("="*80)
                print("LINKEDIN CONFIGURATION")
                print("="*80)

                if not self.config.get('linkedin_cookies'):
                    print("[*] LinkedIn Session Cookies (for employee enumeration)")
                    print("    1. Open LinkedIn in your browser and log in")
                    print("    2. Open Developer Tools (F12) -> Network tab")
                    print("    3. Refresh the page, click any linkedin.com request")
                    print("    4. In Request Headers, find 'Cookie:' and copy the ENTIRE value")
                    cookies = input("    Enter full LinkedIn cookie string (or press Enter to skip): ").strip()
                    if cookies:
                        self.config['linkedin_cookies'] = cookies
                        # Validate the cookies
                        self.print_info("Validating LinkedIn cookies...")
                        if self._validate_api_token('linkedin'):
                            self.print_success("LinkedIn cookies validated and saved")
                            updated = True
                        else:
                            self.print_error("LinkedIn cookies are invalid")
                            self.config['linkedin_cookies'] = ''
                    else:
                        self.print_info("Skipping LinkedIn - employee enumeration will be skipped")
                else:
                    # Validate existing cookies
                    self.print_info("Validating existing LinkedIn cookies...")
                    if self._validate_api_token('linkedin'):
                        self.print_success("LinkedIn cookies are valid")
                    else:
                        if self._handle_invalid_token('linkedin'):
                            updated = True

                print("")

                # HIBP API Key
                if not self.config.get('hibp_api_key'):
                    print("[*] HIBP API Key (for breach data - optional but recommended)")
                    print("    Get a key at: https://haveibeenpwned.com/API/Key")
                    key = input("    Enter HIBP API key (or press Enter to skip): ").strip()
                    if key:
                        self.config['hibp_api_key'] = key
                        updated = True
                        self.print_success("HIBP API key configured")
                    else:
                        self.print_info("Skipping HIBP API key - breach checks may be limited")
                else:
                    self.print_success("HIBP API key already configured")

                print("")

                # Shodan API Key
                if not self.config.get('shodan_api_key'):
                    print("[*] Shodan API Key (for infrastructure reconnaissance - optional)")
                    print("    Register at: https://account.shodan.io/register")
                    key = input("    Enter Shodan API key (or press Enter to skip): ").strip()
                    if key:
                        self.config['shodan_api_key'] = key
                        updated = True
                        self.print_success("Shodan API key configured")
                    else:
                        self.print_info("Skipping Shodan API key")
                else:
                    self.print_success("Shodan API key already configured")

                print("="*80 + "\n")

                # Save if anything was updated
                if updated:
                    self.save_config()

    def _validate_api_token(self, service: str) -> bool:
            """Validate API token for a service. Returns True if valid, False if invalid."""

            if service == 'github':
                token = self.config.get('github_token', '')
                if not token:
                    return False

                try:
                    response = requests.get(
                        'https://api.github.com/user',
                        headers={'Authorization': f'token {token}'},
                        timeout=10
                    )

                    if response.status_code == 200:
                        return True
                    elif response.status_code in [401, 403]:
                        return False
                    else:
                        return True  # Might be rate limited, try anyway

                except Exception:
                    return True  # Network issue, try anyway

            elif service == 'shodan':
                key = self.config.get('shodan_api_key', '')
                if not key:
                    return False

                try:
                    response = requests.get(
                        f'https://api.shodan.io/api-info?key={key}',
                        timeout=10
                    )

                    if response.status_code == 200:
                        return True
                    elif response.status_code in [401, 403]:
                        return False
                    else:
                        return True

                except Exception:
                    return True

            elif service == 'hibp':
                key = self.config.get('hibp_api_key', '')
                if not key:
                    return False

                try:
                    response = requests.get(
                        'https://haveibeenpwned.com/api/v3/subscription/status',
                        headers={'hibp-api-key': key},
                        timeout=10
                    )

                    if response.status_code == 200:
                        return True
                    elif response.status_code in [401, 403]:
                        return False
                    else:
                        return True

                except Exception:
                    return True

            elif service == 'linkedin':
                cookies = self.config.get('linkedin_cookies', '')
                if not cookies:
                    return False

                try:
                    # Set up session with cookies
                    session = requests.Session()
                    for cookie in cookies.split('; '):
                        if '=' in cookie:
                            name, value = cookie.split('=', 1)
                            session.cookies.set(name, value, domain='.linkedin.com')

                    # Extract CSRF token
                    jsessionid = session.cookies.get('JSESSIONID', '').strip('"')
                    if not jsessionid:
                        return False

                    # Test with a simple API call
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                        'Accept': 'application/vnd.linkedin.normalized+json+2.1',
                        'Csrf-Token': jsessionid,
                        'X-Restli-Protocol-Version': '2.0.0',
                    }

                    response = session.get(
                        'https://www.linkedin.com/voyager/api/me',
                        headers=headers,
                        timeout=10
                    )

                    if response.status_code == 200:
                        return True
                    elif response.status_code in [401, 403]:
                        return False
                    else:
                        return True  # Might be temporary issue

                except Exception:
                    return True  # Network issue, try anyway

            return False

    def _handle_invalid_token(self, service: str) -> bool:
            """Handle invalid token - prompt for new one or skip. Returns True if valid token now available."""

            service_config = {
                'github': {'key': 'github_token', 'name': 'GitHub Personal Access Token', 'url': 'https://github.com/settings/tokens'},
                'shodan': {'key': 'shodan_api_key', 'name': 'Shodan API Key', 'url': 'https://account.shodan.io'},
                'hibp': {'key': 'hibp_api_key', 'name': 'HIBP API Key', 'url': 'https://haveibeenpwned.com/API/Key'},
                'linkedin': {'key': 'linkedin_cookies', 'name': 'LinkedIn Cookies', 'url': None}
            }

            config = service_config.get(service)
            if not config:
                return False

            self.print_error(f"{config['name']} is invalid or expired")
            print(f"\n    [n] Enter new {config['name']}")
            print(f"    [s] Skip {service} scanning")
            if config['url']:
                print(f"    Get a key at: {config['url']}")

            if service == 'linkedin':
                print(f"\n    To get LinkedIn cookies:")
                print(f"    1. Open LinkedIn in your browser and log in")
                print(f"    2. Open Developer Tools (F12) -> Network tab")
                print(f"    3. Refresh the page, click any linkedin.com request")
                print(f"    4. In Request Headers, find 'Cookie:' and copy the ENTIRE value")

            choice = input("\n    Selection [n/s]: ").strip().lower()

            if choice == 'n':
                new_token = input(f"    Enter new {config['name']}: ").strip()
                if new_token:
                    self.config[config['key']] = new_token
                    if self._validate_api_token(service):
                        self.print_success(f"{config['name']} validated successfully")
                        self.save_config()  # Save the new valid token
                        return True
                    else:
                        self.print_error(f"New {config['name']} is also invalid")
                        self.config[config['key']] = ''
                        return False
                else:
                    self.config[config['key']] = ''
                    return False
            else:
                self.print_info(f"Skipping {service} scanning")
                self.config[config['key']] = ''
                return False

    def post_dns_whois_lookup(self):
            """Perform WHOIS lookups on IPs discovered from DNS enumeration"""
            self.print_section("POST-DNS WHOIS LOOKUP")

            # Get resolved IPs from DNS enumeration
            resolved = self.results.get('dns_enumeration', {}).get('resolved', {})

            if not resolved:
                self.print_warning("No resolved IPs available for WHOIS lookup")
                return

            # Collect all unique IPs
            all_ips = set()
            for subdomain, ips in resolved.items():
                all_ips.update(ips)

            # Also add IPs from main domain DNS verification
            dns_verification = self.results.get('scope_validation', {}).get('dns_verification', {})
            if dns_verification.get('A'):
                all_ips.update(dns_verification['A'])

            self.print_info(f"Performing WHOIS lookups on {len(all_ips)} unique IP addresses...")

            whois_results = {}
            org_summary = {}  # Track organizations and their IPs

            for ip in sorted(all_ips):
                # Skip private/reserved IPs
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                        continue
                except:
                    continue

                try:
                    output = self.run_command(['whois', ip], timeout=30)
                    if output:
                        parsed = self._parse_whois(output)
                        whois_results[ip] = parsed

                        org = parsed.get('org', 'Unknown')
                        netrange = parsed.get('netrange', 'Unknown')

                        # Track by organization
                        if org not in org_summary:
                            org_summary[org] = {
                                'ips': [],
                                'netranges': set(),
                                'country': parsed.get('country', 'Unknown')
                            }
                        org_summary[org]['ips'].append(ip)
                        if netrange != 'Unknown':
                            org_summary[org]['netranges'].add(netrange)

                        self.print_success(f"{ip} - {org}")

                    time.sleep(0.5)  # Rate limiting

                except Exception as e:
                    self.print_error(f"WHOIS failed for {ip}: {e}")

            # Store results
            self.results['post_dns_whois'] = {
                'ip_lookups': whois_results,
                'organizations': {}
            }

            # Convert sets to lists for JSON serialization
            for org, data in org_summary.items():
                self.results['post_dns_whois']['organizations'][org] = {
                    'ips': data['ips'],
                    'netranges': list(data['netranges']),
                    'country': data['country'],
                    'ip_count': len(data['ips'])
                }

            # Print summary grouped by organization
            self.print_info(f"\nInfrastructure Summary by Organization:")
            sorted_orgs = sorted(org_summary.items(), key=lambda x: len(x[1]['ips']), reverse=True)

            for org, data in sorted_orgs:
                ip_count = len(data['ips'])
                self.print_info(f"\n  {org} ({ip_count} IP{'s' if ip_count > 1 else ''}):")
                for netrange in sorted(data['netranges']):
                    self.print_info(f"    Network: {netrange}")
                # Show sample IPs (first 5)
                for ip in data['ips'][:5]:
                    self.print_info(f"    - {ip}")
                if len(data['ips']) > 5:
                    self.print_info(f"    ... and {len(data['ips']) - 5} more")

            self.print_success(f"\nWHOIS lookup complete: {len(whois_results)} IPs across {len(org_summary)} organizations")

    def github_secret_scanning(self):
                """Search GitHub for leaked credentials and secrets with checkpoint support"""
                self.print_section("GITHUB SECRET SCANNING")

                if not self.config.get('github_token'):
                    self.print_warning("No GitHub token configured. Skipping GitHub scanning.")
                    self.print_info("Run with a configured token for enhanced secret detection")
                    return

                # Validate token before proceeding
                if not self._validate_api_token('github'):
                    if not self._handle_invalid_token('github'):
                        return

                # Get resume data if available
                resume_data = self.get_resume_data('github_secret_scanning')
                progress = resume_data.get('progress', {})

                github_findings = {
                    'repositories': progress.get('repositories', []),
                    'gists': progress.get('gists', []),
                    'issues': progress.get('issues', []),
                    'commits': progress.get('commits', []),
                    'historical_findings': progress.get('historical_findings', []),
                    'total_secrets_found': progress.get('total_secrets_found', 0)
                }

                # Track which queries/repos have been completed
                completed_code_queries = set(progress.get('completed_code_queries', []))
                completed_gist_queries = set(progress.get('completed_gist_queries', []))
                completed_issue_queries = set(progress.get('completed_issue_queries', []))
                completed_commit_queries = set(progress.get('completed_commit_queries', []))
                completed_history_repos = set(progress.get('completed_history_repos', []))
                candidate_repos = set(progress.get('candidate_repos', []))

                headers = {
                    'Authorization': f"token {self.config['github_token']}",
                    'Accept': 'application/vnd.github.v3+json'
                }

                # Define search queries
                search_queries = [
                    f'"{self.domain}"',
                    f'"{self.domain.replace(".", " ")}"',
                    f'"{self.domain.split(".")[0]}"',
                    f'{self.domain} password',
                    f'{self.domain} api_key',
                    f'{self.domain} secret',
                    f'{self.domain} credentials',
                    f'{self.domain} aws_access_key',
                    f'{self.domain} private_key'
                ]

                # Sensitive patterns to look for
                sensitive_patterns = self.SENSITIVE_PATTERNS

                # Create GitHub downloads directory
                github_download_dir = self.output_dir / 'github_secrets'
                github_download_dir.mkdir(parents=True, exist_ok=True)

                if completed_code_queries or completed_gist_queries or completed_issue_queries:
                    self.print_info(f"Resuming from checkpoint:")
                    self.print_info(f"  Code queries completed: {len(completed_code_queries)}/{len(search_queries)}")
                    self.print_info(f"  Gist queries completed: {len(completed_gist_queries)}/3")
                    self.print_info(f"  Issue queries completed: {len(completed_issue_queries)}/3")

                self.print_info(f"Searching GitHub with {len(search_queries)} queries...")

                # Track if we hit auth errors
                auth_failed = False

                # Search Code
                self.print_info("Searching code repositories...")
                for query in search_queries:
                    if query in completed_code_queries:
                        continue

                    if auth_failed:
                        break

                    try:
                        url = f"https://api.github.com/search/code?q={query}&per_page=10"
                        response = self.session.get(url, headers=headers, timeout=15)

                        if response.status_code == 200:
                            data = response.json()

                            for item in data.get('items', []):
                                repo_name = item.get('repository', {}).get('full_name')
                                if repo_name:
                                    candidate_repos.add(repo_name)
                                repo_finding = {
                                    'repository': repo_name,
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
                                                    is_real = self._is_real_secret(secret_type, matches, content)

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
                            if not self._handle_invalid_token('github'):
                                auth_failed = True
                                break
                            # Update headers with new token
                            headers['Authorization'] = f"token {self.config['github_token']}"

                        # Mark query as completed and checkpoint
                        completed_code_queries.add(query)
                        self.checkpoint('github_secret_scanning', 'completed_code_queries', list(completed_code_queries))
                        self.checkpoint('github_secret_scanning', 'repositories', github_findings['repositories'])
                        self.checkpoint('github_secret_scanning', 'candidate_repos', list(candidate_repos))
                        self.checkpoint('github_secret_scanning', 'total_secrets_found', github_findings['total_secrets_found'])

                        time.sleep(2)  # Rate limiting

                    except Exception as e:
                        self.print_error(f"Error searching code: {e}")

                # Search Gists
                if not auth_failed:
                    self.print_info("Searching gists...")
                    for query in search_queries[:3]:
                        if query in completed_gist_queries:
                            continue

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

                            elif response.status_code == 401:
                                self.print_error("GitHub token expired during gist search")
                                break

                            completed_gist_queries.add(query)
                            self.checkpoint('github_secret_scanning', 'completed_gist_queries', list(completed_gist_queries))
                            self.checkpoint('github_secret_scanning', 'gists', github_findings['gists'])

                            time.sleep(2)
                        except Exception as e:
                            self.print_error(f"Error searching gists: {e}")

                # Search Issues
                if not auth_failed:
                    self.print_info("Searching issues...")
                    for query in search_queries[:3]:
                        if query in completed_issue_queries:
                            continue

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
                                            is_real = self._is_real_secret(secret_type, matches, body)

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

                            elif response.status_code == 401:
                                self.print_error("GitHub token expired during issue search")
                                break

                            completed_issue_queries.add(query)
                            self.checkpoint('github_secret_scanning', 'completed_issue_queries', list(completed_issue_queries))
                            self.checkpoint('github_secret_scanning', 'issues', github_findings['issues'])

                            time.sleep(2)
                        except Exception as e:
                            self.print_error(f"Error searching issues: {e}")

                # Search Commits (commit message and authorship metadata)
                if not auth_failed:
                    self.print_info("Searching commits...")
                    commit_headers = dict(headers)
                    commit_headers['Accept'] = 'application/vnd.github+json'
                    for query in search_queries[:3]:
                        if query in completed_commit_queries:
                            continue

                        try:
                            url = f"https://api.github.com/search/commits?q={query}&per_page=10"
                            response = self.session.get(url, headers=commit_headers, timeout=15)

                            if response.status_code == 200:
                                data = response.json()
                                for item in data.get('items', []):
                                    commit = item.get('commit', {}) or {}
                                    author = commit.get('author', {}) or {}
                                    commit_finding = {
                                        'repository': item.get('repository', {}).get('full_name'),
                                        'sha': item.get('sha'),
                                        'message': (commit.get('message') or '')[:200],
                                        'author_name': author.get('name'),
                                        'author_email': author.get('email'),
                                        'date': author.get('date'),
                                        'html_url': item.get('html_url')
                                    }
                                    github_findings['commits'].append(commit_finding)

                                    # Harvest author email as actionable intel
                                    email = author.get('email')
                                    if email and '@' in email and not email.endswith('users.noreply.github.com'):
                                        emails = self.results.setdefault('email_addresses', [])
                                        if email not in emails:
                                            emails.append(email)

                            elif response.status_code == 401:
                                self.print_error("GitHub token expired during commit search")
                                break

                            completed_commit_queries.add(query)
                            self.checkpoint('github_secret_scanning', 'completed_commit_queries', list(completed_commit_queries))
                            self.checkpoint('github_secret_scanning', 'commits', github_findings['commits'])

                            time.sleep(2)
                        except Exception as e:
                            self.print_error(f"Error searching commits: {e}")

                # Commit history secret scan (targeted clone + scanner)
                if not auth_failed:
                    if not shutil.which('git'):
                        self.print_info("git not on PATH - skipping commit history scan")
                    else:
                        # Targeted selection: HEAD-hit repos plus owner-name matches
                        domain_label = self.domain.split('.')[0].lower()
                        client_label = re.sub(r'[^a-z0-9]', '', (self.client_name or '').lower())
                        targeted = set()
                        for r in github_findings['repositories']:
                            if r.get('repository'):
                                targeted.add(r['repository'])
                        for full_name in candidate_repos:
                            owner = full_name.split('/')[0].lower()
                            owner_norm = re.sub(r'[^a-z0-9]', '', owner)
                            if domain_label and domain_label in owner:
                                targeted.add(full_name)
                            elif client_label and len(client_label) >= 4 and client_label in owner_norm:
                                targeted.add(full_name)

                        # Apply caps: skip already scanned, forks, oversized; max 10
                        selected = []
                        for full_name in sorted(targeted):
                            if full_name in completed_history_repos:
                                continue
                            try:
                                meta = self.session.get(f"https://api.github.com/repos/{full_name}", headers=headers, timeout=10)
                                if meta.status_code != 200:
                                    continue
                                mj = meta.json()
                                if mj.get('fork'):
                                    continue
                                if mj.get('size', 0) > 51200:
                                    self.print_info(f"  Skipping {full_name} (>50MB)")
                                    continue
                            except Exception:
                                continue
                            selected.append(full_name)
                            if len(selected) >= 10:
                                break

                        if selected:
                            self.print_info(f"Scanning {len(selected)} repo(s) for historical secrets...")
                            tmp_root = tempfile.mkdtemp(prefix='qr_ghhist_')
                            try:
                                for full_name in selected:
                                    repo_findings = self._scan_repo_history(full_name, tmp_root, headers)
                                    if repo_findings:
                                        github_findings['historical_findings'].extend(repo_findings)
                                        github_findings['total_secrets_found'] += len(repo_findings)
                                        self.print_warning(f"Historical secrets in {full_name}: {len(repo_findings)}")
                                    completed_history_repos.add(full_name)
                                    self.checkpoint('github_secret_scanning', 'completed_history_repos', list(completed_history_repos))
                                    self.checkpoint('github_secret_scanning', 'historical_findings', github_findings['historical_findings'])
                                    self.checkpoint('github_secret_scanning', 'total_secrets_found', github_findings['total_secrets_found'])
                            finally:
                                shutil.rmtree(tmp_root, ignore_errors=True)
                        else:
                            self.print_info("No targeted repositories for history scan")

                # Store results
                self.results['github_secrets'] = github_findings

                # Summary
                self.print_info("\nGitHub Secret Scanning Summary:")
                self.print_info(f"  Repositories with secrets: {len(github_findings['repositories'])}")
                self.print_info(f"  Issues with secrets: {len(github_findings['issues'])}")
                self.print_info(f"  Commits matched: {len(github_findings['commits'])}")
                self.print_info(f"  Historical secrets: {len(github_findings['historical_findings'])}")
                self.print_info(f"  Total secrets found: {github_findings['total_secrets_found']}")

                if github_findings['total_secrets_found'] > 0:
                    self.print_warning(f"\n[!] Downloaded files with secrets to: {github_download_dir}")

    def _scan_repo_history(self, repo_full_name, tmp_root, headers):
                """Full-clone a repo and scan its complete commit history for secrets. Returns normalized findings."""
                findings = []
                safe = repo_full_name.replace('/', '_')
                repo_dir = Path(tmp_root) / safe
                token = self.config.get('github_token', '')
                clone_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"

                # Full clone (complete history). Token never logged.
                try:
                    proc = subprocess.run(
                        ['git', 'clone', '--quiet', clone_url, str(repo_dir)],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=300
                    )
                    if proc.returncode != 0:
                        self.print_error(f"  Clone failed for {repo_full_name}")
                        shutil.rmtree(repo_dir, ignore_errors=True)
                        return findings
                except subprocess.TimeoutExpired:
                    self.print_error(f"  Clone timed out for {repo_full_name}")
                    shutil.rmtree(repo_dir, ignore_errors=True)
                    return findings
                except Exception as e:
                    self.print_error(f"  Clone error for {repo_full_name}: {e}")
                    return findings

                try:
                    findings = self._walk_history_for_secrets(repo_full_name, repo_dir)
                finally:
                    shutil.rmtree(repo_dir, ignore_errors=True)

                return findings

    def _walk_history_for_secrets(self, repo_full_name, repo_dir):
                """Walk full commit history via git log and detect secrets in added lines using shared patterns."""
                def mask(s):
                    s = s or ''
                    if len(s) <= 8:
                        return '*' * len(s)
                    return f"{s[:4]}{'*' * (len(s) - 8)}{s[-4:]}"

                findings = []
                marker = '__COMMIT__'
                fmt = f"{marker}%x1f%H%x1f%an%x1f%aI"

                cur_commit = cur_author = cur_date = None
                cur_file = None
                added = []

                def flush():
                    if not cur_file or not added:
                        return
                    blob = '\n'.join(added)
                    for secret_type, pattern in self.SENSITIVE_PATTERNS.items():
                        try:
                            matches = re.findall(pattern, blob, re.IGNORECASE)
                        except Exception:
                            continue
                        if matches and self._is_real_secret(secret_type, matches, blob):
                            first = matches[0]
                            if isinstance(first, tuple):
                                first = next((x for x in first if x), '')
                            findings.append({
                                'repository': repo_full_name,
                                'commit': cur_commit,
                                'file': cur_file,
                                'rule': secret_type,
                                'secret': mask(first),
                                'date': cur_date,
                                'author': cur_author,
                                'email': None
                            })

                try:
                    proc = subprocess.Popen(
                        ['git', '-C', str(repo_dir), 'log', '--all', '-p', '-U0',
                         f"--format={fmt}", '--no-color'],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, text=True, errors='ignore'
                    )
                except Exception as e:
                    self.print_error(f"  History walk error for {repo_full_name}: {e}")
                    return findings

                try:
                    for line in proc.stdout:
                        line = line.rstrip('\n')
                        if line.startswith(marker):
                            flush()
                            added = []
                            parts = line.split('\x1f')
                            cur_commit = parts[1] if len(parts) > 1 else None
                            cur_author = parts[2] if len(parts) > 2 else None
                            cur_date = parts[3] if len(parts) > 3 else None
                            cur_file = None
                            continue
                        if line.startswith('diff --git'):
                            flush()
                            added = []
                            cur_file = None
                            continue
                        if line.startswith('+++ b/'):
                            cur_file = line[6:].strip()
                            continue
                        if line.startswith('+') and not line.startswith('+++'):
                            added.append(line[1:])
                    flush()
                finally:
                    try:
                        proc.stdout.close()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=600)
                    except Exception:
                        proc.kill()

                return findings

    def linkedin_enumeration(self):
                        """LinkedIn intelligence gathering using authenticated session with checkpoint support and human-like delays"""
                        self.print_section("LinkedIn Information Gathering")

                        # Get resume data if available
                        resume_data = self.get_resume_data('linkedin_enumeration')
                        progress = resume_data.get('progress', {})

                        linkedin_intel = {
                            'company_info': progress.get('company_info', {}),
                            'employees': progress.get('employees', [])
                        }

                        # Determine delay mode from args (default: normal)
                        mode = getattr(self.args, 'linkedin_mode', 'normal') if hasattr(self, 'args') else 'normal'

                        # Delay profiles
                        delay_profiles = {
                            'fast': {
                                'page_min': 4, 'page_max': 7,
                                'long_pause_min': 0, 'long_pause_max': 0,
                                'long_pause_prob': 0.0,
                                'company_break_min': 3, 'company_break_max': 5,
                                'session_cap': 200
                            },
                            'normal': {
                                'page_min': 7, 'page_max': 17,
                                'long_pause_min': 30, 'long_pause_max': 60,
                                'long_pause_prob': 0.18,
                                'company_break_min': 60, 'company_break_max': 120,
                                'session_cap': 50
                            },
                            'paranoid': {
                                'page_min': 20, 'page_max': 40,
                                'long_pause_min': 90, 'long_pause_max': 180,
                                'long_pause_prob': 0.30,
                                'company_break_min': 180, 'company_break_max': 300,
                                'session_cap': 30
                            }
                        }
                        profile = delay_profiles.get(mode, delay_profiles['normal'])
                        self.print_info(f"LinkedIn delay mode: {mode} (session cap: {profile['session_cap']} API calls)")

                        # Session-level tracking
                        api_call_count = 0
                        rate_limit_triggered = False
                        rate_limit_reason = ''
                        last_results_were_empty = False

                        # Check if LinkedIn cookies are configured
                        if not self.config.get('linkedin_cookies'):
                            self.print_warning("No LinkedIn cookies configured.")
                            print("\n    [n] Enter LinkedIn cookies now")
                            print("    [s] Skip LinkedIn enumeration")
                            choice = input("\n    Selection [n/s]: ").strip().lower()

                            if choice == 'n':
                                print("\n    To get LinkedIn cookies:")
                                print("    1. Open LinkedIn in your browser and log in")
                                print("    2. Open Developer Tools (F12) -> Network tab")
                                print("    3. Refresh the page, click any linkedin.com request")
                                print("    4. In Request Headers, find 'Cookie:' and copy the ENTIRE value")
                                cookies = input("\n    Enter full LinkedIn cookie string: ").strip()
                                if cookies:
                                    self.config['linkedin_cookies'] = cookies
                                    if self._validate_api_token('linkedin'):
                                        self.print_success("LinkedIn cookies validated and saved")
                                        self.save_config()
                                    else:
                                        self.print_error("LinkedIn cookies are invalid")
                                        self.config['linkedin_cookies'] = ''
                                        return
                                else:
                                    self.print_info("Skipping LinkedIn enumeration")
                                    return
                            else:
                                self.print_info("Skipping LinkedIn enumeration")
                                return

                        # Validate existing cookies
                        if not self._validate_api_token('linkedin'):
                            if not self._handle_invalid_token('linkedin'):
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
                        page_size = 10

                        # =====================================================================
                        # SEARCH 1: Find companies (with pagination)
                        # =====================================================================
                        all_companies = linkedin_intel['company_info'].get('companies', [])
                        company_search_complete = progress.get('company_search_complete', False)

                        if not company_search_complete:
                            self.print_info(f"\n[1/2] Searching for companies: {search_term}")

                            start = progress.get('company_search_start', 0)

                            while start < max_company_results:
                                # Check session cap
                                if api_call_count >= profile['session_cap']:
                                    rate_limit_triggered = True
                                    rate_limit_reason = f"Session cap reached ({profile['session_cap']} API calls)"
                                    break

                                company_search_url = f"https://www.linkedin.com/voyager/api/voyagerSearchDashClusters?decorationId=com.linkedin.voyager.dash.deco.search.SearchClusterCollection-174&origin=SWITCH_SEARCH_VERTICAL&q=all&query=(keywords:{encoded_term},flagshipSearchIntent:SEARCH_SRP,queryParameters:(resultType:List(COMPANIES)),includeFiltersInResponse:false)&start={start}"

                                try:
                                    response = linkedin_session.get(company_search_url, headers=api_headers, timeout=15)
                                    api_call_count += 1

                                    # Rate-limit detection
                                    if response.status_code == 429:
                                        rate_limit_triggered = True
                                        rate_limit_reason = "HTTP 429 (Too Many Requests)"
                                        break
                                    if response.status_code == 999:
                                        rate_limit_triggered = True
                                        rate_limit_reason = "HTTP 999 (LinkedIn anti-bot)"
                                        break
                                    if response.status_code in [401, 403]:
                                        rate_limit_triggered = True
                                        rate_limit_reason = f"HTTP {response.status_code} (auth invalidated)"
                                        break

                                    # Detect challenge/login redirect pages
                                    if 'challenge' in response.url.lower() or 'authwall' in response.url.lower() or 'login' in response.url.lower():
                                        rate_limit_triggered = True
                                        rate_limit_reason = f"Redirected to {response.url}"
                                        break

                                    if response.status_code != 200:
                                        self.print_warning(f"API returned status {response.status_code}")
                                        break

                                    data = response.json()
                                    included = data.get('included', [])

                                    if not included:
                                        # Two consecutive empty after data = likely soft-limited
                                        if last_results_were_empty and len(all_companies) > 0:
                                            rate_limit_triggered = True
                                            rate_limit_reason = "Consecutive empty results after prior data"
                                        break

                                    last_results_were_empty = False
                                    page_companies = []

                                    # Extract all company IDs from response for lookup
                                    all_company_ids = {}  # slug -> company_id
                                    raw_text = json.dumps(data)

                                    # First pass: build a map of entity URNs to company data
                                    company_map = {}
                                    for item in included:
                                        item_type = item.get('$type', '')
                                        entity_urn = item.get('entityUrn', '')

                                        if 'Company' in item_type or 'Organization' in item_type:
                                            name = item.get('name', '')
                                            universal_name = item.get('universalName', '')

                                            # Extract numeric company ID from entity_urn
                                            company_id = ''
                                            if entity_urn:
                                                match = re.search(r'company:(\d+)', entity_urn)
                                                if match:
                                                    company_id = match.group(1)
                                                    if universal_name:
                                                        all_company_ids[universal_name] = company_id

                                            if name and entity_urn:
                                                company_map[entity_urn] = {
                                                    'name': name,
                                                    'slug': universal_name,
                                                    'url': f"https://www.linkedin.com/company/{universal_name}" if universal_name else '',
                                                    'entity_urn': entity_urn,
                                                    'company_id': company_id
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

                                                    # Look up company_id from our collected data
                                                    company_id = all_company_ids.get(slug, '')

                                                    # Also check company_map by slug
                                                    if not company_id:
                                                        for urn, comp in company_map.items():
                                                            if comp.get('slug') == slug and comp.get('company_id'):
                                                                company_id = comp['company_id']
                                                                break

                                                    if not any(c['slug'] == slug for c in page_companies):
                                                        page_companies.append({
                                                            'name': text,
                                                            'slug': slug,
                                                            'url': f"https://www.linkedin.com/company/{slug}",
                                                            'company_id': company_id
                                                        })

                                        tracking = item.get('trackingUrn', '')
                                        if 'company:' in tracking:
                                            match = re.search(r'company:(\d+)', tracking)
                                            if match:
                                                company_id = match.group(1)
                                                for urn, comp in company_map.items():
                                                    if comp.get('company_id') == company_id and not any(c['slug'] == comp['slug'] for c in page_companies):
                                                        page_companies.append(comp)

                                    for urn, comp in company_map.items():
                                        if not any(c['slug'] == comp['slug'] for c in page_companies) and comp['slug']:
                                            page_companies.append(comp)

                                    if not page_companies:
                                        slug_matches = re.findall(r'"universalName":\s*"([^"]+)"', raw_text)
                                        name_matches = re.findall(r'"name":\s*"([^"]{3,60})"', raw_text)

                                        for i, slug in enumerate(slug_matches):
                                            if slug and not any(c['slug'] == slug for c in page_companies):
                                                name = name_matches[i] if i < len(name_matches) else slug
                                                company_id = all_company_ids.get(slug, '')
                                                page_companies.append({
                                                    'name': name,
                                                    'slug': slug,
                                                    'url': f"https://www.linkedin.com/company/{slug}",
                                                    'company_id': company_id
                                                })

                                    new_count = 0
                                    for comp in page_companies:
                                        if not any(c['slug'] == comp['slug'] and c['name'] == comp['name'] for c in all_companies):
                                            all_companies.append(comp)
                                            new_count += 1

                                    self.print_info(f"  Page {start // page_size + 1}: Found {new_count} new companies (API calls: {api_call_count})")

                                    if new_count == 0:
                                        break

                                    start += page_size

                                    # Checkpoint after each page
                                    self.checkpoint('linkedin_enumeration', 'company_search_start', start)
                                    self.checkpoint('linkedin_enumeration', 'company_info', {'companies': all_companies})

                                    # Per-page delay with jitter
                                    delay = random.uniform(profile['page_min'], profile['page_max'])

                                    # Occasional long pause
                                    if profile['long_pause_prob'] > 0 and random.random() < profile['long_pause_prob']:
                                        long_pause = random.uniform(profile['long_pause_min'], profile['long_pause_max'])
                                        self.print_info(f"  (Long read pause: {long_pause:.0f}s)")
                                        time.sleep(long_pause)
                                    else:
                                        time.sleep(delay)

                                except Exception as e:
                                    self.print_error(f"Error fetching companies: {e}")
                                    break

                            # Mark company search as complete if not rate-limited
                            if not rate_limit_triggered:
                                self.checkpoint('linkedin_enumeration', 'company_search_complete', True)

                                # Filter to only companies containing the target name
                                target_lower = search_term.lower()
                                unfiltered_count = len(all_companies)
                                all_companies = [c for c in all_companies if target_lower in c['name'].lower()]

                                if len(all_companies) < unfiltered_count:
                                    self.print_info(f"Filtered {unfiltered_count} companies to {len(all_companies)} matching '{search_term}'")

                                self.checkpoint('linkedin_enumeration', 'company_info', {'companies': all_companies})

                        # Bail early if rate limited
                        if rate_limit_triggered:
                            self._linkedin_finalize(linkedin_intel, all_companies, api_call_count, rate_limit_reason)
                            return

                        if all_companies:
                            self.print_success(f"Found {len(all_companies)} total companies:")
                            for company in all_companies:
                                self.print_info(f"  - {company['name']}")
                                if company.get('url'):
                                    self.print_info(f"    {company['url']}")

                            # Company selection if more than one found and not resuming with selection
                            selected_companies = progress.get('selected_companies')

                            if selected_companies is None and len(all_companies) > 1:
                                print("\n" + "="*80)
                                print("COMPANY SELECTION")
                                print("="*80)
                                print("Multiple companies found. Select target companies:")
                                print("  [a] All companies")
                                print("  [#] Single company by number")
                                print("  [#,#,#] Multiple companies by numbers (comma-separated)")
                                print()

                                for idx, company in enumerate(all_companies, 1):
                                    print(f"  [{idx}] {company['name']}")
                                    if company.get('url'):
                                        print(f"      {company['url']}")

                                print()
                                selection = input("Enter selection (or press Enter for all): ").strip().lower()

                                if selection == '' or selection == 'a':
                                    selected_companies = all_companies
                                    self.print_info("Using all companies")
                                else:
                                    try:
                                        indices = [int(x.strip()) for x in selection.split(',')]
                                        selected_companies = [all_companies[i-1] for i in indices if 0 < i <= len(all_companies)]
                                        if not selected_companies:
                                            self.print_warning("Invalid selection, using all companies")
                                            selected_companies = all_companies
                                        else:
                                            self.print_success(f"Selected {len(selected_companies)} company/companies:")
                                            for comp in selected_companies:
                                                self.print_info(f"  - {comp['name']}")
                                    except (ValueError, IndexError):
                                        self.print_warning("Invalid selection, using all companies")
                                        selected_companies = all_companies

                                # Save selection to checkpoint
                                self.checkpoint('linkedin_enumeration', 'selected_companies', selected_companies)
                                print("="*80)
                            elif selected_companies is None:
                                selected_companies = all_companies

                            all_companies = selected_companies
                            linkedin_intel['company_info'] = {'companies': all_companies}
                        else:
                            self.print_warning("No companies found")

                        # Brief pause before employee search starts (simulates "now searching for people")
                        time.sleep(random.uniform(3, 6))

                        # =====================================================================
                        # SEARCH 2: Find people at each selected company (using company ID filter)
                        # =====================================================================
                        all_employees = linkedin_intel.get('employees', [])
                        searched_companies = set(progress.get('searched_companies', []))

                        companies_to_search = all_companies if all_companies else []

                        if not companies_to_search:
                            self.print_warning("No companies to search for employees")
                            self._linkedin_finalize(linkedin_intel, all_companies, api_call_count, '')
                            return

                        for company_idx, company in enumerate(companies_to_search, 1):
                            # Check session cap before each company
                            if api_call_count >= profile['session_cap']:
                                rate_limit_triggered = True
                                rate_limit_reason = f"Session cap reached ({profile['session_cap']} API calls)"
                                break

                            company_name = company['name']
                            company_id = company.get('company_id', '')
                            company_slug = company.get('slug', '')

                            if company_name in searched_companies:
                                self.print_info(f"Skipping {company_name} (already searched)")
                                continue

                            self.print_info(f"\n[2/2] Searching for employees at: {company_name} ({company_idx}/{len(companies_to_search)})")

                            # If no company_id, look it up via company page
                            if not company_id and company_slug:
                                self.print_info(f"  Looking up company ID for {company_slug}...")
                                try:
                                    company_lookup_url = f"https://www.linkedin.com/voyager/api/organization/companies?decorationId=com.linkedin.voyager.deco.organization.web.WebFullCompanyMain-21&q=universalName&universalName={company_slug}"
                                    lookup_response = linkedin_session.get(company_lookup_url, headers=api_headers, timeout=15)
                                    api_call_count += 1

                                    if lookup_response.status_code in [429, 999, 401, 403]:
                                        rate_limit_triggered = True
                                        rate_limit_reason = f"HTTP {lookup_response.status_code} during company lookup"
                                        break

                                    if lookup_response.status_code == 200:
                                        lookup_data = lookup_response.json()
                                        elements = lookup_data.get('elements', [])
                                        if elements:
                                            entity_urn = elements[0].get('entityUrn', '')
                                            match = re.search(r'company:(\d+)', entity_urn)
                                            if match:
                                                company_id = match.group(1)
                                                company['company_id'] = company_id
                                                self.print_success(f"  Found company ID: {company_id}")

                                        if not company_id:
                                            raw_text = json.dumps(lookup_data)
                                            match = re.search(r'"companyId":\s*(\d+)', raw_text)
                                            if match:
                                                company_id = match.group(1)
                                                company['company_id'] = company_id
                                                self.print_success(f"  Found company ID: {company_id}")
                                            else:
                                                match = re.search(r'urn:li:(?:fsd_)?company:(\d+)', raw_text)
                                                if match:
                                                    company_id = match.group(1)
                                                    company['company_id'] = company_id
                                                    self.print_success(f"  Found company ID: {company_id}")

                                    time.sleep(random.uniform(2, 4))
                                except Exception as e:
                                    self.print_warning(f"  Company lookup failed: {e}")

                            if company_id:
                                self.print_info(f"  Using company ID filter: {company_id}")
                            else:
                                self.print_error(f"  Could not find company ID - skipping (keyword search is too inaccurate)")
                                searched_companies.add(company_name)
                                continue

                            start = 0
                            company_employees = []
                            max_per_company = max_employee_results // len(companies_to_search) if len(companies_to_search) > 1 else max_employee_results

                            while start < max_per_company:
                                # Check session cap
                                if api_call_count >= profile['session_cap']:
                                    rate_limit_triggered = True
                                    rate_limit_reason = f"Session cap reached ({profile['session_cap']} API calls)"
                                    break

                                people_search_url = f"https://www.linkedin.com/voyager/api/voyagerSearchDashClusters?decorationId=com.linkedin.voyager.dash.deco.search.SearchClusterCollection-174&origin=SWITCH_SEARCH_VERTICAL&q=all&query=(flagshipSearchIntent:SEARCH_SRP,queryParameters:(currentCompany:List({company_id}),resultType:List(PEOPLE)),includeFiltersInResponse:false)&start={start}"

                                try:
                                    response = linkedin_session.get(people_search_url, headers=api_headers, timeout=15)
                                    api_call_count += 1

                                    # Rate-limit detection
                                    if response.status_code == 429:
                                        rate_limit_triggered = True
                                        rate_limit_reason = "HTTP 429 (Too Many Requests)"
                                        break
                                    if response.status_code == 999:
                                        rate_limit_triggered = True
                                        rate_limit_reason = "HTTP 999 (LinkedIn anti-bot)"
                                        break
                                    if response.status_code in [401, 403]:
                                        rate_limit_triggered = True
                                        rate_limit_reason = f"HTTP {response.status_code} (auth invalidated)"
                                        break

                                    # Detect challenge/login redirect pages
                                    if 'challenge' in response.url.lower() or 'authwall' in response.url.lower() or 'login' in response.url.lower():
                                        rate_limit_triggered = True
                                        rate_limit_reason = f"Redirected to {response.url}"
                                        break

                                    if response.status_code != 200:
                                        self.print_warning(f"API returned status {response.status_code}")
                                        break

                                    data = response.json()
                                    included = data.get('included', [])

                                    if not included:
                                        if last_results_were_empty and len(company_employees) > 0:
                                            rate_limit_triggered = True
                                            rate_limit_reason = "Consecutive empty results after prior data"
                                        break

                                    last_results_were_empty = False
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
                                                    'public_id': public_id,
                                                    'company': company_name
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
                                                            'public_id': public_id,
                                                            'company': company_name
                                                        }
                                                        if not any(e['public_id'] == public_id for e in page_employees if e.get('public_id')):
                                                            page_employees.append(emp)

                                    # Add from profile map
                                    for urn, profile_data in profile_map.items():
                                        if profile_data['public_id'] and not any(e.get('public_id') == profile_data['public_id'] for e in page_employees):
                                            page_employees.append(profile_data)

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
                                                    'public_id': public_id,
                                                    'company': company_name
                                                })

                                    new_count = 0
                                    for emp in page_employees:
                                        if not any(e.get('public_id') == emp.get('public_id') for e in company_employees if emp.get('public_id')):
                                            company_employees.append(emp)
                                            new_count += 1

                                    self.print_info(f"  Page {start // page_size + 1}: Found {new_count} new employees (total: {len(company_employees)}, API calls: {api_call_count})")

                                    if new_count == 0:
                                        break

                                    start += page_size

                                    # Per-page delay with jitter
                                    delay = random.uniform(profile['page_min'], profile['page_max'])

                                    # Occasional long pause
                                    if profile['long_pause_prob'] > 0 and random.random() < profile['long_pause_prob']:
                                        long_pause = random.uniform(profile['long_pause_min'], profile['long_pause_max'])
                                        self.print_info(f"  (Long read pause: {long_pause:.0f}s)")
                                        time.sleep(long_pause)
                                    else:
                                        time.sleep(delay)

                                except Exception as e:
                                    self.print_error(f"Error fetching people: {e}")
                                    break

                            # Add company employees to all_employees (avoid duplicates by public_id)
                            for emp in company_employees:
                                if not any(e.get('public_id') == emp.get('public_id') for e in all_employees if emp.get('public_id')):
                                    all_employees.append(emp)

                            # Mark company as searched and checkpoint
                            searched_companies.add(company_name)
                            self.checkpoint('linkedin_enumeration', 'searched_companies', list(searched_companies))
                            self.checkpoint('linkedin_enumeration', 'employees', all_employees)

                            # Bail early if rate limited
                            if rate_limit_triggered:
                                break

                            # Between-company break (only if more companies remain)
                            if company_idx < len(companies_to_search):
                                company_break = random.uniform(profile['company_break_min'], profile['company_break_max'])
                                self.print_info(f"  (Pausing {company_break:.0f}s before next company)")
                                time.sleep(company_break)

                        self.print_success(f"Found {len(all_employees)} total employees")

                        # =====================================================================
                        # Process and store results
                        # =====================================================================
                        if all_employees:
                            for emp in all_employees:
                                if emp not in linkedin_intel['employees']:
                                    linkedin_intel['employees'].append(emp)

                            self.print_info("\nEmployees found:")
                            for emp in linkedin_intel['employees']:
                                title_info = f" - {emp['title']}" if emp.get('title') and emp['title'] != 'Unknown' else ""
                                self.print_success(f"  {emp['name']}{title_info}")
                                if emp.get('profile_url'):
                                    self.print_info(f"    {emp['profile_url']}")
                        else:
                            self.print_warning("No employees found")

                        # Store results
                        linkedin_intel['employees'] = all_employees
                        self.results['linkedin_intel'] = linkedin_intel

                        # Finalize with summary
                        self._linkedin_finalize(linkedin_intel, all_companies, api_call_count, rate_limit_reason if rate_limit_triggered else '')

    def _linkedin_finalize(self, linkedin_intel, all_companies, api_call_count, rate_limit_reason):
            """Finalize LinkedIn enumeration with summary and rate-limit handling"""
            self.results['linkedin_intel'] = linkedin_intel

            self.print_info(f"\nLinkedIn Summary:")
            if linkedin_intel.get('company_info', {}).get('companies'):
                self.print_info(f"  Companies: {len(linkedin_intel['company_info']['companies'])}")
            self.print_info(f"  Employees: {len(linkedin_intel['employees'])}")
            self.print_info(f"  Total API calls: {api_call_count}")

            if rate_limit_reason:
                print("")
                self.print_warning("="*80)
                self.print_warning("LINKEDIN RATE LIMIT / DETECTION TRIGGERED")
                self.print_warning("="*80)
                self.print_warning(f"Trigger: {rate_limit_reason}")
                self.print_warning(f"API calls made before stopping: {api_call_count}")
                self.print_warning(f"Partial results saved to results['linkedin_intel']")
                self.print_warning("")
                self.print_warning("Recommendations before retrying:")
                self.print_warning("  1. Wait at least 1-2 hours before next run")
                self.print_warning("  2. Use a fresh cookie set from a different browser session")
                self.print_warning("  3. Consider switching to --linkedin-mode paranoid")
                self.print_warning("  4. Verify the LinkedIn account is not locked (log in via browser)")
                self.print_warning("="*80)

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

    def _parse_whois(self, whois_output: str, whois_type: str = 'ip') -> Dict[str, Any]:
            """Parse WHOIS output for IP or domain lookups"""
            result = {}

            if whois_type == 'ip':
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

            elif whois_type == 'domain':
                # Privacy detection keywords
                privacy_keywords = [
                    'privacy', 'redacted', 'protected', 'proxy', 'guard', 'withheld',
                    'whoisguard', 'contactprivacy', 'domainsbyproxy', 'perfect privacy',
                    'domains by proxy', 'private registration', 'data protected',
                    'not disclosed', 'identity protect', 'anonymize', 'whoisprivacy'
                ]

                privacy_email_domains = [
                    'privateregistration', 'privacyprotect', 'whoisprivacy',
                    'contactprivacy', 'domainsbyproxy', 'whoisguard', 'anonymize'
                ]

                whois_lower = whois_output.lower()
                result['privacy_protected'] = any(kw in whois_lower for kw in privacy_keywords)

                # Collected valid contact info
                result['emails'] = []
                result['addresses'] = []
                result['phones'] = []
                result['organizations'] = []

                for contact_type in ['Registrant', 'Admin', 'Tech']:
                    # Organization/Name
                    org_match = re.search(rf'{contact_type}\s*Organization:\s*(.+)', whois_output, re.IGNORECASE)
                    name_match = re.search(rf'{contact_type}\s*Name:\s*(.+)', whois_output, re.IGNORECASE)

                    org_or_name = ''
                    if org_match:
                        org_or_name = org_match.group(1).strip()
                    elif name_match:
                        org_or_name = name_match.group(1).strip()

                    # Skip if privacy service
                    if org_or_name and not any(kw in org_or_name.lower() for kw in privacy_keywords):
                        if org_or_name not in result['organizations']:
                            result['organizations'].append(org_or_name)

                    # Email
                    email_match = re.search(rf'{contact_type}\s*Email:\s*([^\s]+@[^\s]+)', whois_output, re.IGNORECASE)
                    if email_match:
                        email = email_match.group(1).strip().lower()
                        local_part = email.split('@')[0]

                        # Filter privacy proxy emails (random strings or privacy domains)
                        is_random = re.match(r'^[a-z0-9]{8,}$', local_part) and not re.search(r'[aeiou]{2,}', local_part)
                        is_privacy_domain = any(pd in email for pd in privacy_email_domains)

                        if not is_random and not is_privacy_domain and email not in result['emails']:
                            result['emails'].append(email)

                    # Phone
                    phone_match = re.search(rf'{contact_type}\s*Phone:\s*(\+?[\d\.\-\s]+)', whois_output, re.IGNORECASE)
                    if phone_match:
                        phone = phone_match.group(1).strip()
                        if phone and len(phone) > 5 and phone not in result['phones']:
                            result['phones'].append(phone)

                    # Address
                    street_match = re.search(rf'{contact_type}\s*Street:\s*(.+)', whois_output, re.IGNORECASE)
                    city_match = re.search(rf'{contact_type}\s*City:\s*(.+)', whois_output, re.IGNORECASE)
                    state_match = re.search(rf'{contact_type}\s*State/Province:\s*(.+)', whois_output, re.IGNORECASE)
                    postal_match = re.search(rf'{contact_type}\s*Postal\s*Code:\s*(.+)', whois_output, re.IGNORECASE)
                    country_match = re.search(rf'{contact_type}\s*Country:\s*(.+)', whois_output, re.IGNORECASE)

                    if street_match and city_match:
                        street = street_match.group(1).strip()
                        city = city_match.group(1).strip()

                        # Filter privacy service addresses
                        privacy_addr_patterns = ['po box', 'p.o. box', 'care of', 'c/o', 'network solutions']
                        combined = f"{street} {city}".lower()

                        if not any(p in combined for p in privacy_addr_patterns) and not any(kw in combined for kw in privacy_keywords):
                            address = {
                                'street': street,
                                'city': city,
                                'state': state_match.group(1).strip() if state_match else '',
                                'postal_code': postal_match.group(1).strip() if postal_match else '',
                                'country': country_match.group(1).strip() if country_match else '',
                                'source': contact_type.lower()
                            }

                            # Dedupe by street+city
                            addr_key = f"{street}|{city}".lower()
                            if not any(f"{a['street']}|{a['city']}".lower() == addr_key for a in result['addresses']):
                                result['addresses'].append(address)

                # Domain metadata
                domain_match = re.search(r'Domain\s*Name:\s*(\S+)', whois_output, re.IGNORECASE)
                if domain_match:
                    result['domain_name'] = domain_match.group(1).strip()

                created_match = re.search(r'Creation\s*Date:\s*(.+)', whois_output, re.IGNORECASE)
                if created_match:
                    result['created'] = created_match.group(1).strip()

                expires_match = re.search(r'(?:Expir.*Date|Registrar Registration Expiration Date):\s*(.+)', whois_output, re.IGNORECASE)
                if expires_match:
                    result['expires'] = expires_match.group(1).strip()

                ns_matches = re.findall(r'Name\s*Server:\s*(\S+)', whois_output, re.IGNORECASE)
                if ns_matches:
                    result['name_servers'] = [ns.lower() for ns in ns_matches]

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

            # Get IPs from DNS resolution
            dns_records = self.results.get('scope_validation', {}).get('dns_verification', {})
            known_ips = dns_records.get('A', [])

            # Also check resolved subdomains
            resolved_subdomains = self.results.get('dns_enumeration', {}).get('resolved', {})
            for subdomain, ips in resolved_subdomains.items():
                known_ips.extend(ips)

            known_ips = list(set(known_ips))  # Remove duplicates

            # Filter out private/reserved IPs
            public_ips = []
            for ip in known_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_reserved:
                        public_ips.append(ip)
                except:
                    pass

            if not public_ips:
                self.print_warning("No public IPs discovered for ASN lookup")
                return

            self.print_info(f"Looking up ASN information for {len(public_ips)} discovered IP addresses...")

            # Track unique ASNs and which IPs belong to them
            asn_to_ips = {}

            for ip in public_ips[:50]:  # Limit to first 50 to avoid excessive queries
                try:
                    asn_info = self._lookup_asn_cymru(ip)

                    if asn_info:
                        asn_num = asn_info['asn']

                        if asn_num not in asn_to_ips:
                            asn_to_ips[asn_num] = {
                                'info': asn_info,
                                'ips': [],
                                'prefixes': set()
                            }

                        asn_to_ips[asn_num]['ips'].append(ip)
                        if asn_info.get('prefix'):
                            asn_to_ips[asn_num]['prefixes'].add(asn_info['prefix'])

                    time.sleep(0.5)  # Rate limiting

                except Exception as e:
                    self.print_error(f"Error looking up ASN for {ip}: {e}")

            # Display results grouped by ASN
            self.print_info(f"\nDiscovered {len(asn_to_ips)} unique ASN(s):\n")

            for asn_num, data in sorted(asn_to_ips.items()):
                info = data['info']
                ips = data['ips']
                prefixes = data['prefixes']

                self.print_success(f"AS{asn_num} - {info.get('owner', 'Unknown')}")
                if info.get('country'):
                    self.print_info(f"  Country: {info['country']}")
                self.print_info(f"  Registry: {info.get('registry', 'Unknown')}")
                self.print_info(f"  Discovered IPs ({len(ips)}):")
                for ip in ips[:10]:
                    self.print_info(f"    - {ip}")
                if len(ips) > 10:
                    self.print_info(f"    ... and {len(ips) - 10} more")

                self.print_info(f"  Announced Prefixes containing discovered IPs:")
                for prefix in sorted(prefixes):
                    self.print_info(f"    - {prefix}")

                # Add to results
                asn_entry = {
                    'asn': asn_num,
                    'owner': info.get('owner', 'Unknown'),
                    'country': info.get('country', 'Unknown'),
                    'registry': info.get('registry', 'Unknown'),
                    'discovered_ips': ips,
                    'source': 'dns_resolution'
                }

                if asn_entry not in asn_data['asn_numbers']:
                    asn_data['asn_numbers'].append(asn_entry)

                asn_data['organization_names'].add(info.get('owner', 'Unknown'))

                for prefix in prefixes:
                    asn_data['ip_ranges'].append({
                        'prefix': prefix,
                        'asn': asn_num,
                        'contains_discovered_ips': True,
                        'discovered_ips_in_prefix': [ip for ip in ips if self._ip_in_prefix(ip, prefix)]
                    })

                print()

            # Only fetch additional prefixes if IP ranges were explicitly provided
            if self.ip_ranges:
                self.print_info("Checking for additional prefixes within authorized scope...")

                for asn_num, data in asn_to_ips.items():
                    max_retries = 3
                    retry_count = 0
                    success = False

                    while retry_count < max_retries and not success:
                        try:
                            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
                            response = self.session.get(url, timeout=30)

                            if response.status_code == 200:
                                ripe_data = response.json()
                                prefixes = ripe_data.get('data', {}).get('prefixes', [])

                                in_scope_count = 0
                                for prefix in prefixes:
                                    prefix_str = prefix.get('prefix')
                                    if prefix_str and self._check_if_in_scope(prefix_str):
                                        in_scope_count += 1
                                        # Only add if not already tracked
                                        existing = [r for r in asn_data['ip_ranges'] if r['prefix'] == prefix_str]
                                        if not existing:
                                            asn_data['ip_ranges'].append({
                                                'prefix': prefix_str,
                                                'asn': asn_num,
                                                'in_scope': True,
                                                'contains_discovered_ips': False
                                            })
                                            self.print_info(f"  Additional in-scope prefix: {prefix_str} (AS{asn_num})")

                                success = True

                            time.sleep(2)

                        except requests.exceptions.Timeout:
                            retry_count += 1
                            if retry_count < max_retries:
                                time.sleep(2)
                        except Exception as e:
                            retry_count += 1
                            if retry_count < max_retries:
                                time.sleep(2)

            # Reverse DNS for related domains
            self.print_info("\nSearching for related domains via reverse DNS...")

            for ip in public_ips[:10]:  # Limit to first 10
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

            # Store results
            self.results['asn_data'] = {
                'asn_numbers': asn_data['asn_numbers'],
                'ip_ranges': asn_data['ip_ranges'],
                'organization_names': list(asn_data['organization_names']),
                'related_domains': asn_data['related_domains']
            }

            # Summary
            self.print_info(f"\nASN Enumeration Summary:")
            self.print_info(f"  Public IPs analyzed: {len(public_ips)}")
            self.print_info(f"  Unique ASNs discovered: {len(asn_to_ips)}")
            self.print_info(f"  IP prefixes identified: {len(asn_data['ip_ranges'])}")
            self.print_info(f"  Related domains found: {len(asn_data['related_domains'])}")

    def _ip_in_prefix(self, ip: str, prefix: str) -> bool:
        """Check if an IP is within a given prefix"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(prefix, strict=False)
            return ip_obj in network
        except:
            return False

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
                    """Perform DNS enumeration to discover subdomains with checkpoint support"""
                    self.print_section("DNS ENUMERATION")

                    # Get resume data if available
                    resume_data = self.get_resume_data('dns_enumeration')
                    progress = resume_data.get('progress', {})

                    subdomains = set()
                    ct_domains = set()
                    brute_domains = set()

                    # Restore previously discovered subdomains if resuming
                    if progress.get('ct_logs', {}).get('status') == 'complete':
                        ct_domains = set(progress['ct_logs'].get('domains', []))
                        self.print_info(f"Restored {len(ct_domains)} CT log domains from checkpoint")
                        subdomains.update(ct_domains)

                    if progress.get('bruteforce', {}).get('status') == 'complete':
                        brute_domains = set(progress['bruteforce'].get('domains', []))
                        self.print_info(f"Restored {len(brute_domains)} bruteforce domains from checkpoint")
                        subdomains.update(brute_domains)

                    # Method 1: Certificate Transparency Logs
                    if progress.get('ct_logs', {}).get('status') != 'complete':
                        self.print_info("Checking Certificate Transparency logs...")
                        ct_domains = set(self._check_certificate_transparency())
                        subdomains.update(ct_domains)
                        self.print_success(f"Found {len(ct_domains)} domains from CT logs")

                        # Checkpoint CT log results
                        self.checkpoint('dns_enumeration', 'ct_logs', {
                            'status': 'complete',
                            'domains': list(ct_domains),
                            'count': len(ct_domains)
                        })

                    # Method 2: DNS brute force with common names
                    if progress.get('bruteforce', {}).get('status') != 'complete':
                        self.print_info("Performing DNS brute force...")
                        brute_domains = set(self._dns_bruteforce())
                        subdomains.update(brute_domains)
                        self.print_success(f"Found {len(brute_domains)} domains from brute force")

                        # Checkpoint bruteforce results
                        self.checkpoint('dns_enumeration', 'bruteforce', {
                            'status': 'complete',
                            'domains': list(brute_domains),
                            'count': len(brute_domains)
                        })

                    # Resolve all discovered subdomains with checkpointing
                    self.print_info("Resolving discovered subdomains...")

                    # Get already resolved subdomains from checkpoint
                    resolved = {}
                    resolution_progress = progress.get('resolution', {})
                    if resolution_progress.get('resolved'):
                        resolved = resolution_progress['resolved']
                        self.print_info(f"Restored {len(resolved)} resolved subdomains from checkpoint")

                    # Determine which subdomains still need resolution
                    subdomains_to_resolve = sorted(subdomains - set(resolved.keys()))
                    total_to_resolve = len(subdomains_to_resolve)

                    if total_to_resolve > 0:
                        self.print_info(f"Resolving {total_to_resolve} remaining subdomains...")

                        checkpoint_interval = 50
                        completed_since_checkpoint = 0

                        for i, subdomain in enumerate(subdomains_to_resolve):
                            # Check shutdown signal
                            if getattr(self, '_shutdown_in_progress', False):
                                break

                            ips = self._resolve_domain(subdomain)
                            if ips:
                                resolved[subdomain] = ips

                                # Check if all IPs are internal/private
                                all_internal = True
                                for ip in ips:
                                    try:
                                        ip_obj = ipaddress.ip_address(ip)
                                        if not ip_obj.is_private and not ip_obj.is_loopback:
                                            all_internal = False
                                            break
                                    except:
                                        all_internal = False
                                        break

                                # Check if any IP is in authorized scope (only when -i was provided)
                                in_authorized_scope = False
                                if self.ip_ranges:
                                    for ip in ips:
                                        if self._is_ip_in_scope(ip):
                                            in_authorized_scope = True
                                            break

                                if in_authorized_scope:
                                    self.print_success(f"[{len(resolved)}/{len(subdomains)}] {subdomain} -> {', '.join(ips)} [IN AUTHORIZED SCOPE]")
                                elif all_internal:
                                    self.print_warning(f"[{len(resolved)}/{len(subdomains)}] {subdomain} -> {', '.join(ips)} [INTERNAL]")
                                else:
                                    self.print_success(f"[{len(resolved)}/{len(subdomains)}] {subdomain} -> {', '.join(ips)}")

                            completed_since_checkpoint += 1

                            # Checkpoint periodically
                            if completed_since_checkpoint >= checkpoint_interval:
                                self.checkpoint('dns_enumeration', 'resolution', {
                                    'resolved': resolved,
                                    'completed': len(resolved),
                                    'total': len(subdomains),
                                    'last_processed': subdomain
                                })
                                completed_since_checkpoint = 0

                        # Final checkpoint for resolution
                        self.checkpoint('dns_enumeration', 'resolution', {
                            'resolved': resolved,
                            'completed': len(resolved),
                            'total': len(subdomains),
                            'status': 'complete'
                        })

                    # =====================================================================
                    # Separate internal vs external resolved subdomains
                    # =====================================================================
                    resolved_internal = {}
                    resolved_external = {}

                    for subdomain, ips in resolved.items():
                        internal_ips = []
                        external_ips = []

                        for ip in ips:
                            try:
                                ip_obj = ipaddress.ip_address(ip)
                                if ip_obj.is_private or ip_obj.is_loopback:
                                    internal_ips.append(ip)
                                else:
                                    external_ips.append(ip)
                            except:
                                external_ips.append(ip)

                        if internal_ips and not external_ips:
                            resolved_internal[subdomain] = internal_ips
                        elif external_ips:
                            resolved_external[subdomain] = external_ips
                            if internal_ips:
                                # Has both - store in external but note internal IPs exist
                                resolved_internal[subdomain] = internal_ips

                    # =====================================================================
                    # Tier 1 classification: subdomains resolving into authorized IP scope
                    # =====================================================================
                    resolved_in_authorized_scope = {}

                    if self.ip_ranges:
                        for subdomain, ips in resolved.items():
                            in_scope_ips = []
                            matched_ranges = set()

                            for ip in ips:
                                if self._is_ip_in_scope(ip):
                                    in_scope_ips.append(ip)
                                    # Identify which authorized range matched (for reporting)
                                    for ip_range in self.ip_ranges:
                                        try:
                                            if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range, strict=False):
                                                matched_ranges.add(ip_range)
                                                break
                                        except (ValueError, TypeError):
                                            continue

                            if in_scope_ips:
                                resolved_in_authorized_scope[subdomain] = {
                                    'ips': in_scope_ips,
                                    'matched_ranges': sorted(matched_ranges)
                                }

                        if resolved_in_authorized_scope:
                            self.print_success(f"\nIdentified {len(resolved_in_authorized_scope)} subdomain(s) resolving into authorized IP scope")

                    # =====================================================================
                    # WHOIS lookups on resolved IPs (when no IP ranges provided)
                    # =====================================================================
                    whois_results = {}
                    org_summary = {}

                    if not self.ip_ranges and resolved_external:
                        self.print_info(f"\nPerforming WHOIS lookups on discovered external IPs...")

                        # Collect unique public IPs
                        all_ips = set()
                        for subdomain, ips in resolved_external.items():
                            all_ips.update(ips)

                        public_ips = []
                        for ip in all_ips:
                            try:
                                ip_obj = ipaddress.ip_address(ip)
                                if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_reserved:
                                    public_ips.append(ip)
                            except:
                                pass

                        self.print_info(f"Found {len(public_ips)} unique public IPs")

                        # Perform WHOIS lookups (limit to 50)
                        for ip in sorted(public_ips)[:50]:
                            try:
                                output = self.run_command(['whois', ip], timeout=30)
                                if output:
                                    parsed = self._parse_whois(output, whois_type='ip')
                                    whois_results[ip] = parsed

                                    org = parsed.get('org', 'Unknown')
                                    netrange = parsed.get('netrange', '')

                                    if org not in org_summary:
                                        org_summary[org] = {
                                            'ips': [],
                                            'netranges': set(),
                                            'country': parsed.get('country', 'Unknown')
                                        }
                                    org_summary[org]['ips'].append(ip)
                                    if netrange:
                                        org_summary[org]['netranges'].add(netrange)

                                time.sleep(0.5)

                            except Exception as e:
                                pass

                        # Print summary by organization
                        if org_summary:
                            self.print_info(f"\nInfrastructure by Organization:")
                            sorted_orgs = sorted(org_summary.items(), key=lambda x: len(x[1]['ips']), reverse=True)

                            for org, data in sorted_orgs:
                                ip_count = len(data['ips'])
                                self.print_success(f"  {org} ({ip_count} IP{'s' if ip_count > 1 else ''})")
                                for netrange in sorted(data['netranges']):
                                    self.print_info(f"    Network: {netrange}")

                    # Store results
                    self.results['dns_enumeration'] = {
                        'total_discovered': len(subdomains),
                        'ct_log_domains': sorted(list(ct_domains)),
                        'bruteforce_domains': sorted(list(brute_domains)),
                        'all_discovered': sorted(list(subdomains)),
                        'resolved': resolved,
                        'resolved_external': resolved_external,
                        'resolved_internal': resolved_internal,
                        'resolved_in_authorized_scope': resolved_in_authorized_scope,
                        'unresolved': sorted(list(subdomains - set(resolved.keys()))),
                        'whois_lookups': whois_results,
                        'infrastructure_summary': {org: {'ips': data['ips'], 'netranges': list(data['netranges']), 'country': data['country']} for org, data in org_summary.items()}
                    }

                    self.print_info(f"\nTotal unique subdomains discovered: {len(subdomains)}")
                    self.print_info(f"  - From CT logs: {len(ct_domains)}")
                    self.print_info(f"  - From brute force: {len(brute_domains)}")
                    self.print_info(f"Successfully resolved: {len(resolved)}")
                    self.print_info(f"  - External (public IPs): {len(resolved_external)}")
                    self.print_info(f"  - Internal (private IPs): {len(resolved_internal)}")
                    if resolved_in_authorized_scope:
                        self.print_info(f"  - In authorized IP scope: {len(resolved_in_authorized_scope)}")
                    if whois_results:
                        self.print_info(f"WHOIS lookups completed: {len(whois_results)} IPs across {len(org_summary)} organizations")

    def subdomain_takeover_detection(self):
                """Check for subdomain takeover vulnerabilities with validation"""
                self.print_section("SUBDOMAIN TAKEOVER DETECTION")

                # Fingerprints for various services that can be taken over
                takeover_fingerprints = {
                    'github': {
                        'cname': ['github.io', 'github.map.fastly.net'],
                        'response': ['There isn\'t a GitHub Pages site here', 'For root URLs (like http://example.com/) you must provide an index.html file'],
                        'service': 'GitHub Pages',
                        'validation_url': '/.well-known/security.txt'
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
                    'shopify': {
                        'cname': ['myshopify.com'],
                        'response': ['Sorry, this shop is currently unavailable', 'Only one step left'],
                        'service': 'Shopify',
                        'validation_url': None
                    },
                    'fastly': {
                        'cname': ['fastly.net'],
                        'response': ['Fastly error: unknown domain'],
                        'service': 'Fastly',
                        'validation_url': None
                    },
                    'pantheon': {
                        'cname': ['pantheonsite.io'],
                        'response': ['404 error unknown site', 'The gods are wise'],
                        'service': 'Pantheon',
                        'validation_url': None
                    },
                    'tumblr': {
                        'cname': ['domains.tumblr.com'],
                        'response': ['There\'s nothing here', 'Whatever you were looking for doesn\'t currently exist'],
                        'service': 'Tumblr',
                        'validation_url': None
                    },
                }

                # Get resume data
                resume_data = self.get_resume_data('subdomain_takeover_detection')
                progress = resume_data.get('progress', {})

                vulnerable_subdomains = progress.get('vulnerable_subdomains', [])
                checked_subdomains = set(progress.get('checked_subdomains', []))

                # Get all resolved subdomains
                resolved_subdomains = self.results.get('dns_enumeration', {}).get('resolved', {})

                if not resolved_subdomains:
                    self.print_warning("No subdomains to check. Run DNS enumeration first.")
                    return

                # Filter out already checked
                subdomains_to_check = {k: v for k, v in resolved_subdomains.items() if k not in checked_subdomains}
                total = len(resolved_subdomains)
                already_done = len(checked_subdomains)
                remaining = len(subdomains_to_check)

                if already_done > 0:
                    self.print_info(f"Resuming: {already_done}/{total} already checked, {remaining} remaining")

                if remaining == 0:
                    self.print_info("All subdomains already checked")
                    self.results['subdomain_takeover'] = vulnerable_subdomains
                    return

                self.print_info(f"Checking {remaining} subdomains for takeover vulnerabilities...")

                def validate_takeover(subdomain: str, cname: str, fingerprint: dict) -> dict:
                    """Validate if a subdomain takeover is actually exploitable"""
                    result = {
                        'is_vulnerable': False,
                        'confidence': 'LOW',
                        'evidence': [],
                        'subdomain': subdomain,
                        'cname': cname,
                        'service': fingerprint['service']
                    }

                    response_patterns = fingerprint['response']
                    validation_url = fingerprint.get('validation_url')

                    for protocol in ['https', 'http']:
                        try:
                            url = f"{protocol}://{subdomain}"
                            response = requests.get(url, timeout=5, allow_redirects=True, verify=False,
                                                headers={'User-Agent': 'Mozilla/5.0'})

                            response_text = response.text.lower()
                            status_code = response.status_code

                            # Check for specific error patterns
                            pattern_matches = 0
                            for pattern in response_patterns:
                                if pattern.lower() in response_text:
                                    pattern_matches += 1
                                    result['evidence'].append(f"Pattern matched: {pattern}")

                            # Must match at least one pattern
                            if pattern_matches == 0:
                                continue

                            # Validation scoring
                            validation_score = 0

                            # Check 1: CNAME points to service (HIGH confidence indicator)
                            if cname:
                                validation_score += 2
                                result['evidence'].append(f"CNAME: {cname}")

                            # Check 2: 404 status code
                            if status_code == 404:
                                validation_score += 1
                                result['evidence'].append(f"Status: 404")

                            # Check 3: Response size (real sites are usually larger)
                            if len(response.content) < 5000:
                                validation_score += 1
                                result['evidence'].append(f"Small response: {len(response.content)} bytes")

                            # Check 4: No active content (no scripts, forms)
                            if '<script' not in response_text and '<form' not in response_text:
                                validation_score += 1
                                result['evidence'].append("No active content")

                            # Check 5: Service-specific validation
                            if validation_url:
                                try:
                                    val_response = requests.get(f"{url}{validation_url}", timeout=3, verify=False,
                                                            headers={'User-Agent': 'Mozilla/5.0'})
                                    if val_response.status_code == 404:
                                        validation_score += 2
                                        result['evidence'].append(f"Validation URL 404: {validation_url}")
                                except:
                                    pass

                            # Determine confidence based on validation score
                            if validation_score >= 5:
                                result['confidence'] = 'HIGH'
                                result['is_vulnerable'] = True
                            elif validation_score >= 3:
                                result['confidence'] = 'MEDIUM'
                                result['is_vulnerable'] = True
                            elif validation_score >= 2 and pattern_matches > 0:
                                result['confidence'] = 'LOW'
                                result['is_vulnerable'] = True

                            if result['is_vulnerable']:
                                break

                        except requests.exceptions.ConnectionError:
                            # Connection refused with valid CNAME = potential takeover
                            if cname:
                                result['is_vulnerable'] = True
                                result['confidence'] = 'MEDIUM'
                                result['evidence'].append("Connection refused but CNAME exists")
                            break
                        except:
                            continue

                    return result

                def check_single_subdomain(subdomain_data):
                    """Check a single subdomain - runs in thread"""
                    subdomain, ips = subdomain_data
                    result = {'subdomain': subdomain, 'vulnerable': False, 'details': None}

                    try:
                        # Get CNAME records with short timeout
                        cname_records = []
                        try:
                            resolver = dns.resolver.Resolver()
                            resolver.timeout = 3
                            resolver.lifetime = 3
                            try:
                                answers = resolver.resolve(subdomain, 'CNAME')
                            except AttributeError:
                                answers = resolver.query(subdomain, 'CNAME')

                            for rdata in answers:
                                cname_records.append(str(rdata.target).rstrip('.'))
                        except:
                            pass

                        # Check if CNAME points to a potentially vulnerable service
                        for cname in cname_records:
                            for service, fingerprint in takeover_fingerprints.items():
                                if any(pattern in cname.lower() for pattern in fingerprint['cname']):
                                    # Full validation
                                    validation = validate_takeover(subdomain, cname, fingerprint)

                                    if validation['is_vulnerable']:
                                        result['vulnerable'] = True
                                        result['details'] = {
                                            'subdomain': subdomain,
                                            'cname': cname,
                                            'service': validation['service'],
                                            'confidence': validation['confidence'],
                                            'evidence': validation['evidence']
                                        }
                                        return result
                    except:
                        pass

                    return result

                # Process in parallel with progress indicator
                completed = 0
                subdomain_list = list(subdomains_to_check.items())

                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = {executor.submit(check_single_subdomain, sd): sd[0] for sd in subdomain_list}

                    for future in concurrent.futures.as_completed(futures):
                        completed += 1
                        subdomain = futures[future]

                        # Progress indicator
                        pct = int((completed + already_done) / total * 100)
                        bar_len = 30
                        filled = int(bar_len * (completed + already_done) / total)
                        bar = '█' * filled + '░' * (bar_len - filled)
                        print(f"\r[{bar}] {pct}% ({completed + already_done}/{total})", end='', flush=True)

                        try:
                            result = future.result()
                            checked_subdomains.add(subdomain)

                            if result['vulnerable']:
                                vulnerable_subdomains.append(result['details'])
                                print()  # newline before alert
                                self.print_warning(f"VULNERABLE [{result['details']['confidence']}]: {result['details']['subdomain']}")
                                self.print_info(f"  CNAME: {result['details']['cname']}")
                                self.print_info(f"  Service: {result['details']['service']}")
                                for evidence in result['details']['evidence'][:3]:  # Show top 3 evidence items
                                    self.print_info(f"  → {evidence}")

                            # Checkpoint every 20 subdomains
                            if completed % 20 == 0:
                                self.checkpoint('subdomain_takeover_detection', 'checked_subdomains', list(checked_subdomains))
                                self.checkpoint('subdomain_takeover_detection', 'vulnerable_subdomains', vulnerable_subdomains)
                        except:
                            checked_subdomains.add(subdomain)

                # Final newline after progress bar
                print()

                # Final checkpoint
                self.checkpoint('subdomain_takeover_detection', 'checked_subdomains', list(checked_subdomains))
                self.checkpoint('subdomain_takeover_detection', 'vulnerable_subdomains', vulnerable_subdomains)

                # Store results
                self.results['subdomain_takeover'] = vulnerable_subdomains

                # Summary
                if vulnerable_subdomains:
                    self.print_warning(f"\nFound {len(vulnerable_subdomains)} potentially vulnerable subdomains:")
                    for vuln in vulnerable_subdomains:
                        self.print_info(f"  [{vuln['confidence']}] {vuln['subdomain']} ({vuln['service']})")
                else:
                    self.print_success("\nNo subdomain takeover vulnerabilities detected")

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
                domains = set()
                target = self.domain.lower()

                def in_scope(name: str) -> bool:
                    name = name.strip().lower()
                    if not name or '*' in name:
                        return False
                    return name == target or name.endswith(f'.{target}')

                # =================================================================
                # Source 1: crt.sh with retries on 502/503/504
                # =================================================================
                self.print_info(f"Querying crt.sh for {self.domain}...")

                crtsh_max_retries = 3
                crtsh_success = False

                for attempt in range(crtsh_max_retries):
                    try:
                        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        }

                        response = requests.get(url, timeout=30, headers=headers)
                        self.print_info(f"crt.sh response status: {response.status_code} (attempt {attempt+1}/{crtsh_max_retries})")

                        if response.status_code == 200:
                            try:
                                data = response.json()
                                self.print_info(f"crt.sh returned {len(data)} certificate entries")

                                for entry in data:
                                    name = entry.get('name_value', '')
                                    for d in name.split('\n'):
                                        if in_scope(d):
                                            domains.add(d.strip().lower())

                                self.print_success(f"crt.sh: extracted {len(domains)} unique in-scope domains")
                                crtsh_success = True
                                break

                            except json.JSONDecodeError as e:
                                self.print_error(f"Failed to parse crt.sh JSON response: {e}")
                                self.print_info(f"Response preview: {response.text[:200]}")
                                break

                        elif response.status_code in (502, 503, 504):
                            if attempt < crtsh_max_retries - 1:
                                backoff = 5 * (attempt + 1)
                                self.print_warning(f"crt.sh returned {response.status_code}, retrying in {backoff}s...")
                                time.sleep(backoff)
                                continue
                            else:
                                self.print_warning(f"crt.sh persistently returning {response.status_code}, falling back to other sources")
                                break

                        else:
                            self.print_warning(f"crt.sh returned status {response.status_code}")
                            self.print_info(f"Response: {response.text[:200]}")
                            break

                    except requests.exceptions.Timeout:
                        if attempt < crtsh_max_retries - 1:
                            self.print_warning(f"crt.sh timeout (attempt {attempt+1}/{crtsh_max_retries}), retrying...")
                            time.sleep(5)
                            continue
                        else:
                            self.print_error("crt.sh timed out after all retries")
                            break

                    except requests.exceptions.ConnectionError as e:
                        if attempt < crtsh_max_retries - 1:
                            self.print_warning(f"crt.sh connection error, retrying...")
                            time.sleep(5)
                            continue
                        else:
                            self.print_error(f"Connection error to crt.sh: {e}")
                            break

                    except Exception as e:
                        self.print_error(f"crt.sh check failed: {e}")
                        break

                # =================================================================
                # Source 2: certspotter (always run if crt.sh did not succeed)
                # =================================================================
                if not crtsh_success:
                    self.print_info("Trying certspotter...")
                    try:
                        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
                        response = requests.get(url, timeout=30,
                                                headers={'User-Agent': 'Mozilla/5.0'})

                        if response.status_code == 200:
                            data = response.json()
                            before = len(domains)
                            for entry in data:
                                for name in entry.get('dns_names', []):
                                    if in_scope(name):
                                        domains.add(name.strip().lower())
                            added = len(domains) - before
                            self.print_success(f"certspotter: added {added} new in-scope domains")
                        elif response.status_code == 429:
                            self.print_warning("certspotter rate limited")
                        else:
                            self.print_warning(f"certspotter returned status {response.status_code}")

                    except Exception as e:
                        self.print_error(f"certspotter check failed: {e}")

                # =================================================================
                # Source 3: HackerTarget hostsearch (free, no key, reliable)
                # =================================================================
                if not crtsh_success:
                    self.print_info("Trying hackertarget hostsearch...")
                    try:
                        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
                        response = requests.get(url, timeout=30,
                                                headers={'User-Agent': 'Mozilla/5.0'})

                        if response.status_code == 200:
                            text = response.text or ''
                            # Rate-limit response is plain text starting with "API count exceeded"
                            if 'API count exceeded' in text or 'error' in text.lower()[:50]:
                                self.print_warning(f"hackertarget: {text.strip()[:100]}")
                            else:
                                before = len(domains)
                                for line in text.splitlines():
                                    # Format: hostname,ip
                                    parts = line.split(',', 1)
                                    if parts and in_scope(parts[0]):
                                        domains.add(parts[0].strip().lower())
                                added = len(domains) - before
                                self.print_success(f"hackertarget: added {added} new in-scope domains")
                        else:
                            self.print_warning(f"hackertarget returned status {response.status_code}")

                    except Exception as e:
                        self.print_error(f"hackertarget check failed: {e}")

                # =================================================================
                # Source 4: Google's CT log search via crt.sh alternate ID format
                # (only if everything else failed and we have nothing)
                # =================================================================
                if not domains:
                    self.print_warning("All CT sources failed - DNS enumeration will rely on bruteforce only")

                return list(domains)

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
            """Identify technology stack of web services with checkpoint support"""
            self.print_section("TECHNOLOGY STACK IDENTIFICATION")

            # Get resume data if available
            resume_data = self.get_resume_data('technology_stack')
            progress = resume_data.get('progress', {})

            tech_stack = {}

            # Restore previously analyzed hosts from checkpoint
            if progress.get('analyzed_hosts'):
                tech_stack = progress['analyzed_hosts']
                self.print_info(f"Restored {len(tech_stack)} analyzed hosts from checkpoint")

            # Get resolved domains from DNS enumeration
            resolved_domains = self.results.get('dns_enumeration', {}).get('resolved', {})

            if not resolved_domains:
                self.print_warning("No resolved domains available for tech stack identification")
                return

            # Build target list
            targets = [self.domain] if self.domain not in resolved_domains else []
            targets.extend(list(resolved_domains.keys()))

            # Remove duplicates while preserving order
            seen = set()
            unique_targets = []
            for t in targets:
                if t not in seen:
                    seen.add(t)
                    unique_targets.append(t)

            # Determine which targets still need analysis
            targets_to_analyze = [t for t in unique_targets if t not in tech_stack]

            if not targets_to_analyze:
                self.print_info(f"All {len(unique_targets)} targets already analyzed")
                self.results['technology_stack'] = tech_stack
                return

            self.print_info(f"Analyzing {len(targets_to_analyze)} targets for technology stack...")
            self.print_info(f"({len(tech_stack)} already complete from checkpoint)")

            checkpoint_interval = 25  # Checkpoint every 25 hosts
            completed_since_checkpoint = 0

            # Use threading for faster scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_target = {
                    executor.submit(self._identify_technologies, target): target
                    for target in targets_to_analyze
                }

                completed = len(tech_stack)
                total = len(unique_targets)

                for future in concurrent.futures.as_completed(future_to_target):
                    target = future_to_target[future]
                    completed += 1
                    completed_since_checkpoint += 1

                    try:
                        tech_info = future.result()
                        if tech_info:
                            tech_stack[target] = tech_info

                            # Print findings
                            self.print_info(f"[{completed}/{total}] {target}")
                            if tech_info.get('server'):
                                self.print_success(f"  Server: {tech_info['server']}")
                            if tech_info.get('powered_by'):
                                self.print_info(f"  X-Powered-By: {tech_info['powered_by']}")
                            if tech_info.get('detected_technologies'):
                                self.print_info(f"  Technologies: {', '.join(tech_info['detected_technologies'])}")
                        else:
                            self.print_info(f"[{completed}/{total}] {target} - No response")

                        # Checkpoint periodically
                        if completed_since_checkpoint >= checkpoint_interval:
                            self.checkpoint('technology_stack', 'analyzed_hosts', tech_stack)
                            self.checkpoint('technology_stack', 'progress_count', {
                                'completed': completed,
                                'total': total
                            })
                            completed_since_checkpoint = 0

                    except Exception as e:
                        self.print_warning(f"[{completed}/{total}] {target} - Error: {e}")

            # Final checkpoint
            self.checkpoint('technology_stack', 'analyzed_hosts', tech_stack)

            self.results['technology_stack'] = tech_stack
            self.print_success(f"\nTechnology stack identified for {len(tech_stack)} targets")

    def _identify_technologies(self, domain: str) -> Dict[str, Any]:
            """Identify technologies for a specific domain including VPN/remote access appliances on default and common alternate HTTP ports"""
            tech_info = {'headers': {}, 'server': None, 'powered_by': None, 'services_by_port': {}}

            # Appliance fingerprints: keyed by class, each entry has match patterns and optional secondary path
            appliance_fingerprints = {
                'F5 BIG-IP': {
                    'headers': [r'BigIP', r'BIG-IP'],
                    'cookies': [r'BIGipServer', r'TS[0-9a-f]{8,}', r'F5_ST'],
                    'html': [r'/my\.policy', r'F5 Networks'],
                    'version_patterns': [r'BIG-IP[^\d]*(\d+\.\d+\.\d+)', r'TMOS[^\d]*(\d+\.\d+\.\d+)'],
                    'secondary_path': '/my.policy'
                },
                'Citrix Netscaler/ADC': {
                    'headers': [r'NetScaler', r'Citrix'],
                    'cookies': [r'NSC_', r'NSC_USER', r'pwcount'],
                    'html': [r'/vpn/index\.html', r'Citrix Gateway', r'NetScaler Gateway', r'_ctxs_AuthId'],
                    'version_patterns': [r'NS([\d.]+)', r'NSBuild[^\d]*(\d+)', r'Build[^\d]*(\d+\.\d+)'],
                    'secondary_path': '/vpn/index.html'
                },
                'FortiGate SSLVPN': {
                    'headers': [r'xxxxxxxx-xxxxx', r'Fortinet'],
                    'cookies': [r'SVPNCOOKIE', r'FGTServer'],
                    'html': [r'/remote/login', r'fgt_lang', r'FortiGate', r'sslvpn'],
                    'version_patterns': [r'FortiGate[^\d]*(\d+\.\d+\.\d+)'],
                    'secondary_path': '/remote/login'
                },
                'GlobalProtect (Palo Alto)': {
                    'headers': [],
                    'cookies': [r'PHPSESSID.*paloalto', r'clientVer'],
                    'html': [r'global-protect', r'GlobalProtect', r'/sslmgr', r'pan-clientver'],
                    'version_patterns': [r'clientVer[^\d]*(\d+\.\d+\.\d+)', r'GlobalProtect[^\d]*(\d+\.\d+\.\d+)'],
                    'secondary_path': '/global-protect/login.esp'
                },
                'Cisco AnyConnect/ASA': {
                    'headers': [r'Cisco', r'ASA'],
                    'cookies': [r'webvpn', r'webvpnLogin', r'webvpnPin'],
                    'html': [r'/\+CSCOE\+/', r'AnyConnect', r'Cisco Systems', r'webvpn_logo'],
                    'version_patterns': [r'ASA[^\d]*(\d+\.\d+\(\d+\))', r'AnyConnect[^\d]*(\d+\.\d+\.\d+)'],
                    'secondary_path': '/+CSCOE+/logon.html'
                },
                'Pulse Secure/Ivanti Connect Secure': {
                    'headers': [r'Pulse', r'Ivanti'],
                    'cookies': [r'DSID', r'DSLastAccess', r'DSSIGNIN'],
                    'html': [r'/dana-na/', r'Pulse Secure', r'Ivanti Connect Secure', r'welcome\.cgi'],
                    'version_patterns': [r'Pulse Secure[^\d]*(\d+\.\d+)', r'(\d+\.\d+R\d+)'],
                    'secondary_path': '/dana-na/auth/url_default/welcome.cgi'
                },
                'SonicWall NetExtender/SMA': {
                    'headers': [r'SonicWALL', r'SonicOS'],
                    'cookies': [r'swap', r'sessId'],
                    'html': [r'SonicWall', r'NetExtender', r'/cgi-bin/welcome', r'sw_logo'],
                    'version_patterns': [r'SonicOS[^\d]*(\d+\.\d+\.\d+)', r'SMA[^\d]*(\d+\.\d+\.\d+)'],
                    'secondary_path': '/cgi-bin/welcome'
                },
                'Microsoft RD Web Access': {
                    'headers': [r'Microsoft-IIS', r'Microsoft-HTTPAPI'],
                    'cookies': [r'TSWAAuthHttpModule'],
                    'html': [r'/RDWeb/', r'RD Web Access', r'Remote Desktop Services', r'TSWebAccess'],
                    'version_patterns': [r'Microsoft-IIS/(\d+\.\d+)'],
                    'secondary_path': '/RDWeb/Pages/en-US/login.aspx'
                },
                'Check Point Mobile Access': {
                    'headers': [r'Check Point'],
                    'cookies': [r'CPCVPN_SESSION_ID', r'selected_realm'],
                    'html': [r'/sslvpn/Login/Login', r'Check Point', r'Mobile Access Portal'],
                    'version_patterns': [r'R\d{2}[\d.]*'],
                    'secondary_path': '/sslvpn/Login/Login'
                }
            }

            # Standard tech indicators
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

            # Interesting headers to capture
            interesting_headers = [
                'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
                'X-Generator', 'X-Drupal-Cache', 'X-Content-Type-Options',
                'X-Frame-Options', 'Strict-Transport-Security', 'Set-Cookie'
            ]

            # Probe targets: (scheme, port, is_default, timeout)
            # Default ports use longer timeout; alternates use shorter to limit runtime impact
            probe_targets = [
                ('https', 443, True, 10),
                ('http', 80, True, 10),
                ('https', 8443, False, 5),
                ('http', 8080, False, 5),
                ('http', 8000, False, 5),
                ('http', 8888, False, 5)
            ]

            def match_appliance(response_text: str, response_headers, set_cookie: str) -> Optional[Dict[str, str]]:
                """Match response against appliance fingerprints. Returns dict with class, version, evidence."""
                header_blob = ' '.join(f"{k}: {v}" for k, v in response_headers.items())
                search_text = (response_text or '')[:50000].lower()
                cookie_blob = (set_cookie or '').lower()

                for appliance_class, fp in appliance_fingerprints.items():
                    score = 0
                    evidence = []

                    for pattern in fp['headers']:
                        if re.search(pattern, header_blob, re.IGNORECASE):
                            score += 2
                            evidence.append(f"header: {pattern}")
                            break

                    for pattern in fp['cookies']:
                        if re.search(pattern, cookie_blob, re.IGNORECASE) or re.search(pattern, header_blob, re.IGNORECASE):
                            score += 2
                            evidence.append(f"cookie: {pattern}")
                            break

                    for pattern in fp['html']:
                        if re.search(pattern, search_text, re.IGNORECASE):
                            score += 1
                            evidence.append(f"html: {pattern}")

                    if score >= 2:
                        version = None
                        for vpattern in fp['version_patterns']:
                            match = re.search(vpattern, response_text or '', re.IGNORECASE) or re.search(vpattern, header_blob, re.IGNORECASE)
                            if match:
                                version = match.group(1) if match.groups() else match.group(0)
                                break

                        return {
                            'class': appliance_class,
                            'version': version or 'Unknown',
                            'evidence': evidence[:3],
                            'secondary_path': fp.get('secondary_path')
                        }

                return None

            primary_response_captured = False

            for scheme, port, is_default, timeout in probe_targets:
                url = f"{scheme}://{domain}:{port}" if not is_default else f"{scheme}://{domain}"

                try:
                    response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)

                    # Build per-port result
                    port_info = {
                        'url': url,
                        'status_code': response.status_code,
                        'scheme': scheme,
                        'port': port,
                        'headers': {},
                        'detected_technologies': []
                    }

                    # Extract headers per port
                    for header in interesting_headers:
                        if header in response.headers:
                            port_info['headers'][header] = response.headers[header]

                    if 'Server' in response.headers:
                        port_info['server'] = response.headers['Server']
                    if 'X-Powered-By' in response.headers:
                        port_info['powered_by'] = response.headers['X-Powered-By']

                    # Tech indicators
                    html = response.text.lower()
                    for tech, indicator in indicators.items():
                        if indicator in html:
                            port_info['detected_technologies'].append(tech)

                    # Appliance fingerprinting against root response
                    set_cookie = response.headers.get('Set-Cookie', '')
                    appliance = match_appliance(response.text, response.headers, set_cookie)

                    # Conditional secondary probe (only on default ports to limit runtime)
                    if not appliance and is_default:
                        is_ambiguous = (
                            len(response.content) < 5000 or
                            any(x in response.url.lower() for x in ['login', 'logon', 'auth', 'signin', 'sso']) or
                            response.status_code in [401, 403] or
                            port_info.get('server', '').lower() in ['', 'unknown', 'apache', 'nginx', 'microsoft-iis/8.5', 'microsoft-iis/10.0']
                        )

                        if is_ambiguous:
                            priority_paths = [
                                '/my.policy', '/vpn/index.html', '/remote/login',
                                '/dana-na/auth/url_default/welcome.cgi', '/+CSCOE+/logon.html',
                                '/global-protect/login.esp', '/RDWeb/Pages/en-US/login.aspx',
                                '/sslvpn/Login/Login', '/cgi-bin/welcome'
                            ]
                            for path in priority_paths:
                                try:
                                    probe_url = f"{url}{path}"
                                    probe_resp = requests.get(probe_url, timeout=5, verify=False, allow_redirects=True)
                                    if probe_resp.status_code in [200, 302, 401, 403]:
                                        probe_cookie = probe_resp.headers.get('Set-Cookie', '')
                                        appliance = match_appliance(probe_resp.text, probe_resp.headers, probe_cookie)
                                        if appliance:
                                            appliance['probe_path'] = path
                                            break
                                except:
                                    continue

                    if appliance:
                        port_info['vpn_appliance'] = appliance

                    # Store per-port findings
                    tech_info['services_by_port'][str(port)] = port_info

                    # Populate flat fields from primary (default-port) response for backward compat
                    if is_default and not primary_response_captured:
                        tech_info['headers'] = port_info['headers']
                        if port_info.get('server'):
                            tech_info['server'] = port_info['server']
                        if port_info.get('powered_by'):
                            tech_info['powered_by'] = port_info['powered_by']
                        if port_info.get('detected_technologies'):
                            tech_info['detected_technologies'] = port_info['detected_technologies']
                        if port_info.get('vpn_appliance'):
                            tech_info['vpn_appliance'] = port_info['vpn_appliance']
                        primary_response_captured = True

                    # If primary response succeeded with usable data, skip the matching fallback default
                    # (HTTPS succeeded, no need to try HTTP on the same default port)
                    if is_default and primary_response_captured and scheme == 'https':
                        # Skip to alternate ports
                        continue

                except requests.exceptions.SSLError:
                    continue
                except requests.exceptions.ConnectionError:
                    continue
                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    continue

            # Promote VPN appliance from alternate ports if not found on default
            if not tech_info.get('vpn_appliance'):
                for port_str, port_data in tech_info['services_by_port'].items():
                    if port_data.get('vpn_appliance'):
                        tech_info['vpn_appliance'] = port_data['vpn_appliance']
                        tech_info['vpn_appliance']['discovered_on_port'] = port_str
                        break

            # Return None only if absolutely nothing found
            return tech_info if (tech_info['headers'] or tech_info.get('detected_technologies') or tech_info.get('vpn_appliance') or tech_info['services_by_port']) else None

    def email_harvesting(self):
                """Harvest email addresses from multiple public sources"""
                self.print_section("EMAIL ADDRESS HARVESTING")

                emails = set()
                email_sources = {}

                # Method 1: theHarvester
                self.print_info("Running theHarvester...")
                harvester_emails = self._run_theharvester()
                for email in harvester_emails:
                    emails.add(email)
                    email_sources[email] = email_sources.get(email, []) + ['theHarvester']
                self.print_success(f"Found {len(harvester_emails)} emails from theHarvester")

                # Method 2: Web scraping
                self.print_info("Scraping web pages for emails...")
                web_emails = self._scrape_emails_from_web()
                for email in web_emails:
                    emails.add(email)
                    email_sources[email] = email_sources.get(email, []) + ['web_scraping']
                self.print_success(f"Found {len(web_emails)} emails from web scraping")

                # Method 3: Google dorking
                self.print_info("Searching search engines for emails...")
                google_emails = self._google_dork_emails()
                for email in google_emails:
                    emails.add(email)
                    email_sources[email] = email_sources.get(email, []) + ['google_dork']
                self.print_success(f"Found {len(google_emails)} emails from Google dorking")

                # Method 4: PGP key servers
                self.print_info("Searching PGP key servers...")
                pgp_emails = self._search_pgp_servers()
                for email in pgp_emails:
                    emails.add(email)
                    email_sources[email] = email_sources.get(email, []) + ['pgp_keyserver']
                self.print_success(f"Found {len(pgp_emails)} emails from PGP servers")

                # Exclusion list
                excluded_addresses = {
                    'cmartorella@edge-security.com',
                }

                # Filter emails
                filtered_emails = []

                for email in emails:
                    email_lower = email.lower()

                    if email_lower in excluded_addresses:
                        continue
                    if len(email) > 100:
                        continue
                    if email.count('@') != 1:
                        continue

                    local, domain = email.split('@')

                    if len(local) == 32 and all(c in '0123456789abcdef' for c in local):
                        continue

                    domain_lower = domain.lower()
                    target_domain_lower = self.domain.lower()

                    if domain_lower == target_domain_lower or domain_lower.endswith(f'.{target_domain_lower}'):
                        filtered_emails.append(email)

                # Detect email pattern
                email_pattern = self._detect_email_pattern(filtered_emails)

                # Store results
                self.results['email_addresses'] = sorted(filtered_emails)
                self.results['email_pattern'] = email_pattern
                self.results['email_sources'] = {e: email_sources.get(e, []) for e in filtered_emails}

                self.print_success(f"\nTotal unique email addresses found: {len(filtered_emails)}")

                if email_pattern:
                    self.print_info(f"Detected email pattern: {email_pattern['pattern']} ({email_pattern['confidence']}% confidence)")
                    self.print_info(f"  Examples: {', '.join(email_pattern['examples'][:3])}")

                if filtered_emails:
                    self.print_info(f"\nEmails from target domain ({self.domain}):")
                    for email in sorted(filtered_emails):
                        sources = email_sources.get(email, [])
                        self.print_info(f"  {email} (from: {', '.join(sources)})")
                else:
                    self.print_warning(f"No emails found for target domain ({self.domain})")

    def _google_dork_emails(self) -> List[str]:
                    """Search for emails using multiple search engines"""
                    emails = []

                    # More restrictive pattern - exclude URL-like prefixes
                    def extract_emails(text, target_domain):
                        """Extract emails while filtering out URL contamination"""
                        # First try mailto: links (most reliable)
                        mailto = re.findall(r'mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', text)

                        # Then general pattern with cleanup
                        raw_pattern = r'[A-Za-z0-9._%+-]+@' + re.escape(target_domain)
                        raw_matches = re.findall(raw_pattern, text, re.IGNORECASE)

                        valid_emails = list(mailto)
                        for email in raw_matches:
                            local_part = email.split('@')[0].lower()

                            # Skip if local part looks like URL remnant
                            if local_part.startswith('www.'):
                                continue
                            if re.search(r'\.(com|org|net|edu|gov|io|co|uk)$', local_part):
                                continue
                            if len(local_part) > 64:
                                continue

                            valid_emails.append(email)

                        return valid_emails

                    target = self.domain

                    # Queries to run
                    queries = [
                        f'"@{target}"',
                        f'site:{target} "@{target}"',
                        f'"@{target}" filetype:pdf',
                        f'"@{target}" contact email',
                    ]

                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                    }

                    # Try Google (may be blocked, but worth trying)
                    self.print_info("  Trying Google...")
                    for query in queries[:2]:
                        try:
                            url = f"https://www.google.com/search?q={requests.utils.quote(query)}&num=50"
                            response = self.session.get(url, headers=headers, timeout=15)

                            if response.status_code == 200:
                                found = extract_emails(response.text, target)
                                if found:
                                    self.print_info(f"    Google found {len(found)} matches")
                                emails.extend(found)
                            elif response.status_code == 429:
                                self.print_warning("    Google rate limited/blocked")
                                break

                            time.sleep(3)

                        except Exception as e:
                            self.print_warning(f"    Google search failed: {e}")
                            break

                    # Try Bing
                    self.print_info("  Trying Bing...")
                    for query in queries:
                        try:
                            url = f"https://www.bing.com/search?q={requests.utils.quote(query)}&count=50"
                            response = self.session.get(url, headers=headers, timeout=15)

                            if response.status_code == 200:
                                found = extract_emails(response.text, target)
                                if found:
                                    self.print_info(f"    Bing found {len(found)} matches")
                                emails.extend(found)

                            time.sleep(2)

                        except Exception as e:
                            self.print_warning(f"    Bing search failed: {e}")

                    # Try DuckDuckGo HTML version
                    self.print_info("  Trying DuckDuckGo...")
                    for query in queries[:2]:
                        try:
                            url = f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}"
                            response = self.session.get(url, headers=headers, timeout=15)

                            if response.status_code == 200:
                                found = extract_emails(response.text, target)
                                if found:
                                    self.print_info(f"    DuckDuckGo found {len(found)} matches")
                                emails.extend(found)

                            time.sleep(3)

                        except Exception as e:
                            self.print_warning(f"    DuckDuckGo search failed: {e}")

                    # Try Yahoo
                    self.print_info("  Trying Yahoo...")
                    for query in queries[:2]:
                        try:
                            url = f"https://search.yahoo.com/search?p={requests.utils.quote(query)}&n=50"
                            response = self.session.get(url, headers=headers, timeout=15)

                            if response.status_code == 200:
                                found = extract_emails(response.text, target)
                                if found:
                                    self.print_info(f"    Yahoo found {len(found)} matches")
                                emails.extend(found)

                            time.sleep(2)

                        except Exception as e:
                            self.print_warning(f"    Yahoo search failed: {e}")

                    # Deduplicate and filter
                    unique_emails = list(set(e.lower() for e in emails))

                    # Filter to only target domain
                    filtered = [e for e in unique_emails if e.endswith(f'@{target.lower()}')]

                    return filtered

    def _search_pgp_servers(self) -> List[str]:
            """Search PGP key servers for emails"""
            emails = []
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

            pgp_servers = [
                f"https://keys.openpgp.org/search?q={self.domain}",
                f"https://keyserver.ubuntu.com/pks/lookup?search={self.domain}&op=index",
            ]

            for server_url in pgp_servers:
                try:
                    response = self.session.get(server_url, timeout=10)

                    if response.status_code == 200:
                        found = re.findall(email_pattern, response.text)
                        emails.extend(found)

                    time.sleep(1)

                except:
                    pass

            return list(set(emails))

    def _detect_email_pattern(self, emails: List[str]) -> Optional[Dict[str, Any]]:
            """Detect the email naming pattern from collected emails"""
            if not emails:
                return None

            patterns = {
                'firstname.lastname': 0,
                'firstnamelastname': 0,
                'firstname_lastname': 0,
                'firstname': 0,
                'flastname': 0,
                'firstl': 0,
                'lastname.firstname': 0,
                'other': 0
            }

            examples = {k: [] for k in patterns.keys()}

            for email in emails:
                local = email.split('@')[0].lower()

                if local in ['info', 'contact', 'support', 'admin', 'sales', 'hr', 'jobs', 'careers', 'press', 'media', 'marketing']:
                    continue

                if '.' in local and len(local.split('.')) == 2:
                    parts = local.split('.')
                    if parts[0].isalpha() and parts[1].isalpha():
                        if len(parts[0]) > 1 and len(parts[1]) > 1:
                            patterns['firstname.lastname'] += 1
                            examples['firstname.lastname'].append(email)
                        elif len(parts[0]) == 1:
                            patterns['flastname'] += 1
                            examples['flastname'].append(email)
                elif '_' in local and len(local.split('_')) == 2:
                    patterns['firstname_lastname'] += 1
                    examples['firstname_lastname'].append(email)
                elif local.isalpha() and len(local) > 2:
                    if len(local) > 10:
                        patterns['firstnamelastname'] += 1
                        examples['firstnamelastname'].append(email)
                    elif len(local) < 6:
                        patterns['firstname'] += 1
                        examples['firstname'].append(email)
                    else:
                        patterns['other'] += 1
                        examples['other'].append(email)
                else:
                    patterns['other'] += 1
                    examples['other'].append(email)

            total = sum(patterns.values())
            if total == 0:
                return None

            best_pattern = max(patterns.items(), key=lambda x: x[1])

            if best_pattern[1] == 0:
                return None

            confidence = int((best_pattern[1] / total) * 100)

            return {
                'pattern': best_pattern[0],
                'confidence': confidence,
                'count': best_pattern[1],
                'total_analyzed': total,
                'examples': examples[best_pattern[0]][:5]
            }

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
                    """Crawl company website to discover email addresses with prioritized targeting and early termination"""
                    emails = set()

                    # Determine crawl mode
                    deep_mode = getattr(self.args, 'deep_crawl', False) if hasattr(self, 'args') else False

                    if deep_mode:
                        max_pages = 100
                        max_depth = 3
                        per_page_timeout = 8
                        no_new_emails_limit = 0  # Disable early termination in deep mode
                        self.print_info("  Deep crawl mode enabled (max 100 pages, depth 3)")
                    else:
                        max_pages = 25
                        max_depth = 2
                        per_page_timeout = 5
                        no_new_emails_limit = 8

                    # Email pattern with URL contamination guard
                    email_pattern = r'(?<![A-Za-z0-9./_-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9])'

                    # High-yield URL patterns - pages where emails actually live
                    high_yield_patterns = [
                        'contact', 'about', 'team', 'staff', 'people', 'directory',
                        'employees', 'leadership', 'management', 'board', 'officers',
                        'locations', 'news', 'press', 'media', 'investor', 'careers',
                        'support', 'help'
                    ]

                    visited = set()
                    high_yield_queue = []  # (url, depth) - priority queue
                    standard_queue = []     # (url, depth)

                    # Determine base URL
                    base_url = None
                    for protocol in ['https', 'http']:
                        try:
                            test_url = f"{protocol}://{self.domain}"
                            response = requests.get(test_url, timeout=per_page_timeout, verify=False, allow_redirects=True)
                            if response.status_code == 200:
                                base_url = f"{protocol}://{self.domain}"
                                break
                        except:
                            continue

                    if not base_url:
                        self.print_warning(f"Could not connect to {self.domain}")
                        return list(emails)

                    # Fast-path: try sitemap.xml to seed high-yield URLs directly
                    sitemap_seeded = False
                    try:
                        sitemap_url = f"{base_url}/sitemap.xml"
                        sitemap_resp = requests.get(sitemap_url, timeout=per_page_timeout, verify=False)
                        if sitemap_resp.status_code == 200 and ('<urlset' in sitemap_resp.text or '<sitemapindex' in sitemap_resp.text):
                            # Extract URLs from sitemap
                            sitemap_urls = re.findall(r'<loc>([^<]+)</loc>', sitemap_resp.text)
                            for sm_url in sitemap_urls:
                                sm_url = sm_url.strip()
                                if self.domain in sm_url:
                                    url_lower = sm_url.lower()
                                    if any(p in url_lower for p in high_yield_patterns):
                                        high_yield_queue.append((sm_url, 0))
                                    else:
                                        standard_queue.append((sm_url, 0))
                            if high_yield_queue:
                                sitemap_seeded = True
                                self.print_info(f"  Sitemap found - seeded {len(high_yield_queue)} high-yield URLs")
                    except:
                        pass

                    # Always start with homepage
                    high_yield_queue.insert(0, (base_url, 0))

                    self.print_info(f"  Crawling {self.domain} (max {max_pages} pages, depth {max_depth}, prioritized)")

                    pages_crawled = 0
                    pages_since_new_email = 0

                    while (high_yield_queue or standard_queue) and pages_crawled < max_pages:
                        # Check for shutdown signal
                        if getattr(self, '_shutdown_in_progress', False):
                            self.print_warning("  Shutdown signal received, stopping crawl")
                            break

                        # High-yield first, then standard
                        if high_yield_queue:
                            url, depth = high_yield_queue.pop(0)
                        elif standard_queue:
                            url, depth = standard_queue.pop(0)
                        else:
                            break

                        # Normalize URL
                        url = url.split('#')[0].split('?')[0].rstrip('/')

                        if url in visited:
                            continue

                        if self.domain not in url:
                            continue

                        visited.add(url)

                        try:
                            response = requests.get(url, timeout=per_page_timeout, verify=False, allow_redirects=True,
                                                headers={'User-Agent': 'Mozilla/5.0 (compatible; reconnaissance tool)'})

                            if response.status_code != 200:
                                continue

                            content_type = response.headers.get('Content-Type', '')
                            if 'text/html' not in content_type:
                                continue

                            pages_crawled += 1
                            html = response.text
                            emails_before = len(emails)

                            # Extract emails - use findall with groups
                            found_emails = re.findall(email_pattern, html)

                            # mailto: links (highest reliability)
                            mailto_matches = re.findall(r'mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', html)
                            found_emails.extend(mailto_matches)

                            # Obfuscated: user [at] domain [dot] com
                            obfuscated = re.findall(r'([A-Za-z0-9._%+-]+)\s*[\[\(]?\s*(?:at|AT)\s*[\]\)]?\s*([A-Za-z0-9.-]+)\s*[\[\(]?\s*(?:dot|DOT)\s*[\]\)]?\s*([A-Za-z]{2,})', html)
                            for parts in obfuscated:
                                found_emails.append(f"{parts[0]}@{parts[1]}.{parts[2]}")

                            for email in found_emails:
                                email_lower = email.lower().strip()

                                # Skip if local part looks like a URL (contains .com, .org, .net, etc before @)
                                local_part = email_lower.split('@')[0]
                                if re.search(r'\.(com|org|net|edu|gov|io|co|uk|de|fr|es|it|ru|cn|jp|au|ca|br|in|mx)$', local_part):
                                    continue

                                # Skip if starts with www.
                                if local_part.startswith('www.'):
                                    continue

                                # Skip if local part is too long (likely garbage)
                                if len(local_part) > 64:
                                    continue

                                # Skip common false positives
                                if any(x in email_lower for x in ['example.com', 'domain.com', 'test.com', '.png', '.jpg', '.gif', 'wixpress', 'sentry.io']):
                                    continue

                                emails.add(email_lower)

                            new_this_page = len(emails) - emails_before

                            # Track pages-since-new-email for early termination
                            if new_this_page == 0:
                                pages_since_new_email += 1
                            else:
                                pages_since_new_email = 0

                            # Early termination
                            if no_new_emails_limit > 0 and pages_since_new_email >= no_new_emails_limit:
                                self.print_info(f"  Stopping crawl: no new emails in last {no_new_emails_limit} pages")
                                break

                            # Discover internal links (only if not already at max depth)
                            if depth < max_depth:
                                links = re.findall(r'href=["\']([^"\']+)["\']', html)

                                for link in links:
                                    # Skip static assets and non-pages
                                    if any(link.lower().endswith(ext) for ext in ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.mp4', '.mp3', '.zip']):
                                        continue
                                    if link.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                                        continue

                                    # Build absolute URL
                                    if link.startswith('http'):
                                        abs_url = link
                                    elif link.startswith('//'):
                                        abs_url = f"https:{link}"
                                    elif link.startswith('/'):
                                        abs_url = f"{base_url}{link}"
                                    else:
                                        abs_url = f"{base_url}/{link}"

                                    abs_url = abs_url.split('#')[0].split('?')[0].rstrip('/')

                                    if self.domain in abs_url and abs_url not in visited:
                                        # Prioritize based on URL content
                                        url_lower = abs_url.lower()
                                        if any(p in url_lower for p in high_yield_patterns):
                                            if (abs_url, depth + 1) not in high_yield_queue:
                                                high_yield_queue.append((abs_url, depth + 1))
                                        else:
                                            if (abs_url, depth + 1) not in standard_queue:
                                                standard_queue.append((abs_url, depth + 1))

                            time.sleep(0.3)

                        except:
                            continue

                    self.print_info(f"  Crawled {pages_crawled} pages, found {len(emails)} unique emails")

                    return list(emails)

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

    def _scan_file_for_secrets(self, file_path, source_ref: str) -> list:
                """Scan a downloaded file's content for secrets using shared patterns. Returns [{type, count}]."""
                findings = []
                try:
                    p = Path(file_path)
                    if not p.exists() or p.stat().st_size == 0:
                        return findings
                    # Bound the read; skip very large files
                    if p.stat().st_size > 5 * 1024 * 1024:
                        return findings
                    raw = p.read_bytes()
                    # Skip binary content (null bytes are a reliable signal)
                    if b'\x00' in raw[:4096]:
                        return findings
                    content = raw.decode('utf-8', errors='ignore')
                except Exception:
                    return findings

                for secret_type, pattern in self.SENSITIVE_PATTERNS.items():
                    try:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                    except Exception:
                        continue
                    if matches and self._is_real_secret(secret_type, matches, content):
                        findings.append({'type': secret_type, 'count': len(matches)})

                if findings:
                    self.print_warning(f"  Secrets detected in {source_ref}: {', '.join(f['type'] for f in findings)}")
                return findings

    def s3_bucket_enumeration(self):
                """Perform S3 bucket enumeration with checkpoint support"""
                self.print_section("S3 BUCKET ENUMERATION")

                # Get resume data if available
                resume_data = self.get_resume_data('s3_bucket_enumeration')
                progress = resume_data.get('progress', {})

                # Get base domain
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
                for subdomain in list(resolved.keys())[:20]:
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

                # Restore previously checked buckets from checkpoint
                checked_buckets = set(progress.get('checked_buckets', []))
                found_buckets = progress.get('found_buckets', [])

                if checked_buckets:
                    self.print_info(f"Restored {len(checked_buckets)} checked buckets from checkpoint")
                    self.print_info(f"Found {len(found_buckets)} buckets so far")

                # Determine which buckets still need checking
                buckets_to_check = [b for b in bucket_candidates if b not in checked_buckets]

                self.print_info(f"Testing {len(buckets_to_check)} potential bucket names...")
                self.print_info(f"({len(checked_buckets)} already checked from checkpoint)")

                checkpoint_interval = 20  # Checkpoint every 20 buckets
                completed_since_checkpoint = 0

                # Check each bucket
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_bucket = {
                        executor.submit(self._check_s3_bucket, bucket): bucket
                        for bucket in buckets_to_check
                    }

                    for future in concurrent.futures.as_completed(future_to_bucket):
                        bucket_name = future_to_bucket[future]
                        checked_buckets.add(bucket_name)
                        completed_since_checkpoint += 1

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

                        # Checkpoint periodically
                        if completed_since_checkpoint >= checkpoint_interval:
                            self.checkpoint('s3_bucket_enumeration', 'checked_buckets', list(checked_buckets))
                            self.checkpoint('s3_bucket_enumeration', 'found_buckets', found_buckets)
                            completed_since_checkpoint = 0

                # Final checkpoint before analysis
                self.checkpoint('s3_bucket_enumeration', 'checked_buckets', list(checked_buckets))
                self.checkpoint('s3_bucket_enumeration', 'found_buckets', found_buckets)

                # Analyze accessible buckets
                analyzed_buckets = set(progress.get('analyzed_buckets', []))

                self.print_info(f"\nAnalyzing {len(found_buckets)} discovered buckets...")
                for bucket in found_buckets:
                    bucket_name = bucket.get('bucket', 'unknown')

                    if bucket_name in analyzed_buckets:
                        self.print_info(f"Skipping {bucket_name} (already analyzed)")
                        continue

                    if bucket['status'] in ['Public Read', 'Redirect']:
                        self.print_info(f"\n[*] Analyzing contents of {bucket_name}...")
                        try:
                            self._analyze_s3_bucket_contents(bucket)
                            analyzed_buckets.add(bucket_name)
                            self.checkpoint('s3_bucket_enumeration', 'analyzed_buckets', list(analyzed_buckets))
                        except Exception as e:
                            self.print_error(f"Analysis failed for {bucket_name}: {e}")
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
                            hits = self._scan_file_for_secrets(output_path, f"s3:{bucket_name}/{f['key']}")
                            if hits:
                                bucket_info.setdefault('secret_findings', []).append({'file': f['key'], 'secrets': hits})

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
                """Enumerate Azure Blob Storage containers with checkpoint support"""
                self.print_section("AZURE STORAGE ENUMERATION")

                # Get resume data if available
                resume_data = self.get_resume_data('azure_storage_enumeration')
                progress = resume_data.get('progress', {})

                # Get base domain
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

                # Restore previously checked storage accounts from checkpoint
                checked_accounts = set(progress.get('checked_accounts', []))
                found_storage = progress.get('found_storage', [])

                if checked_accounts:
                    self.print_info(f"Restored {len(checked_accounts)} checked accounts from checkpoint")
                    self.print_info(f"Found {len(found_storage)} storage accounts so far")

                # Determine which accounts still need checking
                accounts_to_check = [a for a in storage_candidates if a not in checked_accounts]

                self.print_info(f"Testing {len(accounts_to_check)} potential Azure storage account names...")
                self.print_info(f"({len(checked_accounts)} already checked from checkpoint)")

                checkpoint_interval = 20
                completed_since_checkpoint = 0

                # Check each storage account
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_storage = {
                        executor.submit(self._check_azure_storage, account): account
                        for account in accounts_to_check
                    }

                    for future in concurrent.futures.as_completed(future_to_storage):
                        account_name = future_to_storage[future]
                        checked_accounts.add(account_name)
                        completed_since_checkpoint += 1

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

                        # Checkpoint periodically
                        if completed_since_checkpoint >= checkpoint_interval:
                            self.checkpoint('azure_storage_enumeration', 'checked_accounts', list(checked_accounts))
                            self.checkpoint('azure_storage_enumeration', 'found_storage', found_storage)
                            completed_since_checkpoint = 0

                # Final checkpoint before analysis
                self.checkpoint('azure_storage_enumeration', 'checked_accounts', list(checked_accounts))
                self.checkpoint('azure_storage_enumeration', 'found_storage', found_storage)

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
                analyzed_accounts = set(progress.get('analyzed_accounts', []))
                public_storage = [s for s in found_storage if s['status'] == 'Public Read']

                if public_storage:
                    self.print_info(f"\n[*] Analyzing {len(public_storage)} publicly accessible storage accounts...")
                    for storage in public_storage:
                        account_name = storage.get('account', 'unknown')

                        if account_name in analyzed_accounts:
                            self.print_info(f"Skipping {account_name} (already analyzed)")
                            continue

                        self.print_info(f"\n[*] Analyzing contents of {account_name}...")
                        try:
                            self._analyze_azure_storage_contents(storage)
                            analyzed_accounts.add(account_name)
                            self.checkpoint('azure_storage_enumeration', 'analyzed_accounts', list(analyzed_accounts))
                        except Exception as e:
                            self.print_error(f"Analysis failed for {account_name}: {e}")
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
                            hits = self._scan_file_for_secrets(output_path, f"azure:{account_name}/{container}/{f['name']}")
                            if hits:
                                storage_info.setdefault('secret_findings', []).append({'file': f['name'], 'secrets': hits})

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
                """Enumerate Google Cloud Platform (GCP) Storage buckets with checkpoint support"""
                self.print_section("GCP STORAGE ENUMERATION")

                # Get resume data if available
                resume_data = self.get_resume_data('gcp_storage_enumeration')
                progress = resume_data.get('progress', {})

                # Get base domain
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

                # Restore previously checked buckets from checkpoint
                checked_buckets = set(progress.get('checked_buckets', []))
                found_buckets = progress.get('found_buckets', [])

                if checked_buckets:
                    self.print_info(f"Restored {len(checked_buckets)} checked buckets from checkpoint")
                    self.print_info(f"Found {len(found_buckets)} buckets so far")

                # Determine which buckets still need checking
                buckets_to_check = [b for b in bucket_candidates if b not in checked_buckets]

                self.print_info(f"Testing {len(buckets_to_check)} potential GCP bucket names...")
                self.print_info(f"({len(checked_buckets)} already checked from checkpoint)")

                checkpoint_interval = 20
                completed_since_checkpoint = 0

                # Check each bucket
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_bucket = {
                        executor.submit(self._check_gcp_bucket, bucket): bucket
                        for bucket in buckets_to_check
                    }

                    for future in concurrent.futures.as_completed(future_to_bucket):
                        bucket_name = future_to_bucket[future]
                        checked_buckets.add(bucket_name)
                        completed_since_checkpoint += 1

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

                        # Checkpoint periodically
                        if completed_since_checkpoint >= checkpoint_interval:
                            self.checkpoint('gcp_storage_enumeration', 'checked_buckets', list(checked_buckets))
                            self.checkpoint('gcp_storage_enumeration', 'found_buckets', found_buckets)
                            completed_since_checkpoint = 0

                # Final checkpoint before analysis
                self.checkpoint('gcp_storage_enumeration', 'checked_buckets', list(checked_buckets))
                self.checkpoint('gcp_storage_enumeration', 'found_buckets', found_buckets)

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
                analyzed_buckets = set(progress.get('analyzed_buckets', []))
                public_buckets = [b for b in found_buckets if b['status'] == 'Public Read']

                if public_buckets:
                    self.print_info(f"\n[*] Analyzing {len(public_buckets)} publicly accessible buckets...")
                    for bucket in public_buckets:
                        bucket_name = bucket.get('bucket', 'unknown')

                        if bucket_name in analyzed_buckets:
                            self.print_info(f"Skipping {bucket_name} (already analyzed)")
                            continue

                        self.print_info(f"\n[*] Analyzing contents of {bucket_name}...")
                        try:
                            self._analyze_gcp_bucket_contents(bucket)
                            analyzed_buckets.add(bucket_name)
                            self.checkpoint('gcp_storage_enumeration', 'analyzed_buckets', list(analyzed_buckets))
                        except Exception as e:
                            self.print_error(f"Analysis failed for {bucket_name}: {e}")
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
                            hits = self._scan_file_for_secrets(output_path, f"gcp:{bucket_name}/{f['key']}")
                            if hits:
                                bucket_info.setdefault('secret_findings', []).append({'file': f['key'], 'secrets': hits})

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

                    # Skip if we already know the key is invalid (set to empty after failed validation)
                    if self.config.get('_hibp_validated') == False:
                        return breaches

                    try:
                        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                        headers = {
                            'User-Agent': 'Penetration-Testing-Reconnaissance-Tool',
                            'hibp-api-key': self.config.get('hibp_api_key', '')
                        }
                        response = requests.get(url, headers=headers, timeout=10)

                        if response.status_code == 200:
                            data = response.json()
                            breaches = [breach['Name'] for breach in data]
                        elif response.status_code == 404:
                            pass  # No breaches found
                        elif response.status_code == 401:
                            if self.config.get('hibp_api_key'):
                                # Key provided but invalid
                                if not self._handle_invalid_token('hibp'):
                                    self.config['_hibp_validated'] = False
                            else:
                                self.print_warning("HIBP API requires a key. Get one at https://haveibeenpwned.com/API/Key")
                                self.config['_hibp_validated'] = False
                        elif response.status_code == 429:
                            self.print_warning(f"HIBP rate limit hit for {email}")
                            time.sleep(2)
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
                """Generate consolidated multi-domain report"""
                self.print_section("GENERATING REPORT")
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')

                # Structured JSON (full per-domain fidelity + client network)
                json_file = self.output_dir / f"recon_results_{ts}.json"
                with open(json_file, 'w') as f:
                    json.dump({
                        'client': self.client_name,
                        'domains': self.all_results,
                        'network': self.client_results
                    }, f, indent=2, default=str)
                self.print_success(f"JSON results saved to: {json_file}")

                # Merged flat JSON for downstream tooling
                if getattr(self, 'consolidated', None):
                    merged_file = self.output_dir / f"recon_merged_{ts}.json"
                    with open(merged_file, 'w') as f:
                        json.dump(self.consolidated, f, indent=2, default=str)
                    self.print_success(f"Merged results saved to: {merged_file}")

                saved = (self.domain, self.results, self.current_domain)

                # Combined markdown report
                md_file = self.output_dir / f"recon_report_{ts}.md"
                with open(md_file, 'w') as cf:
                    cf.write(f"# Penetration Testing Reconnaissance Report\n\n")
                    cf.write(f"**Client:** {self.client_name}\n\n")
                    cf.write(f"**Domains:** {', '.join(self.domains)}\n\n")
                    cf.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    cf.write(f"---\n\n")
                    network = self.client_results.get('network_scan', {})
                    if network:
                        cf.write(f"## Client Network Enumeration\n\n")
                        for host in sorted(network.keys()):
                            ports = network[host]
                            cf.write(f"### {host}\n\n")
                            cf.write(f"| Port | State | Service | Version |\n")
                            cf.write(f"|------|-------|---------|---------|\n")
                            for port in sorted(ports.keys(), key=lambda x: int(x) if str(x).isdigit() else 0):
                                pd = ports[port]
                                cf.write(f"| {port} | {pd.get('state','')} | {pd.get('service','')} | {pd.get('version','')} |\n")
                            cf.write(f"\n")

                for d in self.domains:
                    self.current_domain = d
                    self.domain = d
                    self.results = self.all_results[d]
                    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', d)
                    tmp_md = self.output_dir / f".section_{safe}.md"
                    self._generate_markdown_report(tmp_md)
                    body = tmp_md.read_text()
                    marker = "\n---\n"
                    idx = body.find(marker)
                    if idx != -1:
                        body = body[idx + len(marker):]
                    with open(md_file, 'a') as cf:
                        cf.write(f"\n\n# DOMAIN: {d}\n\n")
                        cf.write(body)
                    try:
                        tmp_md.unlink()
                    except Exception:
                        pass

                self.domain, self.results, self.current_domain = saved
                self.print_success(f"Markdown report saved to: {md_file}")

                # Combined report template
                template_file = self.output_dir / f"report_template_{ts}.txt"
                with open(template_file, 'w') as tf:
                    tf.write(f"REPORT TEMPLATE - {self.client_name}\n")
                    tf.write(f"Domains: {', '.join(self.domains)}\n")
                    tf.write(f"{'='*80}\n\n")
                for d in self.domains:
                    self.current_domain = d
                    self.domain = d
                    self.results = self.all_results[d]
                    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', d)
                    tmp_tpl = self.output_dir / f".tpl_{safe}.txt"
                    self._generate_report_template(tmp_tpl)
                    body = tmp_tpl.read_text()
                    with open(template_file, 'a') as tf:
                        tf.write(f"\n\n{'#'*80}\n# DOMAIN: {d}\n{'#'*80}\n\n")
                        tf.write(body)
                    try:
                        tmp_tpl.unlink()
                    except Exception:
                        pass
                self.domain, self.results, self.current_domain = saved
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

                    # Domain WHOIS
                    domain_whois = self.results.get('scope_validation', {}).get('domain_whois', {})
                    if domain_whois:
                        f.write(f"### Domain Registration ({self.domain})\n\n")

                        if domain_whois.get('privacy_protected'):
                            f.write(f"**Note:** Domain uses privacy protection\n\n")

                        if domain_whois.get('organizations'):
                            f.write(f"**Organizations:**\n")
                            for org in domain_whois['organizations']:
                                f.write(f"- {org}\n")
                            f.write(f"\n")

                        if domain_whois.get('emails'):
                            f.write(f"**Contact Emails:**\n")
                            for email in domain_whois['emails']:
                                f.write(f"- {email}\n")
                            f.write(f"\n")

                        if domain_whois.get('phones'):
                            f.write(f"**Contact Phones:**\n")
                            for phone in domain_whois['phones']:
                                f.write(f"- {phone}\n")
                            f.write(f"\n")

                        if domain_whois.get('addresses'):
                            f.write(f"**Physical Addresses:**\n")
                            for addr in domain_whois['addresses']:
                                addr_str = f"{addr['street']}, {addr['city']}"
                                if addr.get('state'):
                                    addr_str += f", {addr['state']}"
                                if addr.get('postal_code'):
                                    addr_str += f" {addr['postal_code']}"
                                if addr.get('country'):
                                    addr_str += f", {addr['country']}"
                                f.write(f"- {addr_str} ({addr.get('source', 'registrant')})\n")
                            f.write(f"\n")

                        if domain_whois.get('name_servers'):
                            f.write(f"**Name Servers:**\n")
                            for ns in domain_whois['name_servers']:
                                f.write(f"- {ns}\n")
                            f.write(f"\n")

                        if domain_whois.get('created'):
                            f.write(f"**Created:** {domain_whois['created']}\n")
                        if domain_whois.get('expires'):
                            f.write(f"**Expires:** {domain_whois['expires']}\n")
                        f.write(f"\n")

                    # IP Range WHOIS
                    whois = self.results.get('scope_validation', {}).get('whois', {})
                    if whois:
                        f.write(f"### IP Range Ownership\n\n")
                        for ip_range, info in whois.items():
                            f.write(f"#### {ip_range}\n")
                            f.write(f"- **Organization:** {info.get('org', 'N/A')}\n")
                            f.write(f"- **Net Range:** {info.get('netrange', 'N/A')}\n")
                            f.write(f"- **Country:** {info.get('country', 'N/A')}\n\n")

                    # M365/Azure AD Tenant Attribution
                    m365 = self.results.get('m365_tenant', {})
                    if m365 and m365.get('is_m365'):
                        f.write(f"## M365/Azure AD Tenant Attribution\n\n")
                        f.write(f"- **Tenant ID:** {m365.get('tenant_id', 'Unknown')}\n")
                        if m365.get('tenant_region'):
                            f.write(f"- **Tenant Region:** {m365['tenant_region']}\n")
                        if m365.get('cloud_instance'):
                            f.write(f"- **Cloud Instance:** {m365['cloud_instance']}\n")
                        if m365.get('namespace_type'):
                            f.write(f"- **Namespace Type:** {m365['namespace_type']}\n")
                        if m365.get('federation_brand'):
                            f.write(f"- **Federation Brand:** {m365['federation_brand']}\n")
                        if m365.get('namespace_type') == 'Federated':
                            if m365.get('auth_url'):
                                f.write(f"- **Federation AuthURL:** {m365['auth_url']}\n")
                            if m365.get('federation_host'):
                                f.write(f"- **Federation Host:** {m365['federation_host']}\n")
                            f.write(f"\n**Note:** Federated tenant identified. On-premises identity provider (likely ADFS) presents additional external attack surface.\n")
                        elif m365.get('namespace_type') == 'Managed':
                            f.write(f"\n**Note:** Cloud-native managed tenant. Authentication surface is the M365 sign-in endpoint.\n")
                        f.write(f"\n")
                    elif m365 and not m365.get('is_m365'):
                        f.write(f"## M365/Azure AD Tenant Attribution\n\n")
                        f.write(f"Domain does not appear to be associated with an M365/Azure AD tenant.\n\n")

                    # Email Security Posture (SPF/DKIM/DMARC)
                    email_sec = self.results.get('email_security', {})
                    if email_sec:
                        f.write(f"## Email Security Posture\n\n")
                        f.write(f"**Overall Severity:** {email_sec.get('overall_severity', 'Unknown')}\n\n")

                        # SPF
                        spf = email_sec.get('spf', {})
                        f.write(f"### SPF (Sender Policy Framework)\n\n")
                        if spf.get('present'):
                            f.write(f"- **Record:** `{spf.get('record', '')}`\n")
                            f.write(f"- **Qualifier:** {spf.get('qualifier', 'Unknown')}\n")
                            f.write(f"- **DNS Lookups:** {spf.get('dns_lookup_count', 0)}/10\n")
                            if spf.get('includes'):
                                f.write(f"- **Includes:** {', '.join(spf['includes'])}\n")
                            if spf.get('multiple_records'):
                                f.write(f"- **Multiple Records:** Yes (RFC violation)\n")
                        else:
                            f.write(f"- **Status:** No SPF record present\n")

                        if spf.get('findings'):
                            f.write(f"\n**SPF Findings:**\n\n")
                            for finding in spf['findings']:
                                f.write(f"- **[{finding['severity']}]** {finding['finding']}\n")
                                f.write(f"  - {finding['detail']}\n")
                        f.write(f"\n")

                        # DMARC
                        dmarc = email_sec.get('dmarc', {})
                        f.write(f"### DMARC (Domain-based Message Authentication)\n\n")
                        if dmarc.get('present'):
                            f.write(f"- **Record:** `{dmarc.get('record', '')}`\n")
                            f.write(f"- **Policy (p):** {dmarc.get('policy', 'Unknown')}\n")
                            if dmarc.get('subdomain_policy'):
                                f.write(f"- **Subdomain Policy (sp):** {dmarc['subdomain_policy']}\n")
                            f.write(f"- **Percent (pct):** {dmarc.get('pct', '100')}\n")
                            if dmarc.get('rua'):
                                f.write(f"- **Aggregate Reports (rua):** {', '.join(dmarc['rua'])}\n")
                            if dmarc.get('ruf'):
                                f.write(f"- **Forensic Reports (ruf):** {', '.join(dmarc['ruf'])}\n")
                            f.write(f"- **SPF Alignment:** {dmarc.get('aspf', 'r')}\n")
                            f.write(f"- **DKIM Alignment:** {dmarc.get('adkim', 'r')}\n")
                        else:
                            f.write(f"- **Status:** No DMARC record present\n")

                        if dmarc.get('findings'):
                            f.write(f"\n**DMARC Findings:**\n\n")
                            for finding in dmarc['findings']:
                                f.write(f"- **[{finding['severity']}]** {finding['finding']}\n")
                                f.write(f"  - {finding['detail']}\n")
                        f.write(f"\n")

                        # DKIM
                        dkim = email_sec.get('dkim', {})
                        f.write(f"### DKIM (DomainKeys Identified Mail)\n\n")
                        f.write(f"- **Selectors Checked:** {len(dkim.get('selectors_checked', []))}\n")
                        f.write(f"- **Selectors Found:** {len(dkim.get('selectors_found', []))}\n")

                        if dkim.get('selectors_found'):
                            f.write(f"\n**Active DKIM Selectors:**\n\n")
                            for selector, record_data in dkim.get('records', {}).items():
                                f.write(f"#### {selector}\n")
                                f.write(f"- **Key Length:** {record_data.get('key_length', 'unknown')} bits\n")
                                f.write(f"- **Key Type:** {record_data.get('key_type', 'rsa')}\n")
                                f.write(f"- **Hash Algorithms:** {record_data.get('hash_algorithms', 'sha1,sha256')}\n")
                                f.write(f"- **Service Type:** {record_data.get('service_type', '*')}\n")
                                if not record_data.get('key_present'):
                                    f.write(f"- **Status:** Empty public key (revoked)\n")
                                f.write(f"\n")

                        if dkim.get('findings'):
                            f.write(f"**DKIM Findings:**\n\n")
                            for finding in dkim['findings']:
                                f.write(f"- **[{finding['severity']}]** {finding['finding']}\n")
                                f.write(f"  - {finding['detail']}\n")
                        f.write(f"\n")

                    # ADFS Endpoint Discovery
                    adfs = self.results.get('adfs', {})
                    hosts_probed = adfs.get('hosts_probed', [])
                    reachable_hosts = [h for h in hosts_probed if h.get('reachable')]

                    if reachable_hosts:
                        f.write(f"## ADFS Endpoint Discovery\n\n")
                        f.write(f"**Reachable ADFS Hosts:** {len(reachable_hosts)}\n\n")

                        version_info = adfs.get('version_info', {})
                        if version_info.get('adfs_version'):
                            f.write(f"**ADFS Version:** {version_info['adfs_version']}\n\n")
                        if version_info.get('build_number'):
                            f.write(f"**Build Number:** {version_info['build_number']}\n\n")
                        if version_info.get('oauth2_supported'):
                            f.write(f"**OAuth2 Support:** Yes (ADFS 3.0+)\n\n")

                        fed_metadata = adfs.get('federation_metadata', {})
                        if fed_metadata.get('entity_id'):
                            f.write(f"**Entity ID:** `{fed_metadata['entity_id']}`\n\n")

                        for host_data in reachable_hosts:
                            host = host_data['host']
                            f.write(f"### {host}\n\n")

                            for endpoint_name, endpoint_data in host_data.get('endpoints', {}).items():
                                if endpoint_data.get('present'):
                                    f.write(f"- **{endpoint_name}:** {endpoint_data.get('url', '')} (status {endpoint_data.get('status_code', 'N/A')})\n")
                                    if endpoint_data.get('build_number'):
                                        f.write(f"  - Build: {endpoint_data['build_number']}\n")
                                    if endpoint_data.get('supported_protocols'):
                                        f.write(f"  - Protocols: {', '.join(endpoint_data['supported_protocols'])}\n")
                                    if endpoint_data.get('signing_cert_present'):
                                        f.write(f"  - Token signing certificate present\n")
                                    if endpoint_data.get('ws_trust_supported'):
                                        f.write(f"  - WS-Trust MEX active\n")
                                    if endpoint_data.get('oauth2_supported'):
                                        f.write(f"  - OAuth2 endpoint active\n")

                            f.write(f"\n")

                        supported_endpoints = adfs.get('supported_endpoints', [])
                        if supported_endpoints:
                            f.write(f"### Federation Endpoints Discovered\n\n")
                            for url in supported_endpoints[:20]:
                                f.write(f"- `{url}`\n")
                            f.write(f"\n")

                        f.write(f"**Note:** ADFS version disclosure provides input for vulnerability analysis. ")
                        f.write(f"Recent CVE history on ADFS includes authentication bypass, golden SAML attacks, ")
                        f.write(f"and pre-auth disclosure issues. Review current advisories against the identified version before Phase 3.\n\n")

                    # DNS Enumeration
                    f.write(f"## DNS Enumeration\n\n")
                    dns = self.results.get('dns_enumeration', {})

                    resolved_external = dns.get('resolved_external', {})
                    resolved_internal = dns.get('resolved_internal', {})
                    resolved_in_authorized_scope = dns.get('resolved_in_authorized_scope', {})
                    resolved = dns.get('resolved', {})

                    f.write(f"**Total Subdomains Discovered:** {dns.get('total_discovered', 0)}\n")
                    f.write(f"**Resolved (External):** {len(resolved_external)}\n")
                    f.write(f"**Resolved (Internal):** {len(resolved_internal)}\n")
                    if resolved_in_authorized_scope:
                        f.write(f"**Resolved (In Authorized IP Scope):** {len(resolved_in_authorized_scope)}\n")
                    f.write(f"\n")

                    # Confirmed In-Scope Targets (Tier 1: resolves into authorized IP ranges)
                    if resolved_in_authorized_scope:
                        f.write(f"### Confirmed In-Scope Targets ({len(resolved_in_authorized_scope)})\n\n")
                        f.write(f"The following subdomains resolve to IP addresses within the authorized testing scope. ")
                        f.write(f"These represent confirmed in-scope test targets and should be prioritized for active testing.\n\n")
                        for subdomain, data in sorted(resolved_in_authorized_scope.items()):
                            ips_str = ', '.join(data['ips'])
                            ranges_str = ', '.join(data['matched_ranges'])
                            f.write(f"- `{subdomain}` -> {ips_str} (scope: {ranges_str})\n")
                        f.write(f"\n")

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

                    # External resolved subdomains (public IPs)
                    if resolved_external:
                        f.write(f"### External Subdomains ({len(resolved_external)})\n\n")
                        f.write(f"Subdomains resolving to public IP addresses:\n\n")
                        for subdomain, ips in sorted(resolved_external.items()):
                            scope_marker = " **[IN AUTHORIZED SCOPE]**" if subdomain in resolved_in_authorized_scope else ""
                            f.write(f"- `{subdomain}` -> {', '.join(ips)}{scope_marker}\n")
                        f.write(f"\n")

                    # Internal resolved subdomains (private IPs) - Information Disclosure
                    if resolved_internal:
                        f.write(f"### Internal Subdomains ({len(resolved_internal)}) - INFORMATION DISCLOSURE\n\n")
                        f.write(f"**Finding:** Internal hostnames exposed in public DNS records.\n\n")
                        f.write(f"**Risk:** These subdomains resolve to private/internal IP addresses (RFC 1918), ")
                        f.write(f"revealing internal network structure to external attackers. This information can be used to:\n\n")
                        f.write(f"- Map internal network topology\n")
                        f.write(f"- Identify internal naming conventions\n")
                        f.write(f"- Target systems during internal penetration testing\n")
                        f.write(f"- Craft more convincing phishing attacks\n\n")
                        f.write(f"**Affected Subdomains:**\n\n")
                        for subdomain, ips in sorted(resolved_internal.items()):
                            f.write(f"- `{subdomain}` -> {', '.join(ips)}\n")
                        f.write(f"\n")
                        f.write(f"**Recommendation:** Remove internal DNS records from public-facing DNS servers ")
                        f.write(f"or implement split-horizon DNS to prevent internal hostname disclosure.\n\n")

                    # Fallback to old resolved format if new format not available
                    if not resolved_external and not resolved_internal and resolved:
                        f.write(f"### Resolved Subdomains ({len(resolved)})\n\n")
                        f.write(f"Subdomains that successfully resolved to IP addresses:\n\n")
                        for subdomain, ips in sorted(resolved.items()):
                            f.write(f"- `{subdomain}` -> {', '.join(ips)}\n")
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

                    # Infrastructure Summary (from WHOIS)
                    infra_summary = dns.get('infrastructure_summary', {})
                    if infra_summary:
                        f.write(f"### Infrastructure Summary\n\n")
                        f.write(f"Organizations identified from IP WHOIS lookups:\n\n")
                        for org, data in sorted(infra_summary.items(), key=lambda x: len(x[1].get('ips', [])), reverse=True):
                            ip_count = len(data.get('ips', []))
                            f.write(f"#### {org}\n")
                            f.write(f"- **IPs:** {ip_count}\n")
                            if data.get('country'):
                                f.write(f"- **Country:** {data['country']}\n")
                            if data.get('netranges'):
                                f.write(f"- **Network Ranges:** {', '.join(data['netranges'])}\n")
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

                        appliance_hosts = {h: info for h, info in tech.items() if info.get('vpn_appliance')}
                        if appliance_hosts:
                            f.write(f"### Remote Access Appliances ({len(appliance_hosts)})\n\n")
                            for host, info in sorted(appliance_hosts.items()):
                                appliance = info['vpn_appliance']
                                f.write(f"#### {host}\n")
                                f.write(f"- **Appliance Class:** {appliance['class']}\n")
                                f.write(f"- **Version:** {appliance['version']}\n")
                                if appliance.get('discovered_on_port'):
                                    f.write(f"- **Discovered on Port:** {appliance['discovered_on_port']}\n")
                                if appliance.get('probe_path'):
                                    f.write(f"- **Detected At:** `{appliance['probe_path']}`\n")
                                if appliance.get('evidence'):
                                    f.write(f"- **Evidence:** {', '.join(appliance['evidence'])}\n")
                                f.write(f"\n")
                            f.write(f"**Note:** Remote access appliance version disclosure supports vulnerability analysis. ")
                            f.write(f"Recent CVE history on VPN/remote access appliances is heavy. Review current vendor advisories against the identified versions before Phase 3.\n\n")

                        alt_port_hosts = {}
                        for h, info in tech.items():
                            services = info.get('services_by_port', {})
                            alt_services = {p: s for p, s in services.items() if p not in ('80', '443')}
                            if alt_services:
                                alt_port_hosts[h] = alt_services

                        if alt_port_hosts:
                            f.write(f"### Alternate Port Services ({len(alt_port_hosts)} hosts)\n\n")
                            f.write(f"Services discovered on non-default HTTP/HTTPS ports. These commonly host admin interfaces, ")
                            f.write(f"development environments, or internal applications exposed externally.\n\n")
                            for host, alt_services in sorted(alt_port_hosts.items()):
                                f.write(f"#### {host}\n")
                                for port_str, port_data in sorted(alt_services.items(), key=lambda x: int(x[0])):
                                    f.write(f"- **Port {port_str} ({port_data.get('scheme', 'http')}):** status {port_data.get('status_code', 'N/A')}\n")
                                    if port_data.get('server'):
                                        f.write(f"  - Server: {port_data['server']}\n")
                                    if port_data.get('powered_by'):
                                        f.write(f"  - Powered By: {port_data['powered_by']}\n")
                                    if port_data.get('detected_technologies'):
                                        f.write(f"  - Technologies: {', '.join(port_data['detected_technologies'])}\n")
                                    if port_data.get('vpn_appliance'):
                                        f.write(f"  - VPN Appliance: {port_data['vpn_appliance']['class']} ({port_data['vpn_appliance']['version']})\n")
                                f.write(f"\n")

                        for domain, info in sorted(tech.items()):
                            f.write(f"### {domain}\n")
                            if info.get('server'):
                                f.write(f"- **Server:** {info['server']}\n")
                            if info.get('powered_by'):
                                f.write(f"- **Powered By:** {info['powered_by']}\n")
                            if info.get('detected_technologies'):
                                f.write(f"- **Technologies:** {', '.join(info['detected_technologies'])}\n")
                            if info.get('vpn_appliance'):
                                f.write(f"- **VPN Appliance:** {info['vpn_appliance']['class']} ({info['vpn_appliance']['version']})\n")

                            services = info.get('services_by_port', {})
                            if services:
                                active_ports = sorted([int(p) for p in services.keys()])
                                f.write(f"- **Active Ports:** {', '.join(str(p) for p in active_ports)}\n")

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
                        in_scope = [r for r in ip_ranges if r.get('in_scope') or r.get('contains_discovered_ips')]
                        out_scope = [r for r in ip_ranges if not r.get('in_scope') and not r.get('contains_discovered_ips')]

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

                    # Domain Registration Info
                    f.write("## Target Information\n\n")
                    domain_whois = self.results.get('scope_validation', {}).get('domain_whois', {})

                    if domain_whois:
                        if domain_whois.get('organizations'):
                            f.write(f"**Registered Organization:** {domain_whois['organizations'][0]}\n\n")

                        if domain_whois.get('addresses'):
                            addr = domain_whois['addresses'][0]
                            addr_str = f"{addr['street']}, {addr['city']}"
                            if addr.get('state'):
                                addr_str += f", {addr['state']}"
                            if addr.get('postal_code'):
                                addr_str += f" {addr['postal_code']}"
                            if addr.get('country'):
                                addr_str += f", {addr['country']}"
                            f.write(f"**Physical Location:** {addr_str}\n\n")

                        if domain_whois.get('phones'):
                            f.write(f"**Contact Phone:** {domain_whois['phones'][0]}\n\n")

                    # Ownership Verification
                    f.write("### Ownership Verification\n\n")
                    whois = self.results.get('scope_validation', {}).get('whois', {})
                    if whois:
                        for ip_range, info in whois.items():
                            org = info.get('org', 'Unknown')
                            f.write(f"- {ip_range} - Confirmed owned by {org}\n")
                        f.write("\n")
                    else:
                        f.write("No IP ranges provided for ownership verification.\n\n")

                    # DNS Enumeration Section
                    f.write("## Reconnaissance and OSINT\n\n")
                    f.write("### Finding the External Footprint\n\n")

                    dns = self.results.get('dns_enumeration', {})
                    total = dns.get('total_discovered', 0)
                    resolved_external = dns.get('resolved_external', {})
                    resolved_internal = dns.get('resolved_internal', {})
                    resolved_in_authorized_scope = dns.get('resolved_in_authorized_scope', {})
                    resolved = dns.get('resolved', {})

                    f.write(f"DNS enumeration revealed {total} subdomains. ")
                    if resolved_external or resolved_internal:
                        f.write(f"Of these, {len(resolved_external)} resolve to external IPs and {len(resolved_internal)} resolve to internal IPs.")
                        if resolved_in_authorized_scope:
                            f.write(f" {len(resolved_in_authorized_scope)} of these resolve directly into the authorized IP scope.")
                        f.write("\n\n")
                    else:
                        f.write(f"This mapped out what was reachable from the internet.\n\n")

                    # Confirmed In-Scope Targets
                    if resolved_in_authorized_scope:
                        f.write("### Confirmed In-Scope Targets\n\n")
                        f.write(f"Cross-referencing DNS enumeration results against the authorized IP ranges identified ")
                        f.write(f"{len(resolved_in_authorized_scope)} subdomain(s) resolving directly into the in-scope network space. ")
                        f.write(f"These represent the highest-priority targets for active testing.\n\n")

                        for subdomain, data in sorted(resolved_in_authorized_scope.items()):
                            ips_str = ', '.join(data['ips'])
                            ranges_str = ', '.join(data['matched_ranges'])
                            f.write(f"- {subdomain} -> {ips_str} (scope: {ranges_str})\n")
                        f.write("\n")

                    # Use external resolved if available, fall back to resolved
                    display_resolved = resolved_external if resolved_external else resolved
                    if display_resolved:
                        f.write("Additional external subdomains identified:\n")
                        display_items = [(k, v) for k, v in sorted(display_resolved.items())
                                        if k not in resolved_in_authorized_scope]
                        for subdomain, ips in display_items[:10]:
                            f.write(f"- {subdomain} ({', '.join(ips)})\n")
                        f.write("\n")

                    # Internal DNS Information Disclosure
                    if resolved_internal:
                        f.write("### Internal DNS Information Disclosure\n\n")
                        f.write(f"**Finding:** {len(resolved_internal)} internal hostnames exposed in public DNS.\n\n")
                        f.write("During DNS enumeration, multiple subdomains were discovered that resolve to private ")
                        f.write("RFC 1918 IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x). This constitutes an ")
                        f.write("information disclosure vulnerability as it reveals:\n\n")
                        f.write("- Internal network addressing scheme\n")
                        f.write("- Internal hostname naming conventions\n")
                        f.write("- Potential internal services and their purposes\n\n")
                        f.write("**Affected Systems (sample):**\n\n")
                        for subdomain in sorted(resolved_internal.keys())[:15]:
                            ips = resolved_internal[subdomain]
                            f.write(f"- {subdomain} -> {', '.join(ips)}\n")
                        if len(resolved_internal) > 15:
                            f.write(f"- ... and {len(resolved_internal) - 15} more\n")
                        f.write("\n")
                        f.write("**Recommendation:** Implement split-horizon DNS to prevent internal records from being ")
                        f.write("served to external queries, or remove internal records from public DNS zones entirely.\n\n")

                    # M365/Azure AD Tenant Attribution
                    m365 = self.results.get('m365_tenant', {})
                    if m365 and m365.get('is_m365'):
                        f.write("### M365/Azure AD Tenant Attribution\n\n")
                        brand = m365.get('federation_brand') or self.client_name
                        namespace = m365.get('namespace_type', 'Unknown')

                        f.write(f"Cloud identity reconnaissance confirmed the target operates a Microsoft 365 / Azure AD ")
                        f.write(f"tenant. The tenant was attributed through publicly accessible Microsoft authentication ")
                        f.write(f"endpoints which disclose tenant identifiers, brand information, and federation posture.\n\n")

                        f.write(f"- Tenant ID: {m365.get('tenant_id', 'Unknown')}\n")
                        if m365.get('tenant_region'):
                            f.write(f"- Tenant Region: {m365['tenant_region']}\n")
                        f.write(f"- Federation Brand: {brand}\n")
                        f.write(f"- Namespace Type: {namespace}\n")
                        if m365.get('cloud_instance'):
                            f.write(f"- Cloud Instance: {m365['cloud_instance']}\n")
                        f.write("\n")

                        if namespace == 'Federated':
                            f.write("The tenant is configured for federated authentication, indicating an on-premises ")
                            f.write("identity provider (typically ADFS) handles user authentication. ")
                            if m365.get('federation_host'):
                                f.write(f"The federation endpoint resides at {m365['federation_host']}. ")
                            f.write("Federated tenants present additional external attack surface through the on-premises ")
                            f.write("IdP, which becomes a primary target for credential attacks, version-specific ")
                            f.write("vulnerabilities, and authentication bypass research.\n\n")
                        elif namespace == 'Managed':
                            f.write("The tenant uses cloud-native managed authentication. The primary external ")
                            f.write("authentication surface is the M365 sign-in endpoint, which becomes the target ")
                            f.write("for password spray attacks, valid-user enumeration, and conditional access ")
                            f.write("policy assessment.\n\n")

                    # Email Security Posture Narrative
                    email_sec = self.results.get('email_security', {})
                    if email_sec:
                        f.write("### Email Authentication Posture (SPF/DKIM/DMARC)\n\n")

                        spf = email_sec.get('spf', {})
                        dmarc = email_sec.get('dmarc', {})
                        dkim = email_sec.get('dkim', {})
                        severity = email_sec.get('overall_severity', 'Unknown')

                        f.write(f"Email authentication posture assessment evaluated the domain's SPF, DKIM, and DMARC configuration. ")
                        f.write(f"Overall severity is rated **{severity}** based on the findings identified below. ")
                        f.write(f"Weaknesses in email authentication directly impact the organization's exposure to phishing campaigns ")
                        f.write(f"using its own domain.\n\n")

                        # SPF narrative
                        f.write("#### SPF Configuration\n\n")
                        if not spf.get('present'):
                            f.write("The domain has no SPF record published. Without SPF, any internet sender can claim to originate ")
                            f.write("mail from this domain. Receivers have no authorization data to validate against, and anti-spoofing ")
                            f.write("protection is entirely absent.\n\n")
                        else:
                            qualifier = spf.get('qualifier', 'unknown')
                            if qualifier == '-all':
                                f.write(f"SPF is properly configured with the -all qualifier, instructing receivers to reject mail ")
                                f.write(f"from unauthorized sources. The record performs {spf.get('dns_lookup_count', 0)} DNS lookups ")
                                f.write(f"out of the RFC-mandated 10-lookup limit.\n\n")
                            elif qualifier == '~all':
                                f.write(f"SPF is configured with the ~all (soft fail) qualifier. Mail from unauthorized sources is ")
                                f.write(f"flagged as suspicious but typically still delivered. Hardening to -all (hard fail) is recommended ")
                                f.write(f"once the existing SPF deployment is validated to be complete.\n\n")
                            elif qualifier == '?all':
                                f.write(f"SPF is configured with the ?all (neutral) qualifier, which provides no enforcement guidance ")
                                f.write(f"to receivers. Mail from unauthorized sources is treated identically to legitimate mail. ")
                                f.write(f"The protection is effectively absent.\n\n")
                            elif qualifier == '+all':
                                f.write(f"SPF is configured with +all, instructing receivers to accept mail from any source as ")
                                f.write(f"legitimate. This is a critical misconfiguration that completely defeats SPF and explicitly ")
                                f.write(f"authorizes domain spoofing.\n\n")

                            if spf.get('dns_lookup_count', 0) > 10:
                                f.write(f"The SPF record performs {spf['dns_lookup_count']} DNS lookups, exceeding the RFC 7208 limit ")
                                f.write(f"of 10. Receiving servers will return a permerror and SPF validation fails entirely, ")
                                f.write(f"effectively disabling SPF enforcement regardless of the qualifier configuration.\n\n")

                        # DMARC narrative
                        f.write("#### DMARC Configuration\n\n")
                        if not dmarc.get('present'):
                            f.write("The domain has no DMARC record published. Without DMARC, receivers have no enforcement policy ")
                            f.write("for handling messages that fail SPF or DKIM authentication. Messages failing authentication may ")
                            f.write("still be delivered, and the organization has no visibility into authentication failures across ")
                            f.write("the mail ecosystem.\n\n")
                        else:
                            policy = dmarc.get('policy', 'unknown')
                            if policy == 'reject':
                                f.write(f"DMARC is configured with p=reject, the strongest enforcement policy. Mail failing ")
                                f.write(f"authentication is rejected at the receiver. ")
                            elif policy == 'quarantine':
                                f.write(f"DMARC is configured with p=quarantine. Mail failing authentication is delivered to the ")
                                f.write(f"recipient's spam folder rather than rejected outright. ")
                            elif policy == 'none':
                                f.write(f"DMARC is configured with p=none, a monitor-only posture. The domain receives DMARC reports ")
                                f.write(f"but no enforcement action is taken on failing mail. This is a transitional configuration ")
                                f.write(f"and does not provide spoofing protection. ")

                            pct = dmarc.get('pct', '100')
                            try:
                                pct_val = int(pct)
                                if pct_val < 100 and policy in ('quarantine', 'reject'):
                                    f.write(f"However, pct={pct_val} means only {pct_val}% of failing mail is subject to the policy. ")
                                    f.write(f"The remaining {100 - pct_val}% bypasses enforcement entirely. ")
                            except ValueError:
                                pass

                            rua = dmarc.get('rua', [])
                            if rua:
                                f.write(f"Aggregate reports are sent to {', '.join(rua)}. ")
                            else:
                                f.write(f"No aggregate reporting addresses are configured, limiting visibility into authentication ")
                                f.write(f"failures and spoofing attempts. ")

                            f.write("\n\n")

                        # DKIM narrative
                        f.write("#### DKIM Configuration\n\n")
                        if not dkim.get('selectors_found'):
                            f.write(f"Probing common DKIM selector names did not return any active DKIM records. The domain may not ")
                            f.write(f"sign outbound mail with DKIM, or may use non-standard selector names not covered by the probe set. ")
                            f.write(f"Without DKIM, recipients cannot cryptographically verify that mail content originated from an ")
                            f.write(f"authorized sender and has not been modified in transit.\n\n")
                        else:
                            selectors = dkim.get('selectors_found', [])
                            f.write(f"Active DKIM selectors were identified: {', '.join(selectors)}. ")

                            weak_keys = [s for s, data in dkim.get('records', {}).items()
                                        if isinstance(data.get('key_length'), int) and data['key_length'] <= 1024]
                            if weak_keys:
                                f.write(f"\n\nThe following selectors use 1024-bit or weaker keys: {', '.join(weak_keys)}. ")
                                f.write(f"NIST and RFC 8301 recommend 2048-bit RSA keys as the minimum for DKIM signing. ")
                                f.write(f"Weaker keys should be rotated to stronger keys as part of DKIM hardening.\n\n")
                            else:
                                f.write("All identified selectors use 2048-bit or stronger keys, meeting current cryptographic recommendations.\n\n")

                    # ADFS Endpoint Discovery
                    adfs = self.results.get('adfs', {})
                    hosts_probed = adfs.get('hosts_probed', [])
                    reachable_hosts = [h for h in hosts_probed if h.get('reachable')]

                    if reachable_hosts:
                        f.write("### ADFS Identity Provider Reconnaissance\n\n")
                        version_info = adfs.get('version_info', {})

                        f.write(f"ADFS endpoint reconnaissance against the federated identity provider revealed ")
                        f.write(f"the version, supported authentication protocols, and federation metadata. This ")
                        f.write(f"information establishes the attack surface for the on-premises identity provider.\n\n")

                        if version_info.get('adfs_version'):
                            f.write(f"The deployed ADFS version was identified as {version_info['adfs_version']}")
                            if version_info.get('build_number'):
                                f.write(f" (build {version_info['build_number']})")
                            f.write(". ")

                        protocols = set()
                        for host_data in reachable_hosts:
                            for endpoint_data in host_data.get('endpoints', {}).values():
                                if endpoint_data.get('supported_protocols'):
                                    protocols.update(endpoint_data['supported_protocols'])
                                if endpoint_data.get('ws_trust_supported'):
                                    protocols.add('WS-Trust MEX')
                                if endpoint_data.get('oauth2_supported'):
                                    protocols.add('OAuth2')

                        if protocols:
                            f.write(f"Supported federation protocols include: {', '.join(sorted(protocols))}. ")

                        fed_metadata = adfs.get('federation_metadata', {})
                        if fed_metadata.get('entity_id'):
                            f.write(f"The federation entity identifier was disclosed as {fed_metadata['entity_id']}. ")

                        f.write("\n\n")
                        f.write("ADFS version disclosure provides the input for vulnerability analysis against the ")
                        f.write("identity provider. The on-premises IdP is a high-value target as compromise can lead ")
                        f.write("to credential capture, golden SAML attacks, or authentication bypass affecting all ")
                        f.write("federated cloud services. Current vendor advisories should be reviewed against the ")
                        f.write("identified version before active testing.\n\n")

                    # Subdomain Takeover
                    takeovers = self.results.get('subdomain_takeovers', [])
                    if takeovers:
                        f.write("### Subdomain Takeover Vulnerabilities\n\n")
                        f.write(f"Analysis identified {len(takeovers)} subdomain(s) potentially vulnerable to takeover attacks:\n\n")
                        for vuln in takeovers:
                            f.write(f"- {vuln['subdomain']} - Points to unclaimed {vuln['service']} resource\n")
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
                            f.write(f"- Web Servers: {', '.join(all_servers)}\n")
                        if all_tech:
                            f.write(f"- Technologies: {', '.join(all_tech)}\n")
                        f.write("\n")

                        # Remote access appliance narrative
                        appliance_hosts = {h: info for h, info in tech.items() if info.get('vpn_appliance')}
                        if appliance_hosts:
                            f.write("### Remote Access Appliance Identification\n\n")
                            f.write(f"Technology fingerprinting identified {len(appliance_hosts)} remote access appliance(s) ")
                            f.write("exposed to the internet. These appliances handle VPN, remote desktop, or federated ")
                            f.write("authentication and represent high-value targets given the heavy CVE history on this class of devices.\n\n")

                            for host, info in sorted(appliance_hosts.items()):
                                appliance = info['vpn_appliance']
                                version_part = f" version {appliance['version']}" if appliance['version'] != 'Unknown' else ""
                                port_part = f" on port {appliance['discovered_on_port']}" if appliance.get('discovered_on_port') else ""
                                f.write(f"- {host} - {appliance['class']}{version_part}{port_part}\n")
                            f.write("\n")
                            f.write("Identified appliance versions should be cross-referenced against current vendor advisories. ")
                            f.write("Common high-yield CVE classes on these devices include pre-authentication remote code execution, ")
                            f.write("authentication bypass, and path traversal vulnerabilities.\n\n")

                        # Alternate port services narrative
                        alt_port_count = 0
                        alt_port_hosts_summary = []
                        for h, info in tech.items():
                            services = info.get('services_by_port', {})
                            alt_services = {p: s for p, s in services.items() if p not in ('80', '443')}
                            if alt_services:
                                alt_port_count += 1
                                ports_list = sorted([int(p) for p in alt_services.keys()])
                                alt_port_hosts_summary.append((h, ports_list))

                        if alt_port_hosts_summary:
                            f.write("### Services on Alternate HTTP Ports\n\n")
                            f.write(f"Probing across common alternate HTTP/HTTPS ports identified {alt_port_count} host(s) ")
                            f.write("running services outside the standard 80/443 ports. Services on these ports frequently ")
                            f.write("host administrative interfaces, development environments, or internal applications that ")
                            f.write("were intended for restricted access but became externally reachable.\n\n")

                            for host, ports in sorted(alt_port_hosts_summary)[:15]:
                                f.write(f"- {host} - port(s) {', '.join(str(p) for p in ports)}\n")
                            if len(alt_port_hosts_summary) > 15:
                                f.write(f"- ... and {len(alt_port_hosts_summary) - 15} more\n")
                            f.write("\n")
                            f.write("Each identified alternate-port service should be reviewed during testing for default ")
                            f.write("credentials, exposed management functions, and unauthenticated access to sensitive ")
                            f.write("application functionality.\n\n")

                    # LinkedIn Intelligence
                    f.write("### Employee Enumeration via LinkedIn\n\n")
                    linkedin = self.results.get('linkedin_intel', {})
                    employees = linkedin.get('employees', [])

                    if employees:
                        f.write(f"LinkedIn reconnaissance identified {len(employees)} employee accounts associated with the organization.\n\n")
                        f.write("This intelligence enables targeted phishing campaigns and password spraying attacks against valid accounts.\n\n")
                    else:
                        f.write("Limited employee information was gathered through public LinkedIn sources.\n\n")

                    # Email Addresses Section
                    f.write("### Identifying Valid User Accounts\n\n")
                    emails = self.results.get('email_addresses', [])

                    if emails:
                        f.write(f"Public sources revealed {len(emails)} email addresses:\n\n")
                        for email in emails[:10]:
                            f.write(f"- {email}\n")
                        if len(emails) > 10:
                            f.write(f"- ... and {len(emails) - 10} more\n")
                        f.write("\n")
                    else:
                        f.write("No email addresses were discovered through passive reconnaissance.\n\n")

                    # Breach Data Section
                    f.write("### Searching for Compromised Credentials\n\n")
                    breaches = self.results.get('breach_data', {})

                    if breaches:
                        f.write(f"Breach databases were checked for client email addresses. {len(breaches)} accounts were found with exposed passwords:\n\n")
                        for email, breach_list in list(breaches.items())[:5]:
                            f.write(f"- {email} - Found in: {', '.join(breach_list[:3])}\n")
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
                                f.write(f"- {repo['repository']}/{repo['file_path']}\n")
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
                            f.write(f"- AS{asn['asn']} - {asn['owner']}\n")
                        f.write("\n")

                    if ip_ranges:
                        in_scope = [r for r in ip_ranges if r.get('in_scope') or r.get('contains_discovered_ips')]
                        out_scope = [r for r in ip_ranges if not r.get('in_scope') and not r.get('contains_discovered_ips')]

                        f.write(f"Total IP ranges discovered: {len(ip_ranges)}\n")
                        f.write(f"- Ranges within authorized scope: {len(in_scope)}\n")
                        f.write(f"- Ranges outside authorized scope: {len(out_scope)}\n\n")

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
                        f.write(f"- AWS S3: {len(found_s3)} ({len(public_s3)} public)\n")
                        f.write(f"- Azure Storage: {len(found_azure)} ({len(public_azure)} public)\n")
                        f.write(f"- GCP Storage: {len(found_gcp)} ({len(public_gcp)} public)\n\n")

                        if total_public > 0:
                            f.write(f"**{total_public} publicly accessible cloud storage resource(s) identified.**\n\n")
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

                        interesting_services = []
                        for host, ports in scan.items():
                            for port_num, port_info in ports.items():
                                service = port_info.get('service', 'unknown')
                                if any(keyword in service.lower() for keyword in ['vpn', 'ssh', 'rdp', 'http', 'ftp', 'smtp']):
                                    interesting_services.append(f"{host}:{port_num} ({service})")

                        if interesting_services:
                            f.write("Most promising targets for further investigation:\n")
                            for service in interesting_services[:10]:
                                f.write(f"- {service}\n")
                            f.write("\n")

    def _run_domain_modules(self):
                """Run the per-domain module sequence against the active domain"""
                if self.should_run_module('scope_validation'):
                    self.mark_module_status('scope_validation', 'in_progress')
                    try:
                        self.scope_validation()
                        self.mark_module_status('scope_validation', 'complete')
                    except Exception as e:
                        self.mark_module_status('scope_validation', 'failed', str(e))
                        self.print_error(f"scope_validation failed: {e}")

                if self.should_run_module('m365_tenant'):
                    if not self.args.skip_m365:
                        self.mark_module_status('m365_tenant', 'in_progress')
                        try:
                            self.m365_tenant_attribution()
                            self.mark_module_status('m365_tenant', 'complete')
                        except Exception as e:
                            self.mark_module_status('m365_tenant', 'failed', str(e))
                            self.print_error(f"m365_tenant failed: {e}")
                    else:
                        self.mark_module_status('m365_tenant', 'skipped')

                if self.should_run_module('adfs'):
                    if not self.args.skip_adfs:
                        self.mark_module_status('adfs', 'in_progress')
                        try:
                            self.adfs_endpoint_discovery()
                            self.mark_module_status('adfs', 'complete')
                        except Exception as e:
                            self.mark_module_status('adfs', 'failed', str(e))
                            self.print_error(f"adfs failed: {e}")
                    else:
                        self.mark_module_status('adfs', 'skipped')

                if self.should_run_module('email_security'):
                    if not self.args.skip_email_security:
                        self.mark_module_status('email_security', 'in_progress')
                        try:
                            self.email_security_posture()
                            self.mark_module_status('email_security', 'complete')
                        except Exception as e:
                            self.mark_module_status('email_security', 'failed', str(e))
                            self.print_error(f"email_security failed: {e}")
                    else:
                        self.mark_module_status('email_security', 'skipped')

                if self.should_run_module('dns_enumeration'):
                    self.mark_module_status('dns_enumeration', 'in_progress')
                    try:
                        self.dns_enumeration()
                        self.mark_module_status('dns_enumeration', 'complete')
                    except Exception as e:
                        self.mark_module_status('dns_enumeration', 'failed', str(e))
                        self.print_error(f"dns_enumeration failed: {e}")

                if not self.ip_ranges and self.should_run_module('post_dns_whois'):
                    self.mark_module_status('post_dns_whois', 'in_progress')
                    try:
                        self.post_dns_whois_lookup()
                        self.mark_module_status('post_dns_whois', 'complete')
                    except Exception as e:
                        self.mark_module_status('post_dns_whois', 'failed', str(e))
                        self.print_error(f"post_dns_whois failed: {e}")

                if self.should_run_module('technology_stack'):
                    self.mark_module_status('technology_stack', 'in_progress')
                    try:
                        self.technology_stack_identification()
                        self.mark_module_status('technology_stack', 'complete')
                    except Exception as e:
                        self.mark_module_status('technology_stack', 'failed', str(e))
                        self.print_error(f"technology_stack failed: {e}")

                if self.should_run_module('email_harvesting'):
                    self.mark_module_status('email_harvesting', 'in_progress')
                    try:
                        self.email_harvesting()
                        self.mark_module_status('email_harvesting', 'complete')
                    except Exception as e:
                        self.mark_module_status('email_harvesting', 'failed', str(e))
                        self.print_error(f"email_harvesting failed: {e}")

                if self.should_run_module('linkedin_enumeration'):
                    if self.config.get('linkedin_cookies'):
                        self.mark_module_status('linkedin_enumeration', 'in_progress')
                        try:
                            self.linkedin_enumeration()
                            self.mark_module_status('linkedin_enumeration', 'complete')
                        except Exception as e:
                            self.mark_module_status('linkedin_enumeration', 'failed', str(e))
                            self.print_error(f"linkedin_enumeration failed: {e}")
                    else:
                        self.print_info("Skipping LinkedIn enumeration (no cookies provided)")
                        self.mark_module_status('linkedin_enumeration', 'skipped')

                if self.should_run_module('breach_database_check'):
                    if not self.args.skip_breach_check:
                        self.mark_module_status('breach_database_check', 'in_progress')
                        try:
                            self.breach_database_check()
                            self.mark_module_status('breach_database_check', 'complete')
                        except Exception as e:
                            self.mark_module_status('breach_database_check', 'failed', str(e))
                            self.print_error(f"breach_database_check failed: {e}")
                    else:
                        self.mark_module_status('breach_database_check', 'skipped')

                if self.should_run_module('github_secret_scanning'):
                    if not self.args.skip_github:
                        self.mark_module_status('github_secret_scanning', 'in_progress')
                        try:
                            self.github_secret_scanning()
                            self.mark_module_status('github_secret_scanning', 'complete')
                        except Exception as e:
                            self.mark_module_status('github_secret_scanning', 'failed', str(e))
                            self.print_error(f"github_secret_scanning failed: {e}")
                    else:
                        self.mark_module_status('github_secret_scanning', 'skipped')

                if self.should_run_module('asn_enumeration'):
                    if not self.args.skip_asn:
                        self.mark_module_status('asn_enumeration', 'in_progress')
                        try:
                            self.asn_enumeration()
                            self.mark_module_status('asn_enumeration', 'complete')
                        except Exception as e:
                            self.mark_module_status('asn_enumeration', 'failed', str(e))
                            self.print_error(f"asn_enumeration failed: {e}")
                    else:
                        self.mark_module_status('asn_enumeration', 'skipped')

                if self.should_run_module('subdomain_takeover_detection'):
                    if not self.args.skip_subdomain_takeover:
                        self.mark_module_status('subdomain_takeover_detection', 'in_progress')
                        try:
                            self.subdomain_takeover_detection()
                            self.mark_module_status('subdomain_takeover_detection', 'complete')
                        except Exception as e:
                            self.mark_module_status('subdomain_takeover_detection', 'failed', str(e))
                            self.print_error(f"subdomain_takeover_detection failed: {e}")
                    else:
                        self.mark_module_status('subdomain_takeover_detection', 'skipped')

                if self.should_run_module('s3_bucket_enumeration'):
                    if not self.args.skip_s3:
                        self.mark_module_status('s3_bucket_enumeration', 'in_progress')
                        try:
                            self.s3_bucket_enumeration()
                            self.mark_module_status('s3_bucket_enumeration', 'complete')
                        except Exception as e:
                            self.mark_module_status('s3_bucket_enumeration', 'failed', str(e))
                            self.print_error(f"s3_bucket_enumeration failed: {e}")
                    else:
                        self.mark_module_status('s3_bucket_enumeration', 'skipped')

                if self.should_run_module('azure_storage_enumeration'):
                    if not self.args.skip_azure:
                        self.mark_module_status('azure_storage_enumeration', 'in_progress')
                        try:
                            self.azure_storage_enumeration()
                            self.mark_module_status('azure_storage_enumeration', 'complete')
                        except Exception as e:
                            self.mark_module_status('azure_storage_enumeration', 'failed', str(e))
                            self.print_error(f"azure_storage_enumeration failed: {e}")
                    else:
                        self.mark_module_status('azure_storage_enumeration', 'skipped')

                if self.should_run_module('gcp_storage_enumeration'):
                    if not self.args.skip_gcp:
                        self.mark_module_status('gcp_storage_enumeration', 'in_progress')
                        try:
                            self.gcp_storage_enumeration()
                            self.mark_module_status('gcp_storage_enumeration', 'complete')
                        except Exception as e:
                            self.mark_module_status('gcp_storage_enumeration', 'failed', str(e))
                            self.print_error(f"gcp_storage_enumeration failed: {e}")
                    else:
                        self.mark_module_status('gcp_storage_enumeration', 'skipped')

    def _consolidate_results(self):
                """Merge per-domain result slices into a single flat view for downstream tooling"""
                def deep_merge(dst, src):
                    for k, v in src.items():
                        if k in dst:
                            if isinstance(dst[k], list) and isinstance(v, list):
                                for item in v:
                                    if item not in dst[k]:
                                        dst[k].append(item)
                            elif isinstance(dst[k], dict) and isinstance(v, dict):
                                deep_merge(dst[k], v)
                            else:
                                if not dst[k]:
                                    dst[k] = v
                        else:
                            dst[k] = v
                    return dst

                merged = {
                    'timestamp': datetime.now().isoformat(),
                    'client': self.client_name,
                    'domains': list(self.domains),
                    'ip_ranges': self.ip_ranges
                }
                for d in self.domains:
                    slice_copy = {k: v for k, v in self.all_results[d].items()
                                  if k not in ('timestamp', 'domain', 'client')}
                    deep_merge(merged, slice_copy)
                merged['network_scan'] = self.client_results.get('network_scan', {})
                self.consolidated = merged

    def run_all(self):
                """Run all reconnaissance modules across domains with state tracking"""
                self.print_banner()

                if not self.state['session'].get('api_keys_prompted'):
                    self.prompt_for_api_keys()
                    self.state['session']['api_keys_prompted'] = True
                    self.save_state()

                try:
                    # Per-domain passes
                    for domain in self.domains:
                        self.current_domain = domain
                        self.domain = domain
                        self.results = self.all_results[domain]
                        self.print_section(f"DOMAIN: {domain.upper()}")
                        self._run_domain_modules()

                    # Client-level network enumeration (run once over in-scope ranges)
                    self.current_domain = None
                    self.results = self.client_results
                    if self.should_run_module('network_enumeration'):
                        if self.ip_ranges and not self.args.skip_scan:
                            self.mark_module_status('network_enumeration', 'in_progress')
                            try:
                                self.network_enumeration()
                                self.mark_module_status('network_enumeration', 'complete')
                            except Exception as e:
                                self.mark_module_status('network_enumeration', 'failed', str(e))
                                self.print_error(f"network_enumeration failed: {e}")
                        else:
                            self.mark_module_status('network_enumeration', 'skipped')

                    # Consolidate per-domain slices, then report
                    self._consolidate_results()
                    self.generate_report()

                    self.state['session']['completed'] = True
                    self.state['session']['completed_at'] = datetime.now().isoformat()
                    self.save_state()

                    self.print_section("RECONNAISSANCE COMPLETE")
                    self.print_success(f"All results saved to: {self.output_dir}")
                    self._print_final_summary()

                except KeyboardInterrupt:
                    pass
                except Exception as e:
                    self.print_error(f"Error during reconnaissance: {e}")
                    import traceback
                    traceback.print_exc()
                    self.save_state()

    def _print_final_summary(self):
                """Print summary of all module statuses across domains and client"""
                print(f"\n{Colors.HEADER}Module Summary:{Colors.ENDC}")

                def render(label, module_name, module_state):
                    status = module_state['status']
                    display_name = module_name.replace('_', ' ').title()
                    if status == 'complete':
                        duration = ""
                        if module_state.get('started_at') and module_state.get('completed_at'):
                            try:
                                start = datetime.fromisoformat(module_state['started_at'])
                                end = datetime.fromisoformat(module_state['completed_at'])
                                secs = (end - start).total_seconds()
                                duration = f" ({secs/60:.1f}m)" if secs >= 60 else f" ({secs:.0f}s)"
                            except:
                                pass
                        print(f"  {Colors.OKGREEN}✓{Colors.ENDC} [{label}] {display_name}{duration}")
                    elif status == 'skipped':
                        print(f"  {Colors.OKCYAN}○{Colors.ENDC} [{label}] {display_name} (skipped)")
                    elif status == 'failed':
                        error = module_state.get('error', 'Unknown error')
                        print(f"  {Colors.FAIL}✗{Colors.ENDC} [{label}] {display_name} - {error[:50]}")
                    elif status == 'in_progress':
                        print(f"  {Colors.WARNING}⋯{Colors.ENDC} [{label}] {display_name} (incomplete)")
                    else:
                        print(f"  {Colors.OKCYAN}○{Colors.ENDC} [{label}] {display_name} (not run)")

                for d in self.domains:
                    for module_name, module_state in self.state['domains'][d]['modules'].items():
                        render(d, module_name, module_state)
                for module_name, module_state in self.state['client']['modules'].items():
                    render('client', module_name, module_state)

    # =========================================================================
    # STATE MANAGEMENT METHODS
    # =========================================================================

    def init_state(self):
                """Initialize state tracking structure (multi-domain, client-level)"""
                per_domain_modules = [
                    'scope_validation', 'm365_tenant', 'adfs', 'email_security',
                    'dns_enumeration', 'post_dns_whois', 'technology_stack',
                    'email_harvesting', 'linkedin_enumeration', 'breach_database_check',
                    'github_secret_scanning', 'asn_enumeration',
                    'subdomain_takeover_detection', 's3_bucket_enumeration',
                    'azure_storage_enumeration', 'gcp_storage_enumeration'
                ]
                self.state = {
                    'version': '2.0',
                    'target': {
                        'domains': self.domains,
                        'client': self.client_name,
                        'ip_ranges': self.ip_ranges,
                        'config_hash': self._generate_config_hash()
                    },
                    'session': {
                        'started_at': datetime.now().isoformat(),
                        'last_updated': datetime.now().isoformat(),
                        'interrupted': False,
                        'completed': False
                    },
                    'domains': {
                        d: {'modules': {m: {'status': 'pending', 'progress': {}} for m in per_domain_modules}}
                        for d in self.domains
                    },
                    'client': {
                        'modules': {
                            'network_enumeration': {'status': 'pending', 'progress': {}}
                        }
                    },
                    'results': {}
                }
                self.state_file = self.output_dir / 'recon_state.json'
                self._shutdown_in_progress = False

    def _generate_config_hash(self) -> str:
                """Generate hash of target configuration for change detection"""
                config_str = f"{','.join(sorted(self.domains))}|{self.client_name}|{','.join(sorted(self.ip_ranges))}"
                return hashlib.sha256(config_str.encode()).hexdigest()[:16]

    def _module_bucket(self) -> Dict[str, Any]:
                """Return the module-state bucket for the active context"""
                if self.current_domain is None:
                    return self.state['client']['modules']
                return self.state['domains'][self.current_domain]['modules']

    def setup_signal_handlers(self):
        """Register signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        atexit.register(self._atexit_handler)

    def _signal_handler(self, signum, frame):
                """Handle SIGINT/SIGTERM for graceful shutdown"""
                if self._shutdown_in_progress:
                    self.print_error("\nForced exit - state may be incomplete")
                    sys.exit(1)

                self._shutdown_in_progress = True
                self.print_warning("\n\nInterrupt received - saving state before exit...")

                self.state['session']['interrupted'] = True
                self.state['session']['last_updated'] = datetime.now().isoformat()

                for d in self.domains:
                    for module_name, module_state in self.state['domains'][d]['modules'].items():
                        if module_state['status'] == 'in_progress':
                            self.print_info(f"Module '{module_name}' ({d}) was in progress - state preserved")
                for module_name, module_state in self.state['client']['modules'].items():
                    if module_state['status'] == 'in_progress':
                        self.print_info(f"Module '{module_name}' (client) was in progress - state preserved")

                self.save_state()
                self.print_success(f"State saved to: {self.state_file}")
                self.print_info("Run the same command with --resume to continue")
                sys.exit(0)

    def _atexit_handler(self):
                """Handle normal exit - save state if not already saved"""
                if not self._shutdown_in_progress and hasattr(self, 'state'):
                    self.state['session']['last_updated'] = datetime.now().isoformat()
                    self.save_state()

    def load_state(self) -> bool:
                """Load existing state file. Returns True if valid state was loaded."""
                if not self.state_file.exists():
                    return False
                try:
                    with open(self.state_file, 'r') as f:
                        loaded_state = json.load(f)

                    if loaded_state.get('version') != '2.0':
                        self.print_warning("State file version mismatch (expected 2.0)")
                        return False

                    loaded_target = loaded_state.get('target', {})
                    if (sorted(loaded_target.get('domains', [])) != sorted(self.domains) or
                        loaded_target.get('client') != self.client_name):
                        self.print_warning("State file is for a different target")
                        return False

                    self.state = loaded_state

                    res = loaded_state.get('results', {})
                    restored_domains = res.get('domains', {})
                    for d in self.domains:
                        if d in restored_domains:
                            self.all_results[d] = restored_domains[d]
                    self.client_results = res.get('client', self.client_results)

                    self.current_domain = self.domains[0]
                    self.domain = self.domains[0]
                    self.results = self.all_results[self.domain]

                    return True
                except json.JSONDecodeError as e:
                    self.print_error(f"State file is corrupted: {e}")
                    return False
                except Exception as e:
                    self.print_error(f"Error loading state file: {e}")
                    return False

    def save_state(self):
                """Atomically save current state to file"""
                try:
                    self.state['session']['last_updated'] = datetime.now().isoformat()
                    self.state['results'] = {
                        'domains': self.all_results,
                        'client': self.client_results
                    }
                    temp_file = self.state_file.with_suffix('.json.tmp')
                    with open(temp_file, 'w') as f:
                        json.dump(self.state, f, indent=2, default=str)
                    temp_file.replace(self.state_file)
                except Exception as e:
                    self.print_error(f"Failed to save state: {e}")

    def checkpoint(self, module: str, subtask: str = None, progress_data: Dict = None):
                """Save checkpoint during long-running operations"""
                bucket = self._module_bucket()
                if module not in bucket:
                    return
                if subtask and progress_data is not None:
                    if 'progress' not in bucket[module]:
                        bucket[module]['progress'] = {}
                    bucket[module]['progress'][subtask] = progress_data
                self.save_state()

    def get_module_status(self, module: str) -> str:
                """Get status of a module in the active context"""
                bucket = self._module_bucket()
                if module not in bucket:
                    return 'pending'
                return bucket[module].get('status', 'pending')

    def get_module_progress(self, module: str, subtask: str = None) -> Optional[Dict]:
                """Get progress data for a module/subtask in the active context"""
                bucket = self._module_bucket()
                if module not in bucket:
                    return None
                progress = bucket[module].get('progress', {})
                if subtask:
                    return progress.get(subtask)
                return progress

    def mark_module_status(self, module: str, status: str, error_msg: str = None):
                """Update module status in the active context"""
                bucket = self._module_bucket()
                if module not in bucket:
                    bucket[module] = {'status': status, 'progress': {}}
                else:
                    bucket[module]['status'] = status
                if status == 'in_progress':
                    bucket[module]['started_at'] = datetime.now().isoformat()
                elif status == 'complete':
                    bucket[module]['completed_at'] = datetime.now().isoformat()
                elif status == 'failed' and error_msg:
                    bucket[module]['error'] = error_msg
                self.save_state()

    def prompt_resume(self) -> bool:
                """Interactive prompt when existing state is detected. Returns True to resume."""
                if self.auto_resume:
                    self.print_info("Auto-resume enabled - continuing from last checkpoint")
                    return True

                all_modules = []
                for d in self.domains:
                    for name, st in self.state['domains'][d]['modules'].items():
                        all_modules.append((f"{d}/{name}", st))
                for name, st in self.state['client']['modules'].items():
                    all_modules.append((f"client/{name}", st))

                complete_count = sum(1 for _, m in all_modules if m['status'] == 'complete')
                total_count = len(all_modules)
                in_progress = [n for n, m in all_modules if m['status'] == 'in_progress']

                print(f"\n{'='*80}")
                print(f"{Colors.HEADER}    PREVIOUS SCAN DETECTED{Colors.ENDC}")
                print(f"{'='*80}")
                print(f"    Target: {', '.join(self.state['target']['domains'])} ({self.state['target']['client']})")
                print(f"    Started: {self.state['session']['started_at']}")
                print(f"    Last activity: {self.state['session']['last_updated']}")
                if self.state['session'].get('interrupted'):
                    print(f"    {Colors.WARNING}Status: Interrupted{Colors.ENDC}")

                print(f"\n    Progress ({complete_count}/{total_count} modules complete):")
                for d in self.domains:
                    dom_mods = self.state['domains'][d]['modules']
                    dc = sum(1 for m in dom_mods.values() if m['status'] == 'complete')
                    print(f"      {Colors.OKCYAN}{d}{Colors.ENDC}: {dc}/{len(dom_mods)} complete")
                cm = self.state['client']['modules']
                cc = sum(1 for m in cm.values() if m['status'] == 'complete')
                print(f"      {Colors.OKCYAN}client{Colors.ENDC}: {cc}/{len(cm)} complete")

                print(f"\n    Options:")
                if in_progress:
                    print(f"      [R] Resume (in progress: {', '.join(in_progress)})")
                else:
                    print(f"      [R] Resume from next pending module")
                print(f"      [S] Start fresh (backup existing results)")
                print(f"      [Q] Quit")

                print()
                choice = input(f"    Choice [R]: ").strip().upper()
                if choice == 'Q':
                    self.print_info("Exiting without changes")
                    sys.exit(0)
                elif choice == 'S':
                    self._backup_and_reset_state()
                    return False
                else:
                    return True

    def _backup_and_reset_state(self):
        """Backup existing state and results, then reset for fresh start"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Backup state file
        if self.state_file.exists():
            backup_state = self.state_file.with_name(f'recon_state_backup_{timestamp}.json')
            shutil.copy(self.state_file, backup_state)
            self.print_success(f"State backed up to: {backup_state}")

        # Backup any existing results files
        for result_file in self.output_dir.glob('recon_results_*.json'):
            backup_name = result_file.with_name(f'backup_{timestamp}_{result_file.name}')
            shutil.move(result_file, backup_name)
            self.print_info(f"Results backed up: {backup_name}")

        # Reset state
        self.init_state()
        self.print_info("Starting fresh scan")

    def should_run_module(self, module: str) -> bool:
                """Determine if a module should run based on state"""
                status = self.get_module_status(module)
                label = self.current_domain or 'client'
                if status == 'complete':
                    self.print_info(f"Skipping {module} for {label} (already complete)")
                    return False
                if status == 'skipped':
                    return False
                return True

    def get_resume_data(self, module: str) -> Dict:
                """Get data needed to resume a module from checkpoint"""
                bucket = self._module_bucket()
                module_state = bucket.get(module, {})
                return {
                    'status': module_state.get('status', 'pending'),
                    'progress': module_state.get('progress', {}),
                    'results': self.results
                }

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

  Resume interrupted scan:
    python3 quick_recon.py -d example.com -c "Acme Corp" -o ./existing_output --resume

  Skip specific modules:
    python3 quick_recon.py -d example.com -i 192.168.1.0/24 -c "Acme Corp" --skip-s3 --skip-scan

  Run single module only:
    python3 quick_recon.py -d example.com -c "Acme Corp" --linkedin-only
    python3 quick_recon.py -d example.com -c "Acme Corp" --github-only
    python3 quick_recon.py -d example.com -c "Acme Corp" --s3-only
    python3 quick_recon.py -d example.com -c "Acme Corp" --dns-only
    python3 quick_recon.py -d example.com -c "Acme Corp" --email-only
    python3 quick_recon.py -d example.com -c "Acme Corp" --m365-only
    python3 quick_recon.py -d example.com -c "Acme Corp" --adfs-only
    python3 quick_recon.py -d example.com -c "Acme Corp" --email-security-only

  LinkedIn delay modes (avoid rate limits):
    python3 quick_recon.py -d example.com -c "Acme Corp" --linkedin-only --linkedin-mode paranoid
    python3 quick_recon.py -d example.com -c "Acme Corp" --linkedin-only --linkedin-mode fast

  Deep email crawl (more thorough but slower):
    python3 quick_recon.py -d example.com -c "Acme Corp" --email-only --deep-crawl

  Skip all OSINT modules:
    python3 quick_recon.py -d example.com -i 192.168.1.0/24 -c "Acme Corp" --skip-osint
        '''
    )

    parser.add_argument('-d', '--domain', required=True, help='Target domain(s), comma-separated (e.g., a.com,b.com,c.com)')
    parser.add_argument('-i', '--ip-ranges', nargs='+', help='In-scope IP ranges (e.g., 192.168.1.0/24)')
    parser.add_argument('-f', '--file', help='File containing IP ranges (one CIDR per line)')
    parser.add_argument('-c', '--client', required=True, help='Client name for reporting')
    parser.add_argument('-o', '--output', help='Output directory (default: ./<client_name>_recon)')

    # Resume flag
    parser.add_argument('--resume', action='store_true', help='Automatically resume from last checkpoint without prompting')

    # Module control flags
    parser.add_argument('--skip-breach-check', action='store_true', help='Skip breach database checking')
    parser.add_argument('--skip-scan', action='store_true', help='Skip network scanning')
    parser.add_argument('--skip-s3', action='store_true', help='Skip S3 bucket enumeration')
    parser.add_argument('--skip-azure', action='store_true', help='Skip Azure storage enumeration')
    parser.add_argument('--skip-gcp', action='store_true', help='Skip GCP storage enumeration')
    parser.add_argument('--skip-github', action='store_true', help='Skip GitHub secret scanning')
    parser.add_argument('--skip-asn', action='store_true', help='Skip ASN enumeration')
    parser.add_argument('--skip-subdomain-takeover', action='store_true', help='Skip subdomain takeover detection')
    parser.add_argument('--skip-m365', action='store_true', help='Skip M365/Azure AD tenant attribution')
    parser.add_argument('--skip-adfs', action='store_true', help='Skip ADFS endpoint discovery')
    parser.add_argument('--skip-email-security', action='store_true', help='Skip email security posture check (SPF/DKIM/DMARC)')
    parser.add_argument('--skip-osint', action='store_true', help='Skip all OSINT modules (GitHub, LinkedIn)')
    parser.add_argument('--linkedin-max-results', type=int, default=100, help='Maximum LinkedIn employee results to fetch (default: 100)')
    parser.add_argument('--linkedin-mode', choices=['fast', 'normal', 'paranoid'], default='normal', help='LinkedIn delay mode: fast (testing only, high lockout risk), normal (default, human-like delays), paranoid (slower, for sensitive engagements)')
    parser.add_argument('--deep-crawl', action='store_true', help='Enable deep email crawl mode (100 pages, depth 3) - slower but more thorough')

    # Single module execution flags
    parser.add_argument('--linkedin-only', action='store_true', help='Run only LinkedIn enumeration')
    parser.add_argument('--github-only', action='store_true', help='Run only GitHub secret scanning')
    parser.add_argument('--s3-only', action='store_true', help='Run only S3 bucket enumeration')
    parser.add_argument('--azure-only', action='store_true', help='Run only Azure storage enumeration')
    parser.add_argument('--gcp-only', action='store_true', help='Run only GCP storage enumeration')
    parser.add_argument('--asn-only', action='store_true', help='Run only ASN enumeration')
    parser.add_argument('--subdomain-takeover-only', action='store_true', help='Run only subdomain takeover detection')
    parser.add_argument('--email-only', action='store_true', help='Run only email harvesting')
    parser.add_argument('--dns-only', action='store_true', help='Run only DNS enumeration')
    parser.add_argument('--breach-only', action='store_true', help='Run only breach database check')
    parser.add_argument('--techstack-only', action='store_true', help='Run only technology stack identification')
    parser.add_argument('--m365-only', action='store_true', help='Run only M365 tenant attribution')
    parser.add_argument('--adfs-only', action='store_true', help='Run only ADFS endpoint discovery (runs M365 first)')
    parser.add_argument('--email-security-only', action='store_true', help='Run only email security posture check')

    args = parser.parse_args()

    # Apply skip-osint flag
    if args.skip_osint:
        args.skip_github = True

    # Parse and validate domain list (comma-separated)
    raw_domains = [d.strip().lower() for d in args.domain.split(',') if d.strip()]
    seen_d = set()
    domains = []
    for d in raw_domains:
        if d in seen_d:
            continue
        if not re.match(r'^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$', d):
            print(f"{Colors.WARNING}[!] Skipping invalid domain: {d}{Colors.ENDC}")
            continue
        seen_d.add(d)
        domains.append(d)
    if not domains:
        print(f"{Colors.FAIL}[-] No valid domains supplied to -d{Colors.ENDC}")
        sys.exit(1)
    if len(domains) > 1:
        print(f"{Colors.OKCYAN}[i] Multi-domain run: {', '.join(domains)}{Colors.ENDC}")
    args.domains = domains

    # Set output directory based on client name if not specified
    if not args.output:
        safe_client_name = re.sub(r'[^\w\s-]', '', args.client).strip().replace(' ', '_')
        args.output = f"./{safe_client_name}_recon"

    # Check for any --X-only mode BEFORE processing IP ranges
    only_modes = {
        'linkedin_only': ('LinkedIn enumeration', 'linkedin_enumeration', 'linkedin_intel'),
        'github_only': ('GitHub secret scanning', 'github_secret_scanning', 'github_secrets'),
        's3_only': ('S3 bucket enumeration', 's3_bucket_enumeration', 's3_buckets'),
        'azure_only': ('Azure storage enumeration', 'azure_storage_enumeration', 'azure_storage'),
        'gcp_only': ('GCP storage enumeration', 'gcp_storage_enumeration', 'gcp_storage'),
        'asn_only': ('ASN enumeration', 'asn_enumeration', 'asn_data'),
        'subdomain_takeover_only': ('Subdomain takeover detection', 'subdomain_takeover_detection', 'subdomain_takeovers'),
        'email_only': ('Email harvesting', 'email_harvesting', 'email_addresses'),
        'dns_only': ('DNS enumeration', 'dns_enumeration', 'dns_enumeration'),
        'breach_only': ('Breach database check', 'breach_database_check', 'breach_data'),
        'techstack_only': ('Technology stack identification', 'technology_stack_identification', 'technology_stack'),
        'm365_only': ('M365 tenant attribution', 'm365_tenant_attribution', 'm365_tenant'),
        'adfs_only': ('ADFS endpoint discovery', 'adfs_endpoint_discovery', 'adfs'),
        'email_security_only': ('Email security posture check', 'email_security_posture', 'email_security'),
    }

    active_only_mode = None
    for mode_name, mode_info in only_modes.items():
        if getattr(args, mode_name, False):
            active_only_mode = (mode_name, *mode_info)
            break

    if active_only_mode:
        mode_name, display_name, method_name, result_key = active_only_mode
        print(f"{Colors.OKCYAN}[i] Running in {display_name} only mode{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[i] Output directory: {args.output}{Colors.ENDC}")

        recon = ReconAutomation(
            domain=[domains[0]],
            ip_ranges=[],
            output_dir=args.output,
            client_name=args.client,
            auto_resume=args.resume
        )

        # Store args reference so modules can access flags
        recon.args = args

        # LinkedIn has its own run method with cookie prompting
        if mode_name == 'linkedin_only':
            recon.run_linkedin_only()
            sys.exit(0)

        recon.print_banner()

        # Prompt for module-specific API key only
        if mode_name == 'github_only':
            if not recon.config.get('github_token'):
                print("\n" + "="*80)
                print("GITHUB TOKEN CONFIGURATION")
                print("="*80)
                token = input("    Enter GitHub personal access token (or press Enter to skip): ").strip()
                if token:
                    recon.config['github_token'] = token
                    recon.print_success("GitHub token configured")
                print("="*80 + "\n")

        # Subdomain takeover needs DNS enumeration first
        if mode_name == 'subdomain_takeover_only':
            print(f"{Colors.OKCYAN}[i] Running DNS enumeration first (required for subdomain takeover){Colors.ENDC}")
            recon.dns_enumeration()

        # Breach check needs emails - run email harvesting first
        if mode_name == 'breach_only':
            print(f"{Colors.OKCYAN}[i] Running email harvesting first (required for breach check){Colors.ENDC}")
            recon.email_harvesting()

        # ADFS discovery needs M365 attribution first
        if mode_name == 'adfs_only':
            print(f"{Colors.OKCYAN}[i] Running M365 tenant attribution first (required for ADFS discovery){Colors.ENDC}")
            recon.m365_tenant_attribution()

        try:
            method = getattr(recon, method_name)
            method()

            recon.print_section(f"{display_name.upper()} COMPLETE")

            result_data = recon.results.get(result_key, {})
            if result_data:
                recon.print_success(f"{display_name} completed!")
                json_file = recon.output_dir / f"{mode_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(json_file, 'w') as f:
                    json.dump(result_data, f, indent=2)
                recon.print_success(f"Results saved to: {json_file}")
            else:
                recon.print_warning(f"No data collected from {display_name}")

        except KeyboardInterrupt:
            recon.print_warning(f"\n{display_name} interrupted by user")
        except Exception as e:
            recon.print_error(f"Error during {display_name}: {e}")
            import traceback
            traceback.print_exc()

        sys.exit(0)

    # Parse IP ranges from command line and/or file (only for full recon mode)
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

    # Show resume status
    if args.resume:
        print(f"{Colors.OKCYAN}[i] Auto-resume enabled - will continue from last checkpoint if available{Colors.ENDC}")

    # Create recon automation instance
    recon = ReconAutomation(
        domain=domains,
        ip_ranges=unique_ranges,
        output_dir=args.output,
        client_name=args.client,
        auto_resume=args.resume
    )

    # Store args reference for run_all method
    recon.args = args

    # Run all reconnaissance
    recon.run_all()

if __name__ == '__main__':
    main()
