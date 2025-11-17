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
            's3_buckets': {}
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

    def scope_validation(self):
        """Perform scope validation including WHOIS and DNS verification"""
        self.print_section("SCOPE VALIDATION")

        # WHOIS lookup for IP ranges
        self.print_info("Performing WHOIS lookups for IP ranges...")
        whois_results = {}

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

        self.results['scope_validation']['whois'] = whois_results

        # DNS verification for domain
        self.print_info(f"Verifying DNS records for {self.domain}...")
        dns_records = self._get_dns_records(self.domain)
        self.results['scope_validation']['dns_verification'] = dns_records

        if dns_records.get('A'):
            self.print_success(f"Domain resolves to: {', '.join(dns_records['A'])}")

            # Check if resolved IPs are in scope
            for ip in dns_records['A']:
                in_scope = self._is_ip_in_scope(ip)
                if in_scope:
                    self.print_success(f"✓ {ip} is within authorized scope")
                else:
                    self.print_warning(f"✗ {ip} is NOT in provided scope ranges")

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
            # Build command based on whether it's a Python script or executable
            if self.theharvester_path.endswith('.py'):
                command = ['python3', self.theharvester_path, '-d', self.domain, '-b', 'all', '-l', '500']
            else:
                command = [self.theharvester_path, '-d', self.domain, '-b', 'all', '-l', '500']

            output = self.run_command(command, timeout=120)

            if output:
                # Extract emails from output
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                emails = re.findall(email_pattern, output)
                self.print_success(f"theHarvester found {len(set(emails))} email(s)")
        except Exception as e:
            self.print_warning(f"theHarvester execution failed: {e}")

        return emails

    def _locate_theharvester(self) -> Optional[str]:
        """Locate theHarvester installation using system tools"""
        # Try standard PATH lookup first
        for cmd in ['theHarvester.py', 'theHarvester', 'theharvester']:
            path = shutil.which(cmd)
            if path:
                return path

        # Try locate command
        try:
            output = self.run_command(['locate', 'theHarvester.py'], timeout=10)
            if output:
                # Get first result that's executable or readable
                for line in output.strip().split('\n'):
                    if line and Path(line).exists():
                        return line
        except:
            pass

        # Try find command in common base directories
        try:
            for base_dir in ['/usr', '/opt', str(Path.home())]:
                output = self.run_command([
                    'find', base_dir,
                    '-name', 'theHarvester.py',
                    '-type', 'f',
                    '-readable',
                    '2>/dev/null'
                ], timeout=30)
                if output:
                    # Return first valid result
                    for line in output.strip().split('\n'):
                        if line and Path(line).exists():
                            return line
        except:
            pass

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

        # Analyze accessible buckets
        for bucket in found_buckets:
            if bucket['status'] in ['Public Read', 'Redirect']:
                self.print_info(f"Analyzing contents of {bucket['bucket']}...")
                self._analyze_s3_bucket_contents(bucket)

        self.results['s3_buckets'] = {
            'tested': len(bucket_candidates),
            'found': found_buckets,
            'public_count': len([b for b in found_buckets if b['status'] == 'Public Read']),
            'private_count': len([b for b in found_buckets if b['status'] == 'Private (Exists)'])
        }

        if found_buckets:
            self.print_warning(f"Found {len(found_buckets)} S3 buckets:")
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
        """Analyze S3 bucket contents"""
        try:
            response = self.session.get(bucket_info['url'], timeout=10)
            if response.status_code != 200:
                return

            content = response.text
            files = []

            # Parse XML listing
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(content)
                for contents in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
                    key = contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key')
                    size = contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size')
                    modified = contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}LastModified')

                    if key is not None:
                        files.append({
                            'key': key.text,
                            'size': int(size.text) if size is not None else 0,
                            'last_modified': modified.text if modified is not None else 'Unknown'
                        })
            except ET.ParseError:
                # Fallback regex
                keys = re.findall(r'<Key>([^<]+)</Key>', content)
                files = [{'key': k, 'size': 0, 'last_modified': 'Unknown'} for k in keys]

            bucket_info['files'] = files
            bucket_info['file_count'] = len(files)

            if files:
                total_size = sum(f['size'] for f in files) / 1024  # KB
                self.print_warning(f"  Found {len(files)} files ({total_size:.1f}KB total)")

                # Show first 10 files
                for i, f in enumerate(files[:10]):
                    self.print_info(f"    {f['key']} ({f['size']/1024:.1f}KB)")
                if len(files) > 10:
                    self.print_info(f"    ... and {len(files)-10} more files")
        except Exception as e:
            self.print_error(f"Error analyzing bucket: {e}")

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
                f.write("These credentials became immediate testing priorities.\n\n")
            else:
                f.write("No exposed credentials were found in available breach databases.\n\n")
            
            # S3 Bucket Enumeration Section
            f.write("### Cloud Storage Enumeration (S3 Buckets)\n\n")
            s3_results = self.results.get('s3_buckets', {})
            
            if s3_results.get('found'):
                buckets = s3_results['found']
                public_buckets = [b for b in buckets if b['status'] == 'Public Read']
                private_buckets = [b for b in buckets if b['status'] == 'Private (Exists)']
                
                if public_buckets:
                    f.write(f"S3 bucket enumeration revealed {len(public_buckets)} publicly accessible bucket(s):\n\n")
                    for bucket in public_buckets:
                        f.write(f"• {bucket['bucket']}\n")
                        f.write(f"  URL: {bucket['url']}\n")
                        if bucket.get('file_count'):
                            total_size = sum(file['size'] for file in bucket.get('files', [])) / 1024  # KB
                            f.write(f"  Contents: {bucket['file_count']} files ({total_size:.1f}KB total)\n")
                            
                            # List some sensitive files if found
                            sensitive_patterns = ['.env', 'config', 'credentials', 'password', 'secret', 'key', 'backup', '.sql', '.zip']
                            sensitive_files = [file['key'] for file in bucket.get('files', []) 
                                            if any(pattern in file['key'].lower() for pattern in sensitive_patterns)]
                            if sensitive_files:
                                f.write(f"  Sensitive files detected: {', '.join(sensitive_files[:5])}\n")
                        f.write("\n")
                    
                    f.write("These buckets allow unauthenticated public access and may contain sensitive data. ")
                    f.write("Public S3 buckets pose a significant data exposure risk as any internet user can access their contents.\n\n")
                
                if private_buckets:
                    f.write(f"Additionally, {len(private_buckets)} private S3 bucket(s) were discovered:\n\n")
                    for bucket in private_buckets:
                        f.write(f"• {bucket['bucket']} (Private)\n")
                    f.write("\n")
                    f.write("While these buckets are not publicly accessible, their existence confirms AWS infrastructure usage.\n\n")
                
                if not public_buckets and private_buckets:
                    f.write(f"S3 bucket enumeration found {len(buckets)} bucket(s), but all were properly configured as private.\n\n")
            else:
                f.write("No S3 buckets were discovered during enumeration. Either no S3 infrastructure is in use, ")
                f.write("or bucket names do not follow predictable naming patterns.\n\n")
            
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
        
        try:
            self.scope_validation()
            self.dns_enumeration()
            self.technology_stack_identification()
            self.email_harvesting()
            
            if not args.skip_breach_check:  # Assumes args is accessible
                self.breach_database_check()
            
            # Add S3 enumeration here
            if not args.skip_s3:  # You'll need to add this arg
                self.s3_bucket_enumeration()
            
            if not args.skip_scan:
                self.network_enumeration()
            
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
  
  Skip modules:
    python3 pentest_recon.py -d example.com -i 192.168.1.0/24 -c "Acme Corp" --skip-s3 --skip-scan
        '''
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-i', '--ip-ranges', nargs='+', help='In-scope IP ranges (e.g., 192.168.1.0/24)')
    parser.add_argument('-f', '--file', help='File containing IP ranges (one CIDR per line)')
    parser.add_argument('-c', '--client', required=True, help='Client name for reporting')
    parser.add_argument('-o', '--output', default='./recon_output', help='Output directory (default: ./recon_output)')
    parser.add_argument('--skip-breach-check', action='store_true', help='Skip breach database checking')
    parser.add_argument('--skip-scan', action='store_true', help='Skip network scanning')
    parser.add_argument('--skip-s3', action='store_true', help='Skip S3 bucket enumeration')
    
    args = parser.parse_args()
    
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
    
    # Validate that we have at least one IP range
    if not ip_ranges:
        print(f"{Colors.FAIL}[-] Error: No IP ranges specified. Use -i or -f to provide targets.{Colors.ENDC}")
        parser.print_help()
        sys.exit(1)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_ranges = []
    for ip_range in ip_ranges:
        if ip_range not in seen:
            seen.add(ip_range)
            unique_ranges.append(ip_range)
    
    if len(ip_ranges) != len(unique_ranges):
        print(f"{Colors.WARNING}[!] Removed {len(ip_ranges) - len(unique_ranges)} duplicate IP range(s){Colors.ENDC}")
    
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
