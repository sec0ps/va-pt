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
import socket
import requests
import urllib3
from urllib.parse import urlparse
import sys
import time

# Suppress SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ProxyTester:
    def __init__(self, target_ip, target_port, timeout=10, verbose=False):
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.verbose = verbose
        self.test_urls = [
            "http://example.com",
            "https://example.com",
            "http://httpbin.org/ip",
            "https://www.google.com"
        ]

    def log(self, message, level="INFO"):
        """Print verbose logging"""
        if self.verbose or level == "RESULT":
            prefix = f"[{level}]" if level != "RESULT" else "[✓]"
            print(f"{prefix} {message}")

    def test_http_proxy(self):
        """Test HTTP/HTTPS proxy functionality"""
        self.log("Testing HTTP/HTTPS Proxy...")

        proxies = {
            'http': f'http://{self.target_ip}:{self.target_port}',
            'https': f'http://{self.target_ip}:{self.target_port}'
        }

        results = []
        for url in self.test_urls:
            try:
                self.log(f"  Attempting connection to {url} via proxy", "DEBUG")
                response = requests.get(
                    url,
                    proxies=proxies,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )

                if response.status_code in [200, 301, 302]:
                    self.log(f"  SUCCESS: {url} - Status {response.status_code}", "DEBUG")
                    results.append({
                        'url': url,
                        'status': response.status_code,
                        'success': True
                    })
                else:
                    self.log(f"  FAILED: {url} - Status {response.status_code}", "DEBUG")

            except requests.exceptions.ProxyError as e:
                self.log(f"  Proxy Error: {url} - {str(e)}", "DEBUG")
            except requests.exceptions.ConnectTimeout:
                self.log(f"  Timeout: {url}", "DEBUG")
            except requests.exceptions.ConnectionError as e:
                self.log(f"  Connection Error: {url} - {str(e)}", "DEBUG")
            except Exception as e:
                self.log(f"  Error: {url} - {str(e)}", "DEBUG")

        return results

    def test_socks_proxy(self, socks_version):
        """Test SOCKS4/SOCKS5 proxy functionality"""
        try:
            import socks
            from sockshandler import SocksiPyHandler
        except ImportError:
            self.log("PySocks not installed. Skipping SOCKS tests.", "WARN")
            self.log("Install with: pip install pysocks requests[socks]", "WARN")
            return []

        socks_type = socks.SOCKS5 if socks_version == 5 else socks.SOCKS4
        self.log(f"Testing SOCKS{socks_version} Proxy...")

        results = []
        for url in self.test_urls[:2]:  # Test fewer URLs for SOCKS
            try:
                proxies = {
                    'http': f'socks{socks_version}://{self.target_ip}:{self.target_port}',
                    'https': f'socks{socks_version}://{self.target_ip}:{self.target_port}'
                }

                self.log(f"  Attempting connection to {url} via SOCKS{socks_version}", "DEBUG")
                response = requests.get(
                    url,
                    proxies=proxies,
                    timeout=self.timeout,
                    verify=False
                )

                if response.status_code == 200:
                    self.log(f"  SUCCESS: {url} - Status {response.status_code}", "DEBUG")
                    results.append({
                        'url': url,
                        'status': response.status_code,
                        'success': True
                    })

            except Exception as e:
                self.log(f"  Error: {url} - {str(e)}", "DEBUG")

        return results

    def test_connect_method(self):
        """Test CONNECT method for HTTPS tunneling"""
        self.log("Testing CONNECT method (HTTPS tunneling)...")

        try:
            # Test CONNECT method to example.com:443
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, self.target_port))

            connect_request = f"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
            sock.send(connect_request.encode())

            response = sock.recv(4096).decode()
            sock.close()

            if "200 Connection established" in response or "200 OK" in response:
                self.log("  SUCCESS: CONNECT method accepted", "DEBUG")
                return [{'method': 'CONNECT', 'success': True}]
            else:
                self.log(f"  Response: {response[:100]}", "DEBUG")

        except socket.timeout:
            self.log("  Timeout on CONNECT test", "DEBUG")
        except Exception as e:
            self.log(f"  Error: {str(e)}", "DEBUG")

        return []

    def check_port_open(self):
        """Check if target port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target_ip, self.target_port))
            sock.close()
            return result == 0
        except:
            return False

    def run_tests(self):
        """Run all proxy detection tests"""
        print(f"\n{'='*60}")
        print(f"Proxy Detection Test: {self.target_ip}:{self.target_port}")
        print(f"{'='*60}\n")

        # Check if port is open
        if not self.check_port_open():
            print(f"[✗] Port {self.target_port} appears CLOSED or FILTERED")
            print(f"    Cannot reach {self.target_ip}:{self.target_port}")
            return False

        self.log(f"Port {self.target_port} is OPEN", "RESULT")

        # Test HTTP/HTTPS proxy
        http_results = self.test_http_proxy()

        # Test SOCKS proxies
        socks4_results = self.test_socks_proxy(4)
        socks5_results = self.test_socks_proxy(5)

        # Test CONNECT method
        connect_results = self.test_connect_method()

        # Analyze results
        print(f"\n{'='*60}")
        print("RESULTS:")
        print(f"{'='*60}\n")

        is_proxy = False

        if http_results:
            print(f"[✓] HTTP/HTTPS Proxy: DETECTED")
            print(f"    Successfully proxied {len(http_results)} requests")
            for result in http_results[:3]:
                print(f"    - {result['url']} (Status: {result['status']})")
            is_proxy = True
        else:
            print(f"[✗] HTTP/HTTPS Proxy: NOT DETECTED")

        if socks4_results:
            print(f"\n[✓] SOCKS4 Proxy: DETECTED")
            print(f"    Successfully proxied {len(socks4_results)} requests")
            is_proxy = True
        else:
            print(f"\n[✗] SOCKS4 Proxy: NOT DETECTED")

        if socks5_results:
            print(f"\n[✓] SOCKS5 Proxy: DETECTED")
            print(f"    Successfully proxied {len(socks5_results)} requests")
            is_proxy = True
        else:
            print(f"\n[✗] SOCKS5 Proxy: NOT DETECTED")

        if connect_results:
            print(f"\n[✓] CONNECT Method: SUPPORTED")
            print(f"    HTTPS tunneling capability detected")
            is_proxy = True
        else:
            print(f"\n[✗] CONNECT Method: NOT SUPPORTED")

        print(f"\n{'='*60}")
        if is_proxy:
            print("[✓] CONCLUSION: Service IS functioning as a proxy server")
        else:
            print("[✗] CONCLUSION: Service is NOT functioning as a proxy server")
            print("    (Port is open but doesn't respond to proxy requests)")
        print(f"{'='*60}\n")

        return is_proxy


def main():
    parser = argparse.ArgumentParser(
        description='Test if a service is functioning as a proxy server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.100 -p 8080
  %(prog)s -t 10.10.10.50 -p 3128 -v
  %(prog)s -t proxy.example.com -p 1080 --timeout 15
        """
    )

    parser.add_argument('-t', '--target', required=True,
                        help='Target IP address or hostname')
    parser.add_argument('-p', '--port', required=True, type=int,
                        help='Target port number')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')

    args = parser.parse_args()

    # Validate port
    if not 1 <= args.port <= 65535:
        print("[ERROR] Port must be between 1 and 65535")
        sys.exit(1)

    # Run tests
    tester = ProxyTester(
        target_ip=args.target,
        target_port=args.port,
        timeout=args.timeout,
        verbose=args.verbose
    )

    try:
        result = tester.run_tests()
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n[!] Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
