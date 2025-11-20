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
import struct
import sys
import time
from ipaddress import ip_address
from collections import defaultdict
import select

class mDNSEnumerator:
    def __init__(self, timeout=5, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        self.mdns_port = 5353
        self.mdns_group = '224.0.0.251'

    def log(self, message, level="INFO"):
        """Verbose logging"""
        if self.verbose:
            print(f"[{level}] {message}")

    def create_mdns_query(self, qname, qtype=12):
        """
        Create mDNS query packet
        qtype: 12 = PTR (service enumeration)
               1 = A (hostname)
               33 = SRV (service info)
        """
        transaction_id = b'\x00\x00'  # Transaction ID
        flags = b'\x00\x00'  # Standard query
        questions = b'\x00\x01'  # 1 question
        answer_rrs = b'\x00\x00'
        authority_rrs = b'\x00\x00'
        additional_rrs = b'\x00\x00'

        # Encode domain name
        qname_encoded = b''
        for part in qname.split('.'):
            if part:
                qname_encoded += struct.pack('B', len(part)) + part.encode()
        qname_encoded += b'\x00'  # Null terminator

        qtype_bytes = struct.pack('!H', qtype)
        qclass = b'\x00\x01'  # IN (Internet)

        query = (transaction_id + flags + questions + answer_rrs +
                authority_rrs + additional_rrs + qname_encoded +
                qtype_bytes + qclass)

        return query

    def parse_dns_name(self, data, offset):
        """Parse DNS name with compression support"""
        labels = []
        jumped = False
        jump_offset = 0

        while True:
            if offset >= len(data):
                break

            length = data[offset]

            # Check for compression (pointer)
            if (length & 0xC0) == 0xC0:
                if not jumped:
                    jump_offset = offset + 2
                pointer = struct.unpack('!H', data[offset:offset+2])[0]
                offset = pointer & 0x3FFF
                jumped = True
                continue

            if length == 0:
                offset += 1
                break

            offset += 1
            label = data[offset:offset+length].decode('utf-8', errors='ignore')
            labels.append(label)
            offset += length

        if jumped:
            offset = jump_offset

        return '.'.join(labels), offset

    def parse_mdns_response(self, data):
        """Parse mDNS response packet"""
        if len(data) < 12:
            return None

        # Parse header
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])

        offset = 12
        results = {
            'hostname': None,
            'services': [],
            'addresses': []
        }

        # Skip questions
        for _ in range(qdcount):
            name, offset = self.parse_dns_name(data, offset)
            offset += 4  # Skip qtype and qclass

        # Parse answers
        for _ in range(ancount + nscount + arcount):
            if offset >= len(data):
                break

            try:
                name, offset = self.parse_dns_name(data, offset)

                if offset + 10 > len(data):
                    break

                rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
                offset += 10

                if offset + rdlength > len(data):
                    break

                rdata = data[offset:offset+rdlength]
                offset += rdlength

                # PTR record (service pointer)
                if rtype == 12:
                    service_name, _ = self.parse_dns_name(data, offset - rdlength)
                    if service_name and '_tcp' in service_name or '_udp' in service_name:
                        results['services'].append({
                            'name': service_name,
                            'type': 'PTR'
                        })

                # SRV record (service info)
                elif rtype == 33 and rdlength >= 6:
                    priority, weight, port = struct.unpack('!HHH', rdata[:6])
                    target, _ = self.parse_dns_name(rdata, 6)

                    # Find or update existing service entry
                    found = False
                    for svc in results['services']:
                        if svc.get('name', '').startswith(name.split('.')[0]):
                            svc['port'] = port
                            svc['target'] = target
                            found = True
                            break

                    if not found:
                        results['services'].append({
                            'name': name,
                            'port': port,
                            'target': target,
                            'type': 'SRV'
                        })

                # A record (hostname)
                elif rtype == 1 and rdlength == 4:
                    ip = '.'.join(str(b) for b in rdata)
                    results['addresses'].append(ip)
                    if not results['hostname'] and name.endswith('.local'):
                        results['hostname'] = name

                # TXT record (additional info)
                elif rtype == 16:
                    txt_data = rdata.decode('utf-8', errors='ignore')
                    for svc in results['services']:
                        if 'txt' not in svc:
                            svc['txt'] = []
                        svc['txt'].append(txt_data)

            except Exception as e:
                self.log(f"Parse error at offset {offset}: {e}", "DEBUG")
                continue

        return results

    def query_mdns_unicast(self, target_ip):
        """Query specific host via unicast mDNS"""
        self.log(f"Querying {target_ip} via unicast mDNS", "DEBUG")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        all_results = {
            'hostname': None,
            'services': [],
            'addresses': []
        }

        # Common mDNS query types
        queries = [
            ('_services._dns-sd._udp.local', 12),  # Service enumeration
            ('*.local', 12),  # All local services
        ]

        for qname, qtype in queries:
            try:
                query = self.create_mdns_query(qname, qtype)
                sock.sendto(query, (target_ip, self.mdns_port))

                # Collect responses
                start_time = time.time()
                while time.time() - start_time < self.timeout:
                    ready = select.select([sock], [], [], 0.5)
                    if ready[0]:
                        try:
                            data, addr = sock.recvfrom(4096)
                            results = self.parse_mdns_response(data)

                            if results:
                                if results['hostname']:
                                    all_results['hostname'] = results['hostname']
                                all_results['services'].extend(results['services'])
                                all_results['addresses'].extend(results['addresses'])
                        except socket.timeout:
                            break
                    else:
                        break

            except Exception as e:
                self.log(f"Query error: {e}", "DEBUG")

        sock.close()

        # Deduplicate services
        seen = set()
        unique_services = []
        for svc in all_results['services']:
            svc_key = (svc.get('name'), svc.get('port'))
            if svc_key not in seen:
                seen.add(svc_key)
                unique_services.append(svc)
        all_results['services'] = unique_services

        return all_results

    def query_mdns_multicast(self, target_ip):
        """Query via multicast (passive enumeration)"""
        self.log(f"Listening for multicast mDNS from {target_ip}", "DEBUG")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to mDNS port
        sock.bind(('', self.mdns_port))

        # Join multicast group
        mreq = struct.pack('4sl', socket.inet_aton(self.mdns_group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(self.timeout)

        all_results = {
            'hostname': None,
            'services': [],
            'addresses': []
        }

        start_time = time.time()
        while time.time() - start_time < self.timeout:
            try:
                data, addr = sock.recvfrom(4096)

                # Only process responses from target IP
                if addr[0] == target_ip:
                    results = self.parse_mdns_response(data)

                    if results:
                        if results['hostname']:
                            all_results['hostname'] = results['hostname']
                        all_results['services'].extend(results['services'])
                        all_results['addresses'].extend(results['addresses'])

            except socket.timeout:
                break
            except Exception as e:
                self.log(f"Multicast error: {e}", "DEBUG")

        sock.close()
        return all_results

    def enumerate_target(self, target_ip):
        """Enumerate mDNS information from target"""
        self.log(f"Enumerating {target_ip}", "INFO")

        # Try unicast first (more reliable)
        results = self.query_mdns_unicast(target_ip)

        # If no results, try multicast listening
        if not results['services'] and not results['hostname']:
            self.log("No unicast response, trying multicast...", "DEBUG")
            results = self.query_mdns_multicast(target_ip)

        return results

    def format_output(self, target_ip, results):
        """Format results in Nessus-like output"""
        output = []
        output.append(f"\n{target_ip} (udp/{self.mdns_port}/mdns)")

        if not results['hostname'] and not results['services']:
            output.append("  No mDNS information extracted (service may be filtered or inactive)")
            return '\n'.join(output)

        output.append("Nessus was able to extract the following information :")

        if results['hostname']:
            output.append(f"  - mDNS hostname : {results['hostname']}")

        if results['services']:
            output.append("  - Advertised services :")

            # Sort services by name
            sorted_services = sorted(results['services'],
                                   key=lambda x: x.get('name', ''))

            for svc in sorted_services:
                svc_name = svc.get('name', 'Unknown')
                svc_port = svc.get('port', 'Unknown')

                output.append(f"      o Service name : {svc_name}")
                output.append(f"        Port number : {svc_port}")

                if 'target' in svc:
                    output.append(f"        Target : {svc['target']}")
                if 'txt' in svc:
                    output.append(f"        TXT : {', '.join(svc['txt'])}")

        if results['addresses']:
            output.append(f"  - IP addresses : {', '.join(set(results['addresses']))}")

        return '\n'.join(output)


def validate_ip(ip_string):
    """Validate IP address"""
    try:
        ip_address(ip_string)
        return True
    except ValueError:
        return False


def load_targets(target_file):
    """Load targets from file"""
    targets = []
    try:
        with open(target_file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    if validate_ip(ip):
                        targets.append(ip)
                    else:
                        print(f"[!] Invalid IP address: {ip}")
        return targets
    except FileNotFoundError:
        print(f"[ERROR] File not found: {target_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error reading file: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Enumerate system information from mDNS service',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.100
  %(prog)s -t 192.168.1.100 -v
  %(prog)s -f targets.txt
  %(prog)s -f targets.txt --timeout 10 -o results.txt

Target file format (one IP per line):
  192.168.1.100
  192.168.1.101
  # Comments are ignored
  192.168.1.102
        """
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target',
                            help='Single target IP address')
    target_group.add_argument('-f', '--file',
                            help='File containing target IPs (one per line)')

    parser.add_argument('--timeout', type=int, default=5,
                        help='Query timeout in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-o', '--output',
                        help='Output file (default: stdout)')

    args = parser.parse_args()

    # Validate and collect targets
    targets = []
    if args.target:
        if validate_ip(args.target):
            targets.append(args.target)
        else:
            print(f"[ERROR] Invalid IP address: {args.target}")
            sys.exit(1)
    else:
        targets = load_targets(args.file)

    if not targets:
        print("[ERROR] No valid targets specified")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"mDNS Service Enumeration")
    print(f"{'='*60}")
    print(f"Targets: {len(targets)}")
    print(f"Timeout: {args.timeout} seconds")
    print(f"{'='*60}\n")

    # Initialize enumerator
    enumerator = mDNSEnumerator(timeout=args.timeout, verbose=args.verbose)

    # Collect all results
    all_output = []

    try:
        for i, target in enumerate(targets, 1):
            print(f"[*] Scanning {target} ({i}/{len(targets)})")

            try:
                results = enumerator.enumerate_target(target)
                output = enumerator.format_output(target, results)
                all_output.append(output)
                print(output)

            except KeyboardInterrupt:
                raise
            except Exception as e:
                error_msg = f"\n{target} (udp/5353/mdns)\n  Error: {str(e)}"
                all_output.append(error_msg)
                print(error_msg)

        # Write to output file if specified
        if args.output:
            with open(args.output, 'w') as f:
                f.write('\n\n'.join(all_output))
            print(f"\n[+] Results written to: {args.output}")

        print(f"\n{'='*60}")
        print(f"Scan complete: {len(targets)} targets processed")
        print(f"{'='*60}\n")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
