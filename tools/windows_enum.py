#!/usr/bin/env python3
# =============================================================================
# VAPT Toolkit - Windows System Enumeration Tool (Impacket-Only)
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
#
# Purpose: Comprehensive Windows system enumeration tool for authorized
#          penetration testing using Impacket suite exclusively.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind.
#             For authorized security testing only.
#
# NOTICE: This toolkit is intended for authorized security testing only.
#         Users are responsible for ensuring compliance with all applicable laws.
#
# =============================================================================

import argparse
import ipaddress
import socket
import subprocess
import sys
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
import atexit
import signal

try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def cleanup_terminal():
    """Restore terminal to normal state"""
    try:
        # Clear any remaining progress indicators
        print(f"\r{' ' * 100}\r", end='', flush=True)
        # Reset all terminal attributes
        print(f"{Colors.RESET}", end='', flush=True)
        # Make cursor visible again
        print("\033[?25h", end='', flush=True)
        sys.stdout.flush()
        sys.stderr.flush()
    except:
        pass

# Register cleanup on exit
atexit.register(cleanup_terminal)

# Register cleanup on interrupt
def signal_handler(sig, frame):
    cleanup_terminal()
    sys.exit(130)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Windows-specific ports to check
WINDOWS_PORTS = {
    135: 'RPC',
    139: 'NetBIOS-SSN',
    445: 'SMB',
    3389: 'RDP',
    5985: 'WinRM HTTP',
    5986: 'WinRM HTTPS',
    88: 'Kerberos',
    389: 'LDAP',
    636: 'LDAPS',
    3268: 'Global Catalog',
    3269: 'Global Catalog SSL',
    53: 'DNS',
    1433: 'MSSQL'
}

TOOL_PATHS = {
    'nmap': None,
    'lookupsid.py': None,
    'samrdump.py': None,
    'rpcdump.py': None,
    'smbclient.py': None,
    'reg.py': None,
    'atexec.py': None,
    'netview.py': None,
    'GetADUsers.py': None,
    'GetUserSPNs.py': None
}


def find_tool_path(tool_name: str) -> Optional[str]:
    """
    Locate the full path of a tool using multiple methods
    Returns the full path if found, None otherwise
    """
    import shutil

    # Method 1: Use shutil.which (checks PATH)
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path

    # Method 2: Check common installation paths
    common_paths = [
        '/usr/bin',
        '/usr/local/bin',
        '/opt',
        os.path.expanduser('~/.local/bin'),
        '/usr/share/doc',
        os.path.expanduser('~/tools')
    ]

    for base_path in common_paths:
        try:
            cmd = ['find', base_path, '-name', tool_name, '-type', 'f', '-executable']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, stderr=subprocess.DEVNULL)

            if result.returncode == 0 and result.stdout.strip():
                paths = result.stdout.strip().split('\n')
                if paths:
                    return paths[0]
        except:
            continue

    # Method 3: Try locate command if available
    try:
        cmd = ['locate', '-l', '1', tool_name]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split('\n')[0]
    except:
        pass

    # Check if it's in current directory
    if os.path.isfile(tool_name) and os.access(tool_name, os.X_OK):
        return os.path.abspath(tool_name)

    return None


def initialize_tools() -> bool:
    """
    Initialize all required tools and verify they exist
    Returns True if critical tools are found
    """
    print(f"\n{Colors.BOLD}[*] Locating Impacket tools...{Colors.RESET}")

    # Critical tools
    critical_tools = ['lookupsid.py', 'smbclient.py']
    critical_found = False

    # Locate all tools
    for tool in TOOL_PATHS.keys():
        path = find_tool_path(tool)
        TOOL_PATHS[tool] = path

        if path:
            print(f"{Colors.GREEN}[+] Found {tool}: {path}{Colors.RESET}")
            if tool in critical_tools:
                critical_found = True
        else:
            print(f"{Colors.YELLOW}[!] {tool} not found (optional){Colors.RESET}")

    # Check Python libraries
    print(f"\n{Colors.BOLD}[*] Checking Python libraries...{Colors.RESET}")

    if SCAPY_AVAILABLE:
        print(f"{Colors.GREEN}[+] Scapy available{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] Scapy not available - install with: pip install scapy{Colors.RESET}")

    if not critical_found:
        print(f"\n{Colors.RED}[!] Critical Impacket tools missing. Install with:{Colors.RESET}")
        print(f"    pip install impacket")
        return False

    print()
    return True


def get_tool_command(tool_name: str, args: List[str]) -> Optional[List[str]]:
    """
    Build command list for a tool using its located path
    Returns command list ready for subprocess, or None if tool not found
    """
    tool_path = TOOL_PATHS.get(tool_name)

    if not tool_path:
        return None

    # For Python scripts, explicitly call with python3
    if tool_name.endswith('.py') and not os.access(tool_path, os.X_OK):
        return ['python3', tool_path] + args
    else:
        return [tool_path] + args


def print_banner():
    """Display tool banner"""
    banner = f"""
{Colors.CYAN}{'='*70}
    Windows System Enumeration Tool (Impacket Suite)
    Comprehensive Windows Enumeration Using Impacket Only
    For Authorized Penetration Testing Only
{'='*70}{Colors.RESET}
    """
    print(banner)


def parse_exclusions(exclude_list: List[str]) -> Set[str]:
    """
    Parse exclusion list and expand any subnets to individual IPs
    Returns a set of IPs to exclude
    """
    excluded_ips = set()

    for item in exclude_list:
        item = item.strip()
        if not item:
            continue

        try:
            if '/' in item:
                network = ipaddress.ip_network(item, strict=False)
                excluded_ips.update([str(ip) for ip in network.hosts()])
            else:
                ipaddress.ip_address(item)  # Validate
                excluded_ips.add(item)
        except ValueError:
            print(f"{Colors.YELLOW}[!] Invalid exclusion IP/subnet: {item}{Colors.RESET}")

    return excluded_ips


def read_targets(filename: str, excluded_ips: Optional[Set[str]] = None) -> List[str]:
    """Read targets from file and expand subnets to individual IPs"""
    if excluded_ips is None:
        excluded_ips = set()

    targets = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                try:
                    if '/' in line:
                        network = ipaddress.ip_network(line, strict=False)
                        for ip in network.hosts():
                            ip_str = str(ip)
                            if ip_str not in excluded_ips:
                                targets.append(ip_str)
                    else:
                        ipaddress.ip_address(line)  # Validate
                        if line not in excluded_ips:
                            targets.append(line)
                except ValueError:
                    print(f"{Colors.YELLOW}[!] Invalid IP/subnet: {line}{Colors.RESET}")

    except FileNotFoundError:
        print(f"{Colors.RED}[!] File not found: {filename}{Colors.RESET}")
        sys.exit(1)

    return targets


def check_port_socket(ip: str, port: int, timeout: float = 2) -> bool:
    """Check if a port is open using socket"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_windows_ports(ip: str, timeout: float = 1) -> Dict[int, str]:
    """
    Scan common Windows ports on target using nmap (or socket fallback)
    Returns dict of open ports with their services
    """
    open_ports = {}

    # Use nmap if available
    if TOOL_PATHS['nmap']:
        try:
            ports_str = ','.join([str(p) for p in WINDOWS_PORTS.keys()])

            cmd = get_tool_command('nmap', [
                '-p', ports_str,
                '--open',
                '-T4',
                '-Pn',
                '--host-timeout', '30s',
                '--max-retries', '1',
                ip
            ])

            if cmd:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)

                if result.returncode == 0:
                    # Parse nmap output
                    for line in result.stdout.split('\n'):
                        for port, service in WINDOWS_PORTS.items():
                            if f'{port}/tcp' in line and 'open' in line:
                                open_ports[port] = service

                    return open_ports
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    # Fallback to socket scanning if nmap fails or unavailable
    for port, service in WINDOWS_PORTS.items():
        if check_port_socket(ip, port, timeout):
            open_ports[port] = service

    return open_ports


def identify_windows_system(ip: str) -> Tuple[bool, Dict[int, str]]:
    """
    Identify if target is a Windows system by checking common Windows ports
    Returns (is_windows, open_ports_dict)
    """
    open_ports = scan_windows_ports(ip, timeout=1)

    # Consider it Windows if it has SMB (445) or NetBIOS (139) or RPC (135)
    has_smb = 445 in open_ports
    has_netbios = 139 in open_ports
    has_rpc = 135 in open_ports
    has_winrm = 5985 in open_ports or 5986 in open_ports

    is_windows = has_smb or has_netbios or has_rpc or has_winrm

    return is_windows, open_ports


def scan_for_windows_systems(targets: List[str], max_threads: int = 50) -> List[Dict]:
    """Scan targets to identify Windows systems"""
    print(f"\n{Colors.BOLD}[*] Scanning {len(targets)} targets for Windows systems...{Colors.RESET}")

    windows_systems = []
    completed = 0
    total = len(targets)

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {executor.submit(identify_windows_system, ip): ip for ip in targets}

            try:
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1

                    try:
                        is_windows, open_ports = future.result()
                        if is_windows:
                            windows_systems.append({'ip': ip, 'ports': open_ports})
                            services = ', '.join([f"{p}({s})" for p, s in open_ports.items()])
                            print(f"\r{' ' * 100}\r{Colors.GREEN}[+] Windows system found: {ip} [{services}]{Colors.RESET}")
                    except Exception as e:
                        pass

                    # Update progress bar
                    percent = (completed / total) * 100
                    bar_length = 40
                    filled = int(bar_length * completed / total)
                    bar = '█' * filled + '░' * (bar_length - filled)
                    print(f"\r{Colors.BLUE}[*] Progress: [{bar}] {completed}/{total} ({percent:.1f}%) - {len(windows_systems)} system(s) found{Colors.RESET}", end='')
                    sys.stdout.flush()

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Scan interrupted. Cancelling remaining tasks...{Colors.RESET}")
                for future in future_to_ip:
                    future.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
                raise

    except KeyboardInterrupt:
        if windows_systems:
            print(f"\n{Colors.YELLOW}[!] Returning {len(windows_systems)} Windows system(s) found so far{Colors.RESET}")
        raise

    print(f"\r{' ' * 100}\r", end='', flush=True)
    sys.stdout.flush()
    return windows_systems


def enum_lookupsid(ip: str, domain: str = '', username: str = '', password: str = '', output_dir: str = '') -> Dict:
    """
    Enumerate users, groups, and domain SID using Impacket lookupsid.py (RID cycling)
    This replaces enum4linux user/group enumeration
    """
    print(f"{Colors.BOLD}[*] Enumerating via RID cycling (lookupsid.py)...{Colors.RESET}")

    result_data = {
        'users': [],
        'groups': [],
        'domain_sid': None,
        'computer_name': None,
        'domain_name': None
    }

    if not TOOL_PATHS['lookupsid.py']:
        print(f"{Colors.YELLOW}[!] lookupsid.py not available{Colors.RESET}")
        return result_data

    try:
        # Build target string
        if username and password:
            target = f'{domain}/{username}:{password}@{ip}' if domain else f'{username}:{password}@{ip}'
        else:
            # Try anonymous/guest access
            target = f'{domain}/guest@{ip}' if domain else f'guest@{ip}'

        cmd = get_tool_command('lookupsid.py', [target, '-no-pass'] if not password else [target])

        if not cmd:
            return result_data

        # Save output to file for analysis
        output_file = os.path.join(output_dir, f'lookupsid_{ip}.txt')

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # Save raw output
        with open(output_file, 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n\n=== STDERR ===\n")
                f.write(result.stderr)

        if result.returncode == 0 or result.stdout:
            output = result.stdout

            # Extract Domain SID
            for line in output.split('\n'):
                if 'Domain SID is:' in line or 'Domain SID:' in line:
                    sid_match = re.search(r'S-1-5-21-[\d-]+', line)
                    if sid_match:
                        result_data['domain_sid'] = sid_match.group(0)

                # Extract domain/computer name
                if '\\' in line and ('SidTypeUser' in line or 'SidTypeDomain' in line):
                    parts = line.split('\\')
                    if len(parts) >= 2:
                        domain_part = parts[0].split(':')[-1].strip()
                        if not result_data['domain_name'] and 'SidTypeDomain' in line:
                            result_data['domain_name'] = domain_part
                        elif not result_data['computer_name']:
                            result_data['computer_name'] = domain_part

            # Parse users
            for line in output.split('\n'):
                if 'SidTypeUser' in line:
                    try:
                        # Line format: "500: DOMAIN\Administrator (SidTypeUser)"
                        user_part = line.split(':')[1].split('(')[0].strip()
                        if '\\' in user_part:
                            user = user_part.split('\\')[1]
                        else:
                            user = user_part

                        # Filter out machine accounts
                        if not user.endswith('$'):
                            result_data['users'].append(user)
                    except:
                        pass

            # Parse groups
            for line in output.split('\n'):
                if 'SidTypeGroup' in line or 'SidTypeAlias' in line:
                    try:
                        group_part = line.split(':')[1].split('(')[0].strip()
                        if '\\' in group_part:
                            group = group_part.split('\\')[1]
                        else:
                            group = group_part
                        result_data['groups'].append(group)
                    except:
                        pass

            # Remove duplicates
            result_data['users'] = list(set(result_data['users']))
            result_data['groups'] = list(set(result_data['groups']))

            if result_data['users']:
                print(f"{Colors.GREEN}[+] Found {len(result_data['users'])} users via RID cycling{Colors.RESET}")
            if result_data['groups']:
                print(f"{Colors.GREEN}[+] Found {len(result_data['groups'])} groups via RID cycling{Colors.RESET}")
            if result_data['domain_sid']:
                print(f"{Colors.GREEN}[+] Domain SID: {result_data['domain_sid']}{Colors.RESET}")
            if result_data['domain_name']:
                print(f"{Colors.GREEN}[+] Domain: {result_data['domain_name']}{Colors.RESET}")

            result_data['output_file'] = output_file

    except subprocess.TimeoutExpired:
        print(f"{Colors.YELLOW}[!] lookupsid.py timed out{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error with lookupsid.py: {e}{Colors.RESET}")

    return result_data


def enum_samrdump(ip: str, username: str = '', password: str = '', domain: str = '') -> Dict:
    """
    Enumerate SAM database using Impacket samrdump.py
    Provides password policy and additional user info
    """
    print(f"{Colors.BOLD}[*] Querying SAM database (samrdump.py)...{Colors.RESET}")

    sam_info = {
        'users': [],
        'password_policy': {}
    }

    if not TOOL_PATHS['samrdump.py']:
        print(f"{Colors.YELLOW}[!] samrdump.py not available{Colors.RESET}")
        return sam_info

    try:
        # Build target
        if username or password:
            creds = f'{username}:{password}@' if username else f':{password}@'
        else:
            creds = ''

        if domain:
            target = f'{domain}/{creds}{ip}'
        else:
            target = f'{creds}{ip}'

        cmd = get_tool_command('samrdump.py', [target])

        if not cmd:
            return sam_info

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            output = result.stdout

            # Parse users
            for line in output.split('\n'):
                if 'Found user:' in line or 'Name:' in line:
                    try:
                        user = line.split(':')[1].strip()
                        if user and not user.endswith('$'):
                            sam_info['users'].append(user)
                    except:
                        pass

            # Parse password policy
            for line in output.split('\n'):
                if 'Minimum password length:' in line:
                    try:
                        sam_info['password_policy']['min_length'] = line.split(':')[1].strip()
                    except:
                        pass
                elif 'Password history length:' in line:
                    try:
                        sam_info['password_policy']['history_length'] = line.split(':')[1].strip()
                    except:
                        pass
                elif 'Maximum password age:' in line:
                    try:
                        sam_info['password_policy']['max_age'] = line.split(':')[1].strip()
                    except:
                        pass
                elif 'Password Complexity Flags:' in line:
                    try:
                        sam_info['password_policy']['complexity'] = line.split(':')[1].strip()
                    except:
                        pass
                elif 'Lockout threshold:' in line:
                    try:
                        sam_info['password_policy']['lockout_threshold'] = line.split(':')[1].strip()
                    except:
                        pass

            if sam_info['users']:
                print(f"{Colors.GREEN}[+] Found {len(sam_info['users'])} users in SAM database{Colors.RESET}")

            if sam_info['password_policy']:
                print(f"{Colors.GREEN}[+] Retrieved password policy{Colors.RESET}")

    except subprocess.TimeoutExpired:
        print(f"{Colors.YELLOW}[!] samrdump.py timed out{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error with samrdump.py: {e}{Colors.RESET}")

    return sam_info


def enum_rpcdump(ip: str, output_dir: str) -> Dict:
    """
    Enumerate RPC endpoints using Impacket rpcdump.py
    Maps available RPC services
    """
    print(f"{Colors.BOLD}[*] Enumerating RPC endpoints (rpcdump.py)...{Colors.RESET}")

    rpc_info = {}

    if not TOOL_PATHS['rpcdump.py']:
        print(f"{Colors.YELLOW}[!] rpcdump.py not available{Colors.RESET}")
        return rpc_info

    try:
        output_file = os.path.join(output_dir, f'rpcdump_{ip}.txt')

        cmd = get_tool_command('rpcdump.py', [ip])

        if not cmd:
            return rpc_info

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # Save output
        with open(output_file, 'w') as f:
            f.write(result.stdout)

        if result.returncode == 0:
            # Count endpoints
            endpoint_count = result.stdout.count('Protocol:')
            rpc_info['endpoint_count'] = endpoint_count
            rpc_info['output_file'] = output_file
            print(f"{Colors.GREEN}[+] Found {endpoint_count} RPC endpoints - saved to {output_file}{Colors.RESET}")

    except subprocess.TimeoutExpired:
        print(f"{Colors.YELLOW}[!] rpcdump.py timed out{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error with rpcdump.py: {e}{Colors.RESET}")

    return rpc_info


def enum_shares_smbclient(ip: str, username: str = '', password: str = '', domain: str = '', output_dir: str = '') -> Dict:
    """
    Enumerate shares using Impacket smbclient.py
    Also extracts OS information from SMB connection
    """
    print(f"{Colors.BOLD}[*] Enumerating shares and OS info (smbclient.py)...{Colors.RESET}")

    share_info = {
        'shares': [],
        'os_info': {},
        'smb_info': {}
    }

    if not TOOL_PATHS['smbclient.py']:
        return share_info

    try:
        # Build target
        if username or password:
            creds = f'{username}:{password}@' if username else f':{password}@'
        else:
            creds = ''

        if domain:
            target = f'{domain}/{creds}{ip}'
        else:
            target = f'{creds}{ip}'

        # Use shares command to list shares
        cmd = get_tool_command('smbclient.py', [target, '-list'] if not password else [target, '-list'])

        if not cmd:
            return share_info

        output_file = os.path.join(output_dir, f'smbclient_{ip}.txt')

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # Save output
        with open(output_file, 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n\n=== STDERR ===\n")
                f.write(result.stderr)

        if result.returncode == 0 or result.stdout:
            output = result.stdout

            # Extract OS information from connection banner
            for line in output.split('\n'):
                if 'Windows' in line or 'OS:' in line:
                    share_info['os_info']['banner'] = line.strip()

                # Parse SMB version
                if 'SMB' in line and 'dialect' in line.lower():
                    share_info['smb_info']['dialect'] = line.strip()

            # Parse shares
            in_shares_section = False
            for line in output.split('\n'):
                # Look for share listings
                if 'DISK' in line or 'IPC' in line or 'PRINTER' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        share_name = parts[0]
                        share_type = 'DISK' if 'DISK' in line else ('IPC' if 'IPC' in line else 'PRINTER')

                        # Extract comment if present
                        comment = ''
                        if len(parts) > 2:
                            comment = ' '.join(parts[2:])

                        share_info['shares'].append({
                            'name': share_name,
                            'type': share_type,
                            'comment': comment
                        })

            if share_info['shares']:
                print(f"{Colors.GREEN}[+] Found {len(share_info['shares'])} shares{Colors.RESET}")
                for share in share_info['shares'][:5]:  # Show first 5
                    print(f"    - {share['name']} ({share['type']})")
                if len(share_info['shares']) > 5:
                    print(f"    ... and {len(share_info['shares']) - 5} more")

            if share_info['os_info'].get('banner'):
                print(f"{Colors.GREEN}[+] OS Info: {share_info['os_info']['banner']}{Colors.RESET}")

            share_info['output_file'] = output_file

    except subprocess.TimeoutExpired:
        print(f"{Colors.YELLOW}[!] smbclient.py timed out{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error with smbclient.py: {e}{Colors.RESET}")

    return share_info


def enum_sessions(ip: str, username: str = '', password: str = '', domain: str = '') -> Dict:
    """
    Enumerate active sessions using Impacket (if netview available)
    Shows logged on users and active sessions
    """
    print(f"{Colors.BOLD}[*] Enumerating sessions (netview.py)...{Colors.RESET}")

    session_info = {
        'sessions': [],
        'logged_on_users': []
    }

    if not TOOL_PATHS.get('netview.py'):
        print(f"{Colors.YELLOW}[!] netview.py not available (optional){Colors.RESET}")
        return session_info

    try:
        # Build target
        if username and password:
            target = f'{domain}/{username}:{password}@{ip}' if domain else f'{username}:{password}@{ip}'
        else:
            return session_info  # Sessions typically require auth

        cmd = get_tool_command('netview.py', [target, '-target', ip])

        if not cmd:
            return session_info

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            # Parse logged on users
            for line in result.stdout.split('\n'):
                if 'logged on' in line.lower() or 'session' in line.lower():
                    session_info['sessions'].append(line.strip())

            if session_info['sessions']:
                print(f"{Colors.GREEN}[+] Found {len(session_info['sessions'])} active sessions{Colors.RESET}")

    except subprocess.TimeoutExpired:
        print(f"{Colors.YELLOW}[!] netview.py timed out{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error with netview.py: {e}{Colors.RESET}")

    return session_info


def enumerate_windows_system(ip: str, ports: Dict, output_dir: str, username: str = '', password: str = '', domain: str = '') -> Dict:
    """
    Comprehensive enumeration of a Windows system using only Impacket tools
    """
    print(f"\n{Colors.BOLD}{'='*70}")
    print(f"[*] Enumerating Windows System: {ip}")
    print(f"{'='*70}{Colors.RESET}")

    system_info = {
        'ip': ip,
        'ports': ports,
        'timestamp': datetime.now().isoformat()
    }

    # 1. RID Cycling - Users, Groups, Domain SID (replaces enum4linux -U -G)
    lookupsid_results = enum_lookupsid(ip, domain, username, password, output_dir)
    if lookupsid_results:
        system_info['lookupsid'] = lookupsid_results

        # Extract domain for subsequent queries
        if not domain and lookupsid_results.get('domain_name'):
            domain = lookupsid_results['domain_name']

    # 2. SAM Database - Password Policy (replaces enum4linux -P)
    sam_info = enum_samrdump(ip, username, password, domain)
    if sam_info:
        system_info['sam'] = sam_info

    # 3. Share Enumeration + OS Info (replaces enum4linux -S)
    share_info = enum_shares_smbclient(ip, username, password, domain, output_dir)
    if share_info:
        system_info['shares'] = share_info

    # 4. RPC Endpoint Enumeration (replaces enum4linux -r)
    if 135 in ports:
        rpc_info = enum_rpcdump(ip, output_dir)
        if rpc_info:
            system_info['rpc'] = rpc_info

    # 5. Session Enumeration (replaces enum4linux -i)
    if username and password:
        session_info = enum_sessions(ip, username, password, domain)
        if session_info and session_info['sessions']:
            system_info['sessions'] = session_info

    return system_info

def save_results(system_info: Dict, output_dir: str):
    """Save enumeration results to consolidated files per host"""
    try:
        os.makedirs(output_dir, exist_ok=True)

        # Create raw outputs subdirectory
        raw_dir = os.path.join(output_dir, 'raw')
        os.makedirs(raw_dir, exist_ok=True)

        ip = system_info['ip']
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Create single comprehensive report file per host
        report_file = os.path.join(output_dir, f'{ip}_report.txt')

        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write(f"Windows Enumeration Report - {ip}\n")
            f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")

            # System Information
            f.write("[SYSTEM INFORMATION]\n")
            f.write("-"*70 + "\n")

            if 'lookupsid' in system_info:
                ls = system_info['lookupsid']
                if ls.get('computer_name'):
                    f.write(f"Computer Name: {ls['computer_name']}\n")
                if ls.get('domain_name'):
                    f.write(f"Domain: {ls['domain_name']}\n")
                if ls.get('domain_sid'):
                    f.write(f"Domain SID: {ls['domain_sid']}\n")

            if 'shares' in system_info and 'os_info' in system_info['shares']:
                if system_info['shares']['os_info'].get('banner'):
                    f.write(f"OS Info: {system_info['shares']['os_info']['banner']}\n")

            if 'ports' in system_info:
                ports_str = ', '.join([f"{p}({s})" for p, s in system_info['ports'].items()])
                f.write(f"Open Ports: {ports_str}\n")

            f.write("\n")

            # Users
            f.write("[USERS]\n")
            f.write("-"*70 + "\n")

            all_users = set()
            if 'lookupsid' in system_info and 'users' in system_info['lookupsid']:
                all_users.update(system_info['lookupsid']['users'])
            if 'sam' in system_info and 'users' in system_info['sam']:
                all_users.update(system_info['sam']['users'])

            if all_users:
                for user in sorted(all_users):
                    f.write(f"  - {user}\n")
                f.write(f"\nTotal Users: {len(all_users)}\n")
            else:
                f.write("  No users enumerated\n")

            f.write("\n")

            # Groups
            f.write("[GROUPS]\n")
            f.write("-"*70 + "\n")

            if 'lookupsid' in system_info and 'groups' in system_info['lookupsid']:
                groups = system_info['lookupsid']['groups']
                if groups:
                    for group in sorted(groups):
                        f.write(f"  - {group}\n")
                    f.write(f"\nTotal Groups: {len(groups)}\n")
                else:
                    f.write("  No groups enumerated\n")
            else:
                f.write("  No groups enumerated\n")

            f.write("\n")

            # Shares
            f.write("[SHARES]\n")
            f.write("-"*70 + "\n")

            if 'shares' in system_info and 'shares' in system_info['shares']:
                shares_list = system_info['shares']['shares']
                if shares_list:
                    for share in shares_list:
                        f.write(f"  - {share['name']} ({share['type']})")
                        if share.get('comment'):
                            f.write(f" - {share['comment']}")
                        f.write("\n")
                    f.write(f"\nTotal Shares: {len(shares_list)}\n")
                else:
                    f.write("  No shares enumerated\n")
            else:
                f.write("  No shares enumerated\n")

            f.write("\n")

            # Password Policy
            f.write("[PASSWORD POLICY]\n")
            f.write("-"*70 + "\n")

            if 'sam' in system_info and 'password_policy' in system_info['sam']:
                policy = system_info['sam']['password_policy']
                if policy:
                    for key, value in policy.items():
                        f.write(f"  {key.replace('_', ' ').title()}: {value}\n")
                else:
                    f.write("  No password policy retrieved\n")
            else:
                f.write("  No password policy retrieved\n")

            f.write("\n")

            # RPC Endpoints
            if 'rpc' in system_info and 'endpoint_count' in system_info['rpc']:
                f.write("[RPC ENDPOINTS]\n")
                f.write("-"*70 + "\n")
                f.write(f"  Total Endpoints: {system_info['rpc']['endpoint_count']}\n")
                f.write(f"  Details: See {system_info['rpc']['output_file']}\n")
                f.write("\n")

            # Sessions
            if 'sessions' in system_info and 'sessions' in system_info['sessions']:
                f.write("[ACTIVE SESSIONS]\n")
                f.write("-"*70 + "\n")
                sessions = system_info['sessions']['sessions']
                if sessions:
                    for session in sessions:
                        f.write(f"  - {session}\n")
                    f.write(f"\nTotal Sessions: {len(sessions)}\n")
                else:
                    f.write("  No active sessions\n")
                f.write("\n")

            # Raw Output References
            f.write("[RAW TOOL OUTPUTS]\n")
            f.write("-"*70 + "\n")
            if 'lookupsid' in system_info and 'output_file' in system_info['lookupsid']:
                f.write(f"  RID Cycling: {system_info['lookupsid']['output_file']}\n")
            if 'shares' in system_info and 'output_file' in system_info['shares']:
                f.write(f"  SMB Client: {system_info['shares']['output_file']}\n")
            if 'rpc' in system_info and 'output_file' in system_info['rpc']:
                f.write(f"  RPC Dump: {system_info['rpc']['output_file']}\n")

            f.write("\n")
            f.write("="*70 + "\n")
            f.write("End of Report\n")
            f.write("="*70 + "\n")

        print(f"{Colors.GREEN}[+] Consolidated report saved to {report_file}{Colors.RESET}")

        # Move raw tool outputs to raw subdirectory
        if 'lookupsid' in system_info and 'output_file' in system_info['lookupsid']:
            old_path = system_info['lookupsid']['output_file']
            if os.path.exists(old_path):
                new_path = os.path.join(raw_dir, os.path.basename(old_path))
                os.rename(old_path, new_path)
                system_info['lookupsid']['output_file'] = new_path

        if 'shares' in system_info and 'output_file' in system_info['shares']:
            old_path = system_info['shares']['output_file']
            if os.path.exists(old_path):
                new_path = os.path.join(raw_dir, os.path.basename(old_path))
                os.rename(old_path, new_path)
                system_info['shares']['output_file'] = new_path

        if 'rpc' in system_info and 'output_file' in system_info['rpc']:
            old_path = system_info['rpc']['output_file']
            if os.path.exists(old_path):
                new_path = os.path.join(raw_dir, os.path.basename(old_path))
                os.rename(old_path, new_path)
                system_info['rpc']['output_file'] = new_path

        # Save JSON summary
        json_file = os.path.join(output_dir, f'{ip}_data.json')
        with open(json_file, 'w') as f:
            json.dump(system_info, f, indent=2, default=str)
        print(f"{Colors.GREEN}[+] JSON data saved to {json_file}{Colors.RESET}")

    except Exception as e:
        print(f"{Colors.RED}[!] Error saving results: {e}{Colors.RESET}")

def print_summary(systems: List[Dict]):
    """Print enumeration summary"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}")
    print("=== ENUMERATION SUMMARY ===")
    print(f"{'='*70}{Colors.RESET}\n")

    for system in systems:
        print(f"{Colors.BOLD}System: {system['ip']}{Colors.RESET}")

        # Domain/Computer info
        if 'lookupsid' in system:
            if 'computer_name' in system['lookupsid'] and system['lookupsid']['computer_name']:
                print(f"  Computer Name: {system['lookupsid']['computer_name']}")
            if 'domain_name' in system['lookupsid'] and system['lookupsid']['domain_name']:
                print(f"  Domain: {system['lookupsid']['domain_name']}")
            if 'domain_sid' in system['lookupsid'] and system['lookupsid']['domain_sid']:
                print(f"  Domain SID: {system['lookupsid']['domain_sid']}")

        # OS Info
        if 'shares' in system and 'os_info' in system['shares']:
            if 'banner' in system['shares']['os_info']:
                print(f"  OS: {system['shares']['os_info']['banner']}")

        # User counts
        if 'lookupsid' in system and 'users' in system['lookupsid']:
            print(f"  Users Found (RID cycling): {len(system['lookupsid']['users'])}")

        if 'sam' in system and 'users' in system['sam']:
            print(f"  Users Found (SAM): {len(system['sam']['users'])}")

        # Group count
        if 'lookupsid' in system and 'groups' in system['lookupsid']:
            print(f"  Groups Found: {len(system['lookupsid']['groups'])}")

        # Share count
        if 'shares' in system and 'shares' in system['shares']:
            print(f"  Shares Found: {len(system['shares']['shares'])}")

        # Password policy
        if 'sam' in system and 'password_policy' in system['sam']:
            if system['sam']['password_policy']:
                print(f"  Password Policy: Retrieved")

        # RPC endpoints
        if 'rpc' in system and 'endpoint_count' in system['rpc']:
            print(f"  RPC Endpoints: {system['rpc']['endpoint_count']}")

        # Sessions
        if 'sessions' in system and 'sessions' in system['sessions']:
            print(f"  Active Sessions: {len(system['sessions']['sessions'])}")

        # Open ports
        if 'ports' in system:
            ports_str = ', '.join([f"{p}({s})" for p, s in system['ports'].items()])
            print(f"  Open Ports: {ports_str}")

        print()


def main():
    parser = argparse.ArgumentParser(
        description='Windows System Enumeration Tool - Impacket Suite Only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t targets.txt
  %(prog)s -t targets.txt --exclude 192.168.1.1 192.168.1.5
  %(prog)s -t targets.txt --exclude 192.168.1.0/28
  %(prog)s -t targets.txt -u admin -p password -d CORP.LOCAL
  %(prog)s -t targets.txt --threads 100
        """
    )

    parser.add_argument('-t', '--targets', required=True,
                       help='File containing IPs/subnets (one per line)')
    parser.add_argument('-o', '--output', default='windows_enum_results',
                       help='Output directory (default: windows_enum_results)')
    parser.add_argument('-u', '--username', default='',
                       help='Username for authenticated enumeration')
    parser.add_argument('-p', '--password', default='',
                       help='Password for authenticated enumeration')
    parser.add_argument('-d', '--domain', default='',
                       help='Domain name (optional)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads for scanning (default: 50)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Port scan timeout in seconds (default: 1.0)')
    parser.add_argument('--exclude', nargs='+', default=[],
                       help='IP addresses or subnets to exclude from scanning')

    args = parser.parse_args()

    try:
        print_banner()

        # Initialize and locate all tools
        if not initialize_tools():
            print(f"\n{Colors.RED}[!] Critical tools missing. Cannot continue.{Colors.RESET}")
            sys.exit(1)

        # Parse exclusions
        excluded_ips = set()
        if args.exclude:
            print(f"{Colors.BOLD}[*] Processing exclusions...{Colors.RESET}")
            excluded_ips = parse_exclusions(args.exclude)
            if excluded_ips:
                print(f"{Colors.YELLOW}[*] Excluding {len(excluded_ips)} IP(s) from scan{Colors.RESET}")

        # Read and expand targets
        targets = read_targets(args.targets, excluded_ips)
        print(f"{Colors.BOLD}[*] Loaded {len(targets)} target IPs{Colors.RESET}")

        if not targets:
            print(f"{Colors.RED}[!] No targets to scan after exclusions{Colors.RESET}")
            sys.exit(1)

        # Scan for Windows systems
        windows_systems = scan_for_windows_systems(targets, max_threads=args.threads)

        if not windows_systems:
            print(f"\n{Colors.RED}[!] No Windows systems found{Colors.RESET}")
            sys.exit(0)

        print(f"\n{Colors.GREEN}[+] Found {len(windows_systems)} Windows system(s){Colors.RESET}")

        # Create output directory
        os.makedirs(args.output, exist_ok=True)

        # Enumerate each Windows system
        enumerated_systems = []
        for system in windows_systems:
            try:
                system_info = enumerate_windows_system(
                    system['ip'],
                    system['ports'],
                    args.output,
                    args.username,
                    args.password,
                    args.domain
                )
                enumerated_systems.append(system_info)

                # Save results for this system
                save_results(system_info, args.output)

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Enumeration interrupted{Colors.RESET}")
                raise
            except Exception as e:
                print(f"{Colors.RED}[!] Error enumerating {system['ip']}: {e}{Colors.RESET}")
                continue

        # Print summary
        print_summary(enumerated_systems)

        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Enumeration complete! Results saved to {args.output}/{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Interrupted by user. Exiting...{Colors.RESET}")
        if 'args' in locals() and os.path.exists(args.output):
            print(f"{Colors.GREEN}[+] Partial results saved to {args.output}/{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
