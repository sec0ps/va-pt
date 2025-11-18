#!/usr/bin/env python3
# =============================================================================
# VAPT Toolkit - Windows System Enumeration Tool
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
#          penetration testing. Targets all Windows systems (not just DCs)
#          using Scapy, Impacket, and enum4linux for anonymous enumeration.
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional

try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available - some functionality will be limited")

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, epm, srvs
    from impacket.nmb import NetBIOSTimeout, NetBIOSError
    from impacket import nmb
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print("[!] Impacket not available - some functionality will be limited")


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


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
    53: 'DNS',
    80: 'HTTP',
    443: 'HTTPS',
    1433: 'MSSQL',
    1521: 'Oracle',
    3306: 'MySQL'
}

TOOL_PATHS = {
    'enum4linux': None,
    'rpcclient': None,
    'smbclient': None,
    'nmblookup': None,
    'nmap': None
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
    print(f"\n{Colors.BOLD}[*] Locating enumeration tools...{Colors.RESET}")

    # Critical tools - at least one enum tool and SMB client
    critical_found = False

    # Locate all tools
    for tool in TOOL_PATHS.keys():
        path = find_tool_path(tool)
        TOOL_PATHS[tool] = path

        if path:
            print(f"{Colors.GREEN}[+] Found {tool}: {path}{Colors.RESET}")
            if tool in ['enum4linux', 'enum4linux-ng', 'smbclient']:
                critical_found = True
        else:
            print(f"{Colors.YELLOW}[!] {tool} not found (optional){Colors.RESET}")

    # Check Python libraries
    print(f"\n{Colors.BOLD}[*] Checking Python libraries...{Colors.RESET}")

    if SCAPY_AVAILABLE:
        print(f"{Colors.GREEN}[+] Scapy available{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] Scapy not available - install with: pip install scapy{Colors.RESET}")

    if IMPACKET_AVAILABLE:
        print(f"{Colors.GREEN}[+] Impacket available{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] Impacket not available - install with: pip install impacket{Colors.RESET}")

    if not critical_found and not IMPACKET_AVAILABLE:
        print(f"\n{Colors.RED}[!] No enumeration tools available. Install at least one of:{Colors.RESET}")
        print(f"    apt-get install samba-common-bin enum4linux")
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
    Windows System Enumeration Tool
    Comprehensive Anonymous Enumeration for All Windows Systems
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


def check_port_scapy(ip: str, port: int, timeout: int = 2) -> bool:
    """Check if TCP port is open using Scapy SYN scan"""
    if not SCAPY_AVAILABLE:
        return check_port_socket(ip, port, timeout)

    try:
        # Suppress Scapy verbosity
        conf.verb = 0

        # Send SYN packet
        pkt = IP(dst=ip)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            return False

        # Check for SYN-ACK (port open)
        if resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                # Send RST to close connection
                rst = IP(dst=ip)/TCP(dport=port, flags='R')
                sr1(rst, timeout=1, verbose=0)
                return True

        return False
    except Exception as e:
        # Fallback to socket method
        return check_port_socket(ip, port, timeout)


def scan_windows_ports(ip: str, timeout: float = 1) -> Dict[int, str]:
    """
    Scan common Windows ports on target
    Returns dict of open ports with their services
    """
    open_ports = {}

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
                    print(f"\r{Colors.BLUE}[*] Progress: [{bar}] {completed}/{total} ({percent:.1f}%) - {len(windows_systems)} system(s) found{Colors.RESET}", end='', flush=True)

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

    print(f"\r{' ' * 100}\r", end='')
    return windows_systems


def get_netbios_info(ip: str) -> Dict:
    """Get NetBIOS information using Impacket or nmblookup"""
    netbios_info = {}

    if IMPACKET_AVAILABLE:
        try:
            # Use Impacket's NetBIOS functionality
            nb = nmb.NetBIOS()

            # Query NetBIOS name
            try:
                names = nb.getnetbiosname(ip, timeout=3)
                if names:
                    netbios_info['netbios_name'] = names
            except:
                pass

            # Get node status
            try:
                nb_names = nb.getnodestatus(ip, timeout=3)
                if nb_names:
                    for name in nb_names:
                        name_str = name[0].strip()
                        name_type = name[1]

                        # Parse different name types
                        if name_type == 0x00:
                            netbios_info['computer_name'] = name_str
                        elif name_type == 0x20:
                            netbios_info['server_service'] = name_str
                        elif name_type == 0x03:
                            netbios_info['messenger_service'] = name_str
                        elif name_type == 0x1D:
                            netbios_info['master_browser'] = name_str
                        elif name_type == 0x1E:
                            netbios_info['browser_election'] = name_str
            except:
                pass

        except Exception as e:
            pass

    # Fallback to nmblookup if Impacket fails
    if not netbios_info and TOOL_PATHS['nmblookup']:
        try:
            cmd = get_tool_command('nmblookup', ['-A', ip])
            if cmd:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '<00>' in line and 'GROUP' not in line:
                            parts = line.split()
                            if parts:
                                netbios_info['computer_name'] = parts[0].strip()
                                break
        except:
            pass

    return netbios_info


def get_smb_info(ip: str, username: str = '', password: str = '') -> Dict:
    """Get SMB information using Impacket"""
    smb_info = {}

    if not IMPACKET_AVAILABLE:
        return smb_info

    try:
        # Attempt anonymous connection first
        conn = SMBConnection(ip, ip, timeout=10)

        # Try anonymous login
        try:
            conn.login('', '')
            smb_info['anonymous_login'] = True
        except:
            smb_info['anonymous_login'] = False

            # Try with credentials if provided
            if username or password:
                try:
                    conn.login(username, password)
                    smb_info['authenticated'] = True
                except:
                    smb_info['authenticated'] = False
                    return smb_info

        # Get server information
        try:
            smb_info['server_name'] = conn.getServerName()
            smb_info['server_domain'] = conn.getServerDomain()
            smb_info['server_os'] = conn.getServerOS()
            smb_info['server_os_major'] = conn.getServerOSMajor()
            smb_info['server_os_minor'] = conn.getServerOSMinor()
            smb_info['server_os_build'] = conn.getServerOSBuild()

            # Check SMB signing
            smb_info['smb_signing'] = conn.isSigningRequired()

            # Get SMB dialect
            smb_info['smb_dialect'] = conn.getDialect()

        except Exception as e:
            pass

        # List shares
        try:
            shares = conn.listShares()
            smb_info['shares'] = []
            for share in shares:
                share_name = share['shi1_netname'][:-1]  # Remove null terminator
                share_type = share['shi1_type']
                smb_info['shares'].append({
                    'name': share_name,
                    'type': share_type
                })
        except Exception as e:
            pass

        conn.close()

    except Exception as e:
        smb_info['error'] = str(e)

    return smb_info


def enum_rpc_services(ip: str) -> Dict:
    """Enumerate RPC services using Impacket"""
    rpc_info = {}

    if not IMPACKET_AVAILABLE:
        return rpc_info

    try:
        # Connect to endpoint mapper
        string_binding = f'ncacn_ip_tcp:{ip}[135]'
        trans = transport.DCERPCTransportFactory(string_binding)
        trans.set_connect_timeout(10)

        dce = trans.get_dce_rpc()
        dce.connect()

        # Query endpoint mapper
        dce.bind(epm.MSRPC_UUID_PORTMAP)

        # Get endpoint map
        resp = epm.hept_lookup(dce)

        endpoints = []
        for entry in resp:
            binding = entry['tower']['Floors']
            if len(binding) >= 3:
                uuid = str(binding[0])
                proto = str(binding[2])
                endpoints.append({
                    'uuid': uuid,
                    'protocol': proto
                })

        rpc_info['endpoints'] = endpoints
        rpc_info['endpoint_count'] = len(endpoints)

        dce.disconnect()

    except Exception as e:
        rpc_info['error'] = str(e)

    return rpc_info


def run_enum4linux(ip: str, output_dir: str) -> Dict:
    """Run enum4linux for comprehensive enumeration"""
    enum_results = {}

    if not TOOL_PATHS[tool]:
        return {'error': 'enum4linux not available'}

    print(f"{Colors.BOLD}[*] Running {tool} on {ip}...{Colors.RESET}")

    try:
        output_file = os.path.join(output_dir, f'enum4linux_{ip}.txt')

        if tool == 'enum4linux-ng':
            cmd = get_tool_command(tool, ['-A', ip, '-oJ', output_file.replace('.txt', '.json')])
        else:
            cmd = get_tool_command(tool, ['-a', ip])

        if not cmd:
            return {'error': f'{tool} command failed'}

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        # Save output
        with open(output_file, 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n\n=== STDERR ===\n")
                f.write(result.stderr)

        # Parse key information from output
        output = result.stdout

        # Extract users
        if 'user:' in output.lower():
            users = []
            for line in output.split('\n'):
                if 'user:[' in line.lower():
                    try:
                        user = line.split('[')[1].split(']')[0]
                        users.append(user)
                    except:
                        pass
            if users:
                enum_results['users'] = users

        # Extract groups
        if 'group:' in output.lower():
            groups = []
            for line in output.split('\n'):
                if 'group:[' in line.lower():
                    try:
                        group = line.split('[')[1].split(']')[0]
                        groups.append(group)
                    except:
                        pass
            if groups:
                enum_results['groups'] = groups

        # Extract shares
        if 'sharename' in output.lower() or 'shares' in output.lower():
            shares = []
            in_shares_section = False
            for line in output.split('\n'):
                if 'sharename' in line.lower():
                    in_shares_section = True
                    continue
                if in_shares_section and line.strip():
                    parts = line.split()
                    if len(parts) >= 1 and not line.startswith('='):
                        shares.append(parts[0])
            if shares:
                enum_results['shares'] = shares

        # Extract OS information
        for line in output.split('\n'):
            if 'OS:' in line or 'operating system' in line.lower():
                enum_results['os_info'] = line.strip()
                break

        enum_results['output_file'] = output_file
        print(f"{Colors.GREEN}[+] enum4linux completed - results saved to {output_file}{Colors.RESET}")

        if result.returncode != 0 and result.stderr:
            enum_results['warnings'] = result.stderr

    except subprocess.TimeoutExpired:
        enum_results['error'] = 'enum4linux timed out'
        print(f"{Colors.YELLOW}[!] enum4linux timed out on {ip}{Colors.RESET}")
    except Exception as e:
        enum_results['error'] = str(e)
        print(f"{Colors.YELLOW}[!] enum4linux failed: {e}{Colors.RESET}")

    return enum_results


def enumerate_windows_system(ip: str, ports: Dict, output_dir: str, username: str = '', password: str = '') -> Dict:
    """
    Comprehensive enumeration of a Windows system
    """
    print(f"\n{Colors.BOLD}{'='*70}")
    print(f"[*] Enumerating Windows System: {ip}")
    print(f"{'='*70}{Colors.RESET}")

    system_info = {
        'ip': ip,
        'ports': ports,
        'timestamp': datetime.now().isoformat()
    }

    # Get NetBIOS information
    print(f"{Colors.BOLD}[*] Gathering NetBIOS information...{Colors.RESET}")
    netbios_info = get_netbios_info(ip)
    if netbios_info:
        system_info['netbios'] = netbios_info
        if 'computer_name' in netbios_info:
            print(f"{Colors.GREEN}[+] Computer Name: {netbios_info['computer_name']}{Colors.RESET}")

    # Get SMB information
    if 445 in ports or 139 in ports:
        print(f"{Colors.BOLD}[*] Gathering SMB information...{Colors.RESET}")
        smb_info = get_smb_info(ip, username, password)
        if smb_info:
            system_info['smb'] = smb_info
            if 'server_os' in smb_info:
                print(f"{Colors.GREEN}[+] OS: {smb_info['server_os']}{Colors.RESET}")
            if 'server_domain' in smb_info:
                print(f"{Colors.GREEN}[+] Domain: {smb_info['server_domain']}{Colors.RESET}")
            if 'anonymous_login' in smb_info:
                status = "Allowed" if smb_info['anonymous_login'] else "Not Allowed"
                color = Colors.GREEN if smb_info['anonymous_login'] else Colors.YELLOW
                print(f"{color}[+] Anonymous Login: {status}{Colors.RESET}")
            if 'shares' in smb_info and smb_info['shares']:
                print(f"{Colors.GREEN}[+] Found {len(smb_info['shares'])} shares{Colors.RESET}")

    # Enumerate RPC if available
    if 135 in ports:
        print(f"{Colors.BOLD}[*] Enumerating RPC services...{Colors.RESET}")
        rpc_info = enum_rpc_services(ip)
        if rpc_info and 'endpoint_count' in rpc_info:
            system_info['rpc'] = rpc_info
            print(f"{Colors.GREEN}[+] Found {rpc_info['endpoint_count']} RPC endpoints{Colors.RESET}")

    # Run enum4linux for comprehensive enumeration
    enum4linux_results = run_enum4linux(ip, output_dir)
    if enum4linux_results:
        system_info['enum4linux'] = enum4linux_results
        if 'users' in enum4linux_results:
            print(f"{Colors.GREEN}[+] Found {len(enum4linux_results['users'])} users{Colors.RESET}")
        if 'groups' in enum4linux_results:
            print(f"{Colors.GREEN}[+] Found {len(enum4linux_results['groups'])} groups{Colors.RESET}")

    return system_info


def save_results(system_info: Dict, output_dir: str):
    """Save enumeration results to files"""
    try:
        os.makedirs(output_dir, exist_ok=True)

        ip = system_info['ip']
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save users if found
        if 'enum4linux' in system_info and 'users' in system_info['enum4linux']:
            user_file = os.path.join(output_dir, f'users_{ip}.txt')
            with open(user_file, 'w') as f:
                for user in system_info['enum4linux']['users']:
                    f.write(f"{user}\n")
            print(f"{Colors.GREEN}[+] Users saved to {user_file}{Colors.RESET}")

        # Save shares if found
        shares = []
        if 'smb' in system_info and 'shares' in system_info['smb']:
            shares.extend([s['name'] for s in system_info['smb']['shares']])
        if 'enum4linux' in system_info and 'shares' in system_info['enum4linux']:
            shares.extend(system_info['enum4linux']['shares'])

        if shares:
            share_file = os.path.join(output_dir, f'shares_{ip}.txt')
            with open(share_file, 'w') as f:
                for share in set(shares):  # Remove duplicates
                    f.write(f"{share}\n")
            print(f"{Colors.GREEN}[+] Shares saved to {share_file}{Colors.RESET}")

        # Save JSON summary
        json_file = os.path.join(output_dir, f'windows_enum_{ip}_{timestamp}.json')
        with open(json_file, 'w') as f:
            json.dump(system_info, f, indent=2, default=str)
        print(f"{Colors.GREEN}[+] Full results saved to {json_file}{Colors.RESET}")

    except Exception as e:
        print(f"{Colors.RED}[!] Error saving results: {e}{Colors.RESET}")


def print_summary(systems: List[Dict]):
    """Print enumeration summary"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}")
    print("=== ENUMERATION SUMMARY ===")
    print(f"{'='*70}{Colors.RESET}\n")

    for system in systems:
        print(f"{Colors.BOLD}System: {system['ip']}{Colors.RESET}")

        # NetBIOS info
        if 'netbios' in system and 'computer_name' in system['netbios']:
            print(f"  Computer Name: {system['netbios']['computer_name']}")

        # SMB info
        if 'smb' in system:
            if 'server_os' in system['smb']:
                print(f"  OS: {system['smb']['server_os']}")
            if 'server_domain' in system['smb']:
                print(f"  Domain: {system['smb']['server_domain']}")
            if 'anonymous_login' in system['smb']:
                print(f"  Anonymous Login: {'Yes' if system['smb']['anonymous_login'] else 'No'}")

        # Enumeration results
        if 'enum4linux' in system:
            if 'users' in system['enum4linux']:
                print(f"  Users Found: {len(system['enum4linux']['users'])}")
            if 'groups' in system['enum4linux']:
                print(f"  Groups Found: {len(system['enum4linux']['groups'])}")
            if 'shares' in system['enum4linux']:
                print(f"  Shares Found: {len(system['enum4linux']['shares'])}")

        # Open ports
        if 'ports' in system:
            ports_str = ', '.join([f"{p}({s})" for p, s in system['ports'].items()])
            print(f"  Open Ports: {ports_str}")

        print()


def main():
    parser = argparse.ArgumentParser(
        description='Windows System Enumeration Tool for Authorized Penetration Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t targets.txt
  %(prog)s -t targets.txt --exclude 192.168.1.1 192.168.1.5
  %(prog)s -t targets.txt --exclude 192.168.1.0/28
  %(prog)s -t targets.txt -u admin -p password
  %(prog)s -t targets.txt --threads 100 --timeout 0.5
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
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads for scanning (default: 50)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Port scan timeout in seconds (default: 1.0)')
    parser.add_argument('--exclude', nargs='+', default=[],
                       help='IP addresses or subnets to exclude from scanning')
    parser.add_argument('--skip-enum4linux', action='store_true',
                       help='Skip enum4linux enumeration')

    args = parser.parse_args()

    try:
        print_banner()

        # Initialize and locate all tools
        if not initialize_tools():
            print(f"\n{Colors.YELLOW}[!] Some tools are missing but continuing with available functionality{Colors.RESET}")

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
                    args.password
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
        sys.exit(1)


if __name__ == '__main__':
    main()
