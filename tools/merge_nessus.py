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

import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime


def find_nessus_files(directory):
    """Scan directory recursively for .nessus files."""
    nessus_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.nessus'):
                nessus_files.append(os.path.join(root, file))
    return sorted(nessus_files)


def parse_nessus_file(filepath):
    """Parse a .nessus file and return the ElementTree."""
    try:
        tree = ET.parse(filepath)
        return tree
    except ET.ParseError as e:
        print(f"[!] Parse error in {filepath}: {e}")
        return None
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
        return None


def merge_nessus_files(nessus_files, output_file):
    """
    Merge multiple .nessus files into a single output file.
    Uses the Policy from the first file and combines all ReportHost elements.
    """
    if not nessus_files:
        print("[!] No .nessus files found to merge")
        return False

    print(f"[*] Found {len(nessus_files)} .nessus file(s)")

    # Parse first file as the base
    base_tree = parse_nessus_file(nessus_files[0])
    if base_tree is None:
        print(f"[!] Failed to parse base file: {nessus_files[0]}")
        return False

    base_root = base_tree.getroot()
    base_report = base_root.find('Report')

    if base_report is None:
        print("[!] No Report element found in base file")
        return False

    print(f"[+] Using {nessus_files[0]} as base structure")

    # Track statistics
    total_hosts = 0
    total_items = 0
    host_count_base = len(base_report.findall('ReportHost'))

    # Count items in base file
    for report_host in base_report.findall('ReportHost'):
        total_items += len(report_host.findall('ReportItem'))

    total_hosts = host_count_base

    # Merge remaining files
    for nessus_file in nessus_files[1:]:
        print(f"[*] Merging: {nessus_file}")
        tree = parse_nessus_file(nessus_file)

        if tree is None:
            print(f"[!] Skipping {nessus_file} due to parse error")
            continue

        root = tree.getroot()
        report = root.find('Report')

        if report is None:
            print(f"[!] No Report element in {nessus_file}, skipping")
            continue

        # Add all ReportHost elements from this file
        report_hosts = report.findall('ReportHost')
        for report_host in report_hosts:
            base_report.append(report_host)
            total_hosts += 1
            total_items += len(report_host.findall('ReportItem'))

        print(f"    Added {len(report_hosts)} host(s)")

    # Update Report name to indicate merged status
    report_name = base_report.get('name', 'merged_scan')
    base_report.set('name', f"{report_name}_merged_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    # Write merged output
    try:
        # Pretty print XML with proper formatting
        ET.indent(base_tree, space="  ")
        base_tree.write(output_file, encoding='utf-8', xml_declaration=True)
        print(f"\n[+] Successfully merged {len(nessus_files)} file(s)")
        print(f"[+] Total hosts: {total_hosts}")
        print(f"[+] Total findings: {total_items}")
        print(f"[+] Output written to: {output_file}")
        return True
    except Exception as e:
        print(f"[!] Error writing output file: {e}")
        return False


def main():
    """Main execution function."""
    # Handle command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 nessus_merger.py <directory> [output_file]")
        print("  directory    : Directory to scan for .nessus files")
        print("  output_file  : Optional output filename (default: merged_scan.nessus)")
        sys.exit(1)

    scan_dir = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "merged_scan.nessus"

    # Validate directory
    if not os.path.isdir(scan_dir):
        print(f"[!] Error: {scan_dir} is not a valid directory")
        sys.exit(1)

    # Find all .nessus files
    print(f"[*] Scanning directory: {scan_dir}")
    nessus_files = find_nessus_files(scan_dir)

    if not nessus_files:
        print("[!] No .nessus files found in directory")
        sys.exit(1)

    # Display files found
    print("\n[*] Files to merge:")
    for idx, file in enumerate(nessus_files, 1):
        file_size = os.path.getsize(file) / 1024  # KB
        print(f"    {idx}. {file} ({file_size:.1f} KB)")

    # Merge files
    print("\n[*] Starting merge process...")
    success = merge_nessus_files(nessus_files, output_file)

    if success:
        output_size = os.path.getsize(output_file) / 1024  # KB
        print(f"[+] Merged file size: {output_size:.1f} KB")
        sys.exit(0)
    else:
        print("[!] Merge failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
