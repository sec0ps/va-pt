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
import os
import shutil
import subprocess
import sys
from typing import List, Dict, Optional
import multiprocessing

def find_executable(name: str) -> Optional[str]:
    """
    Try to locate an executable in PATH first,
    then fall back to a more exhaustive filesystem search.
    """
    # First, try PATH
    path = shutil.which(name)
    if path:
        return path

    # Fallback: walk some common root dirs (avoid full / walk for speed)
    search_roots = ["/usr/bin", "/usr/local/bin", "/opt"]
    for root_dir in search_roots:
        for root, _, files in os.walk(root_dir):
            if name in files:
                full_path = os.path.join(root, name)
                if os.access(full_path, os.X_OK):
                    return full_path

    return None

def find_files_in_dirs(filename: str, base_dirs: List[str]) -> List[str]:
    """
    Search for files named `filename` under the given base directories.
    Returns a list of full paths (may be empty).
    """
    results = []
    for base in base_dirs:
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base):
            if filename in files:
                results.append(os.path.join(root, filename))
    return results

def discover_wordlists() -> Dict[str, List[str]]:
    """
    Locate rockyou and weakpass wordlists using the system `locate` command.
    Fast and accurate on Ubuntu.
    """
    wordlist_names = ["rockyou.txt", "weakpass_2a", "weakpass-3a"]
    found = {}

    for wl in wordlist_names:
        try:
            result = subprocess.run(
                ["locate", "-e", wl],  # -e ensures results must exist
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            paths = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if paths:
                found[wl] = paths
        except Exception:
            pass

    return found

def prompt_wordlist_choice(found_wordlists: Dict[str, List[str]]) -> str:
    """
    Present a menu of discovered wordlists and allow user to choose,
    or specify a custom path.
    Returns the chosen wordlist path (must exist).
    """
    options: List[str] = []

    print("\n[+] Wordlist selection\n")

    # Flatten options list with labels
    for wl_name, paths in found_wordlists.items():
        for p in paths:
            options.append(p)

    # Deduplicate while preserving order
    seen = set()
    unique_options = []
    for p in options:
        if p not in seen:
            seen.add(p)
            unique_options.append(p)

    # Show menu
    idx = 1
    for p in unique_options:
        print(f"  {idx}) {p}")
        idx += 1

    print(f"  {idx}) Enter custom wordlist path")
    custom_index = idx

    # Handle case where we found nothing
    if not unique_options:
        print("[-] No known wordlists found automatically.")
        while True:
            custom_path = input("Enter full path to a wordlist file: ").strip()
            if os.path.isfile(custom_path):
                return custom_path
            print("  [!] That path does not exist or is not a file. Try again.\n")

    # Normal case: we have some options and a custom option
    while True:
        choice = input(f"\nSelect wordlist [1-{custom_index}]: ").strip()
        if not choice.isdigit():
            print("  [!] Please enter a number.")
            continue

        choice_int = int(choice)
        if 1 <= choice_int < custom_index:
            selected = unique_options[choice_int - 1]
            print(f"[+] Selected wordlist: {selected}")
            return selected
        elif choice_int == custom_index:
            while True:
                custom_path = input("Enter full path to a wordlist file: ").strip()
                if os.path.isfile(custom_path):
                    print(f"[+] Using custom wordlist: {custom_path}")
                    return custom_path
                print("  [!] That path does not exist or is not a file. Try again.\n")
        else:
            print(f"  [!] Invalid selection. Choose a number between 1 and {custom_index}.")

def detect_gpu_support(john_path: str) -> bool:
    """
    Check if this john build has OpenCL/GPU support and at least one device.

    Strategy:
      - Run: john --list=opencl-devices
      - If it exits non-zero or prints 'No OpenCL devices found' -> no GPU
      - Otherwise -> GPU support is available.
    """
    try:
        result = subprocess.run(
            [john_path, "--list=opencl-devices"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except Exception:
        return False

    if result.returncode != 0:
        return False

    out = (result.stdout or "") + "\n" + (result.stderr or "")
    if "No OpenCL devices found" in out:
        return False

    return True

def get_default_fork_count() -> int:
    """
    Choose a reasonable default fork count based on CPU cores.
    Caps at 8 to avoid going crazy on big boxes unless you tweak it.
    """
    try:
        count = multiprocessing.cpu_count()
    except NotImplementedError:
        return 2
    return max(2, min(count, 8))

def run_john(john_path: str, hashfile: str, wordlist: str, use_gpu: bool) -> int:
    """
    Invoke John the Ripper with auto-detected format and given wordlist.
    If GPU is not available, add --fork=<N> to use multiple CPU processes.
    Returns the process's return code.
    """
    cmd = [
        john_path,
        hashfile,
        f"--wordlist={wordlist}",
    ]

    if not use_gpu:
        fork_n = get_default_fork_count()
        cmd.append(f"--fork={fork_n}")
        print(f"\n[+] GPU not available – using CPU with --fork={fork_n}")
    else:
        print("\n[+] GPU/OpenCL support detected for John.")
        print("    John will use GPU-enabled formats when applicable.")

    print("\n[+] Running John the Ripper with:")
    print("    " + " ".join(cmd))
    print("\n[+] John will attempt to automatically detect the hash type.\n")

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except FileNotFoundError:
        print("[-] Error: john binary not found when executing.")
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Auto John wrapper: finds john & wordlists, then cracks hashes."
    )
    parser.add_argument(
        "-f",
        "--hashfile",
        required=True,
        help="Path to the file containing hashes to crack.",
    )
    parser.add_argument(
        "--john-path",
        help="Optional explicit path to john binary (if not in PATH).",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()

    hashfile = os.path.abspath(args.hashfile)
    if not os.path.isfile(hashfile):
        print(f"[-] Hash file not found: {hashfile}")
        sys.exit(1)

    # Locate john binary
    if args.john_path:
        john_path = os.path.abspath(args.john_path)
        if not (os.path.isfile(john_path) and os.access(john_path, os.X_OK)):
            print(f"[-] Specified john binary is not executable: {john_path}")
            sys.exit(1)
    else:
        print("[+] Searching for john binary...")
        john_path = find_executable("john")
        if not john_path:
            print("[-] Could not locate 'john' binary. Is John the Ripper installed and in PATH?")
            sys.exit(1)
        print(f"[+] Found john: {john_path}")

    # Detect GPU support
    print("\n[+] Checking for GPU/OpenCL support in john...")
    gpu_available = detect_gpu_support(john_path)
    if gpu_available:
        print("[+] OpenCL/GPU devices appear to be available.")
    else:
        print("[-] No OpenCL/GPU devices available or john was not built with OpenCL.")

    # Discover wordlists
    print("\n[+] Searching for wordlists (rockyou.txt, weakpass_2a, weakpass-3a)...")
    found_wordlists = discover_wordlists()
    if found_wordlists:
        for wl_name, paths in found_wordlists.items():
            print(f"    Found {wl_name}:")
            for p in paths:
                print(f"      - {p}")
    else:
        print("    No known wordlists found in default directories.")

    # Prompt user for which wordlist to use
    wordlist_path = prompt_wordlist_choice(found_wordlists)

    # Run john with auto hash-type detection and GPU/CPU logic
    ret = run_john(john_path, hashfile, wordlist_path, gpu_available)
    if ret == 0:
        print("\n[+] John completed successfully.")
    else:
        print(f"\n[!] John exited with return code: {ret}")
    sys.exit(ret)

if __name__ == "__main__":
    main()
