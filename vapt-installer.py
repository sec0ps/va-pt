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
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
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
import subprocess
import sys
import re
import glob
import json
import datetime

LOG_PATH = "/vapt/install_failures.log"
MANIFEST_PATH = "/vapt/.install_manifest.json"

FAILED_PACKAGES = []

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        with open(LOG_PATH, 'a') as f:
            f.write(f"\n{'=' * 70}\n")
            f.write(f"{datetime.datetime.now().isoformat()}\n")
            f.write(f"COMMAND: {command}\n")
            f.write(f"EXIT CODE: {result.returncode}\n")
            if result.stdout.strip():
                f.write(f"--- STDOUT ---\n{result.stdout}\n")
            if result.stderr.strip():
                f.write(f"--- STDERR ---\n{result.stderr}\n")
        return False
    return True

def pip_flags():
    marked = (glob.glob("/usr/lib/python3.*/EXTERNALLY-MANAGED")
              or glob.glob("/usr/lib/python3/EXTERNALLY-MANAGED"))
    if marked:
        help_out = subprocess.run("pip3 install --help", shell=True,
                                  capture_output=True, text=True).stdout
        if "--break-system-packages" in help_out:
            return " --break-system-packages"
    return ""

# Computed once at import and refreshed after apt installs pip in the base step.
PIP = "pip3 install" + pip_flags()

def install_one(kind, install_cmd, name):
    print(f"  [{kind}] {name} ...", end=" ", flush=True)
    if run_command(install_cmd):
        print("ok")
        return True
    print("FAILED")
    FAILED_PACKAGES.append(f"{kind}: {name}")
    return False

def apt_install(packages):
    for pkg in packages:
        install_one("apt", f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}", pkg)

def pip_install(packages):
    """Install pip packages one at a time, continuing past any failure."""
    for pkg in packages:
        install_one("pip", f"{PIP} {pkg}", pkg)

def print_failure_summary():
    """Print a consolidated list of everything that failed to install."""
    if FAILED_PACKAGES:
        print("\n" + "=" * 60)
        print(f"{len(FAILED_PACKAGES)} item(s) failed to install:")
        for item in FAILED_PACKAGES:
            print(f"  - {item}")
        print(f"Full errors: {LOG_PATH}")
        print("=" * 60)
    else:
        print("\nAll attempted packages installed successfully.")

# ---------------------------------------------------------------------------
# Install manifest: persistent record of which tool categories are installed on
# THIS host, so `update_toolsets()` only touches what was actually installed. A
# WSL host that skipped the wireless category must not try to git-pull or rebuild
# wireless tools that were never cloned. Shape: {"categories": [<slug>, ...],
# "updated": "<iso8601>"}. Writes union into the existing set so re-running the
# installer with a different subset adds categories rather than replacing them.
# ---------------------------------------------------------------------------

def read_manifest():
    """Return the set of installed category slugs, or None if no manifest exists.
    None is meaningful: it marks a pre-manifest install, which update_toolsets()
    treats as 'update everything' for backward compatibility."""
    if not os.path.exists(MANIFEST_PATH):
        return None
    try:
        with open(MANIFEST_PATH) as f:
            data = json.load(f)
        return set(data.get("categories", []))
    except (json.JSONDecodeError, OSError) as e:
        print(f"  WARNING: manifest at {MANIFEST_PATH} is unreadable ({e}); "
              "treating host as un-tracked (update will cover all categories).")
        return None

def write_manifest(categories):
    """Union `categories` into the manifest and persist it. Never shrinks the
    tracked set on its own - a category is only removed by an explicit rebuild."""
    existing = read_manifest() or set()
    merged = sorted(existing | set(categories))
    data = {"categories": merged, "updated": datetime.datetime.now().isoformat()}
    try:
        with open(MANIFEST_PATH, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Install manifest updated: {', '.join(merged)}")
    except OSError as e:
        print(f"  WARNING: could not write manifest to {MANIFEST_PATH} ({e}). "
              "Update runs will fall back to covering all categories.")

def git_pull_changed(path):
    result = subprocess.run(f"cd {path} && git pull", shell=True,
                            capture_output=True, text=True)
    if result.returncode != 0:
        with open(LOG_PATH, 'a') as f:
            f.write(f"\n{'=' * 70}\n")
            f.write(f"{datetime.datetime.now().isoformat()}\n")
            f.write(f"COMMAND: cd {path} && git pull\n")
            f.write(f"EXIT CODE: {result.returncode}\n")
            if result.stdout.strip():
                f.write(f"--- STDOUT ---\n{result.stdout}\n")
            if result.stderr.strip():
                f.write(f"--- STDERR ---\n{result.stderr}\n")
        return False
    low = result.stdout.lower()
    # git wording varies by version: "Already up to date." / "up-to-date."
    return "already up to date" not in low and "already up-to-date" not in low

def filter_uninstalled_apt(packages):
    """Return only the apt packages not already installed (status 'installed')."""
    result = subprocess.run(
        "dpkg-query -W -f='${Package} ${Status}\n'",
        shell=True, capture_output=True, text=True
    )
    installed = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3] == "installed":
            installed.add(parts[0])
    return [pkg for pkg in packages if pkg not in installed]

def filter_uninstalled_pip(packages):
    """Return only the pip packages not already installed (PEP 503 normalized)."""
    import importlib.metadata
    installed = {
        re.sub(r"[-_.]+", "-", dist.metadata["Name"]).lower()
        for dist in importlib.metadata.distributions()
        if dist.metadata["Name"]
    }
    return [pkg for pkg in packages
            if re.sub(r"[-_.]+", "-", pkg).lower() not in installed]

def filter_uninstalled_cpan(modules):
    """Return only the Perl modules that don't already load."""
    missing = []
    for module in modules:
        result = subprocess.run(
            f"perl -M{module} -e 1",
            shell=True, capture_output=True, text=True
        )
        if result.returncode != 0:
            missing.append(module)
    return missing

def display_logo():
    RED = "\033[91m"
    RESET = "\033[0m"
    SPLIT_COL = 49  # column dividing "RED" (left, red) from "CELL" (right, default fg) in the wordmark

    logo_ascii = """
                                 #                              #
                               ###              #*#              ##
                              ##**            #***##             *##
                              ###*         ##*#*** #*##         #*###
                             ######     ### ##**** ####*##     ### *#
                             ##*####   * #####**** #########  ########
                             ####### # # #####**** ########### ###*###
                             **### ##### #####**** ############### ##
                             ######*#*########**** #########*#*####*#
                              ###*###**#######**** ########*** ####*#
                               ######**#######**** ######*#*#*###*##
                                #####*#* *####**** #########**#####
                                ###*#####**###**** #####*#########
                                  ####*#*#**##**** # ###########*
                                   ##*##***##*#*** ####*##*###*
                                      ###*####**####*##*#####
                                         #***###**####**#
                                            ## #### ##
                                               #*##
                                                #*
                                                #*#
        #########     ###########  #########          ###### *****##### #****#    ******
          ###   ####    ###    ###   ###    ###    #*#    ##  #**#   #*   **#      ***
          ###    ###    ###     ##   ###     ###  ##*      #  *#**    #   **#      #**
          ###    ###    ###  ##      ###     #### **#         **** ##     ***      #**
          #########     #######      ###     #### **#         #**####     **#      ***
          ###    ####   ###   #   #  ###     #### **#       # #*** ##  #  **#   #  #**    #
          ###    ####   ###      ##  ###     ###   #*      ## #***    ##  **#   *  #**    #
          ###     ### # ###   #####  ###   ###      ##    #*# #**#  #*#* #**###**  #*# *#*#



                      Vulnerability Assessment and Penetration Testing Toolkit
    """

    for line in logo_ascii.split("\n"):
        if not line.strip():
            print(line)
        elif "Vulnerability" in line:
            # subtitle: default foreground, readable on any background
            print(line)
        elif (len(line) - len(line.lstrip())) < 15:
            # wordmark line: RED red, CELL in default foreground
            print(f"{RED}{line[:SPLIT_COL]}{RESET}{line[SPLIT_COL:]}{RESET}")
        else:
            # emblem (winged shield)
            print(f"{RED}{line}{RESET}")

def check_directory_structure():
    base_path = "/vapt"
    directories = [
        base_path, f"{base_path}/temp", f"{base_path}/wireless", f"{base_path}/exploits",
        f"{base_path}/web", f"{base_path}/intel", f"{base_path}/scanners", f"{base_path}/misc",
        f"{base_path}/passwords", f"{base_path}/fuzzers", f"{base_path}/audit",
        f"{base_path}/mobile", f"{base_path}/cloud", f"{base_path}/network",
        f"{base_path}/ad_windows"
    ]

    # Create the base directory if it does not exist
    if not os.path.exists(base_path):
        print("Creating base directory at /vapt")
        run_command(f"sudo mkdir {base_path}")
        run_command(f"sudo chown -R $USER {base_path} && sudo chgrp -R $USER {base_path}")

    # Check and create subdirectories if they don't exist
    for directory in directories:
        if not os.path.exists(directory):
            print(f"Creating directory: {directory}")
            run_command(f"mkdir -p {directory}")

    # Clone va-pt repository if not already cloned
    va_pt_path = f"{base_path}/misc/va-pt"
    if not os.path.exists(va_pt_path):
        print("Cloning va-pt repository...")
        run_command(f"cd {base_path}/misc && git clone https://github.com/sec0ps/va-pt.git")

    print("Directory structure is ready.")

def cleanup_old_directories():
    """Automatically remove old directories from previous installations"""
    old_powershell_dir = "/vapt/powershell"
    old_findshares_dir = "/vapt/scanners/FindUncommonShares"
    old_grecon_dir = "/vapt/intel/GRecon"
    old_arachni_dir = "/vapt/web/arachni"

    if os.path.exists(old_powershell_dir):
        print("Cleaning up old powershell directory...")
        # Automatically move any existing tools to the new location
        if os.path.exists(f"{old_powershell_dir}/PowerSploit"):
            run_command(f"mv {old_powershell_dir}/PowerSploit /vapt/ad_windows/")
        if os.path.exists(f"{old_powershell_dir}/ps1encode"):
            run_command(f"mv {old_powershell_dir}/ps1encode /vapt/ad_windows/")
        if os.path.exists(f"{old_powershell_dir}/Invoke-TheHash"):
            run_command(f"mv {old_powershell_dir}/Invoke-TheHash /vapt/ad_windows/")
        if os.path.exists(f"{old_powershell_dir}/PowerShdll"):
            run_command(f"mv {old_powershell_dir}/PowerShdll /vapt/ad_windows/")

        run_command(f"rm -rf {old_powershell_dir}")
        print("Old powershell directory cleaned up successfully.")

    if os.path.exists(old_findshares_dir):
        print("Cleaning up old FindUncommonShares directory...")
        run_command(f"rm -rf {old_findshares_dir}")
        print("Old FindUncommonShares directory removed. Will be reinstalled as pyFindUncommonShares.")

    if os.path.exists(old_grecon_dir):
        print("Cleaning up old GRecon directory...")
        run_command(f"rm -rf {old_grecon_dir}")
        print("Old GRecon directory removed.")

    if os.path.exists(old_arachni_dir):
        print("Cleaning up deprecated Arachni directory...")
        run_command(f"rm -rf {old_arachni_dir}")
        print("Old Arachni directory removed.")

    old_responder_dir = "/vapt/exploits/Responder"
    if os.path.exists(old_responder_dir):
        print("Cleaning up old Responder directory...")
        run_command(f"rm -rf {old_responder_dir}")
        print("Old Responder directory removed. Replaced by Responder-NG.")

def check_and_install(repo_url, install_dir, setup_commands=None):
    if os.path.exists(install_dir):
        print(f"{os.path.basename(install_dir)} already installed, skipping.")
        return

    print(f"Installing {os.path.basename(install_dir)}")
    if not run_command(f"git clone {repo_url} {install_dir}"):
        print(f"  WARNING: clone failed for {install_dir} (see {LOG_PATH})")
        return

    if setup_commands:
        for command in setup_commands:
            run_command(f"cd {install_dir} && {command}")

def fix_searchsploit_rc():
    """Repoint the exploitdb .searchsploit_rc at the real clone path and drop the Papers block. Idempotent."""
    rc_path = "/vapt/exploits/exploitdb/.searchsploit_rc"
    if not os.path.exists(rc_path):
        return

    with open(rc_path) as f:
        lines = f.readlines()

    corrected = []
    skipping_papers = False
    changed = False
    for line in lines:
        if line.strip() == "##-- Papers":
            skipping_papers = True
            changed = True
            continue
        if skipping_papers:
            if line.strip() == 'package_array+=("exploitdb-papers")':
                skipping_papers = False
            continue
        if line.rstrip("\n") == 'path_array+=("/opt/exploitdb")':
            corrected.append('path_array+=("/vapt/exploits/exploitdb")\n')
            changed = True
            continue
        corrected.append(line)

    if changed:
        with open(rc_path, "w") as f:
            f.writelines(corrected)
        print("Corrected searchsploit rc paths.")
    else:
        print("searchsploit rc already correct, skipping.")

def install_go():
    go_bin = "/usr/local/go/bin/go"
    min_major, min_minor = 1, 24

    if os.path.exists(go_bin):
        out = subprocess.run(f"{go_bin} version", shell=True,
                             capture_output=True, text=True).stdout
        m = re.search(r"go(\d+)\.(\d+)", out)
        if m and (int(m.group(1)), int(m.group(2))) >= (min_major, min_minor):
            print(f"Go already installed: {out.strip()}")
            return

    # Ask go.dev for the current stable, fall back to a known-good pin
    ver_out = subprocess.run("curl -sL https://go.dev/VERSION?m=text",
                             shell=True, capture_output=True, text=True).stdout.split()
    version = ver_out[0] if ver_out and ver_out[0].startswith("go") else "go1.26.5"
    tarball = f"{version}.linux-amd64.tar.gz"

    print(f"Installing Go toolchain {version} to /usr/local/go...")
    run_command(f"curl -sL -o /tmp/{tarball} https://go.dev/dl/{tarball}")
    run_command("sudo rm -rf /usr/local/go")
    run_command(f"sudo tar -C /usr/local -xzf /tmp/{tarball}")
    run_command(f"rm -f /tmp/{tarball}")

    check = subprocess.run(f"{go_bin} version", shell=True,
                           capture_output=True, text=True)
    if check.returncode == 0:
        print(f"Go installed: {check.stdout.strip()}")
    else:
        print(f"  WARNING: Go did not verify after install (see {LOG_PATH}). "
              "Go-based tool builds will fail until this is resolved.")
        FAILED_PACKAGES.append("go: toolchain")

def install_wordlist_files():
    """Install the Weakpass dictionary for password cracking."""
    weakpass_file = "/vapt/passwords/weakpass_3a"
    if not os.path.exists(weakpass_file):
        user_confirmation = input("The Weakpass dictionary file is 30GB in size. Do you want to continue with the installation? (yes/no): ").strip().lower()
        if user_confirmation == 'yes':
            print("Downloading the Weakpass dictionary...")
            run_command("cd /vapt/passwords && wget https://download.weakpass.com/wordlists/1948/weakpass_3a.7z")
            run_command("cd /vapt/passwords && 7z e weakpass_3a.7z")
            print("Weakpass dictionary installation complete.")
        else:
            print("Installation of Weakpass dictionary aborted. Returning to main menu.")
            return
    else:
        print("Weakpass dictionary already installed, skipping.")

def install_ruby():
    print("Checking Ruby version...")

    ruby_check = subprocess.run("ruby -v", shell=True, capture_output=True, text=True)
    if ruby_check.returncode == 0 and "3.3.9" in ruby_check.stdout:
        print("Ruby 3.3.9 already installed and active, skipping.")
        return

    rbenv_root = os.path.expanduser("~/.rbenv")
    rbenv_bin = f"{rbenv_root}/bin/rbenv"
    ruby_build_dir = f"{rbenv_root}/plugins/ruby-build"

    # rbenv itself
    if not os.path.exists(rbenv_bin):
        print("Installing rbenv...")
        run_command(f"git clone https://github.com/rbenv/rbenv.git {rbenv_root}")
        for line in ['export PATH="$HOME/.rbenv/bin:$PATH"', 'eval "$(rbenv init - bash)"']:
            run_command(f"grep -qxF '{line}' ~/.bashrc || echo '{line}' >> ~/.bashrc")

    # ruby-build plugin: clone if missing, always update definitions
    if not os.path.exists(ruby_build_dir):
        print("Installing ruby-build plugin...")
        run_command(f"git clone https://github.com/rbenv/ruby-build.git {ruby_build_dir}")
    else:
        print("Updating ruby-build definitions...")
        run_command(f"cd {ruby_build_dir} && git pull")

    # Make rbenv and its shims usable for the rest of THIS process
    os.environ["RBENV_ROOT"] = rbenv_root
    os.environ["PATH"] = f"{rbenv_root}/bin:{rbenv_root}/shims:{os.environ.get('PATH', '')}"

    # Confirm the definition exists before a multi-minute compile
    if not os.path.exists(f"{ruby_build_dir}/share/ruby-build/3.3.9"):
        print("  ERROR: ruby-build has no 3.3.9 definition even after update. "
              f"Confirm the ruby-build git pull succeeded (see {LOG_PATH}).")

    print("Installing Ruby 3.3.9 (compiles from source, several minutes)...")
    if not run_command(f"{rbenv_bin} install -s 3.3.9"):
        print("  ERROR: rbenv install 3.3.9 failed. Usual causes: stale "
              f"ruby-build definitions or a missing compile header (see {LOG_PATH}).")
        FAILED_PACKAGES.append("ruby: 3.3.9 (rbenv install failed)")
        return

    run_command(f"{rbenv_bin} global 3.3.9")
    run_command(f"{rbenv_bin} rehash")

    verify = subprocess.run(f"{rbenv_root}/shims/ruby -v",
                            shell=True, capture_output=True, text=True)
    if "3.3.9" in verify.stdout:
        print("Ruby 3.3.9 installed and active.")
    else:
        print(f"  WARNING: install ran but active ruby is: {verify.stdout.strip()} "
              "(shims or PATH issue). Run: source ~/.bashrc")
        FAILED_PACKAGES.append("ruby: 3.3.9 (verify failed)")


def install_firefox_headless():
    """Install a real .deb Firefox from Mozilla's APT repo (not the Ubuntu snap
    shim, which cannot be driven headless by ZAP's Selenium) plus a matching
    geckodriver on PATH. ZAP's AJAX spider needs both."""
    print("Installing headless Firefox (.deb) and geckodriver")

    real = subprocess.run(
        "readlink -f \"$(command -v firefox)\" 2>/dev/null", shell=True,
        capture_output=True, text=True).stdout.strip()
    have_deb = bool(real) and "/snap" not in real and os.path.exists(
        "/etc/apt/sources.list.d/mozilla.list")

    if not have_deb:
        run_command("sudo snap remove firefox")          # no-op if not a snap
        run_command("sudo apt-get purge -y firefox")     # transitional package
        run_command("sudo install -d -m 0755 /etc/apt/keyrings")
        run_command(
            "wget -qO- https://packages.mozilla.org/apt/repo-signing-key.gpg "
            "| sudo tee /etc/apt/keyrings/packages.mozilla.org.asc >/dev/null")
        run_command(
            "echo 'deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] "
            "https://packages.mozilla.org/apt mozilla main' "
            "| sudo tee /etc/apt/sources.list.d/mozilla.list")
        run_command(
            "printf 'Package: *\\nPin: origin packages.mozilla.org\\n"
            "Pin-Priority: 1000\\n' | sudo tee /etc/apt/preferences.d/mozilla")
        run_command("sudo DEBIAN_FRONTEND=noninteractive apt-get update")
        run_command(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y firefox")
    else:
        print("Real .deb Firefox already present, skipping repo setup.")

    if subprocess.run("command -v geckodriver", shell=True,
                      capture_output=True).returncode != 0:
        print("Installing geckodriver")
        run_command(
            "cd /tmp && GV=$(curl -s "
            "https://api.github.com/repos/mozilla/geckodriver/releases/latest "
            "| grep -oP '\"tag_name\": \"\\K[^\"]+') && "
            "curl -sL -o geckodriver.tar.gz "
            "\"https://github.com/mozilla/geckodriver/releases/download/"
            "$GV/geckodriver-$GV-linux64.tar.gz\" && "
            "tar -xzf geckodriver.tar.gz && "
            "sudo install -m 0755 geckodriver /usr/local/bin/geckodriver && "
            "rm -f geckodriver geckodriver.tar.gz")
    else:
        print("geckodriver already present, skipping.")

    ff = subprocess.run("firefox --version 2>/dev/null", shell=True,
                        capture_output=True, text=True).stdout.strip()
    gd = subprocess.run("geckodriver --version 2>/dev/null", shell=True,
                        capture_output=True, text=True).stdout.splitlines()
    print(f"  firefox:     {ff or 'NOT FOUND'}")
    print(f"  geckodriver: {gd[0] if gd else 'NOT FOUND'}")


def detect_ubuntu_codename():
    """Resolve the running Ubuntu release codename (e.g. 'jammy', 'noble') for
    selecting the matching third-party repo. Tries, in order: VERSION_CODENAME
    from /etc/os-release, `lsb_release -cs`, then a VERSION_ID fallback map for
    minimal images carrying neither. Returns '' if it cannot be determined."""
    # 1. /etc/os-release - present on all modern Ubuntu, including minimal/container
    codename = subprocess.run(
        ". /etc/os-release 2>/dev/null && echo $VERSION_CODENAME", shell=True,
        capture_output=True, text=True).stdout.strip()
    if codename:
        return codename

    # 2. lsb_release - not always installed on stripped images
    codename = subprocess.run(
        "lsb_release -cs 2>/dev/null", shell=True,
        capture_output=True, text=True).stdout.strip()
    if codename:
        return codename

    # 3. Last resort: map VERSION_ID -> codename
    version_id = subprocess.run(
        ". /etc/os-release 2>/dev/null && echo $VERSION_ID", shell=True,
        capture_output=True, text=True).stdout.strip()
    return {"20.04": "focal", "22.04": "jammy", "24.04": "noble"}.get(version_id, "")


# Minimum Python for the newest pipx tools (NetExec requires >=3.11). On 22.04 the
# system python3 is 3.10, so these tools need a co-installed newer interpreter - NOT
# a change to the system default, which would break apt/netplan/ufw built against 3.10.
MIN_PIPX_PY = (3, 11)

def _py_version(binary):
    """Return (major, minor) for a python binary, or None if it won't run."""
    out = subprocess.run(
        f"{binary} -c 'import sys; print(f\"{{sys.version_info.major}}.{{sys.version_info.minor}}\")'",
        shell=True, capture_output=True, text=True)
    if out.returncode != 0:
        return None
    m = re.match(r"(\d+)\.(\d+)", out.stdout.strip())
    return (int(m.group(1)), int(m.group(2))) if m else None

def ensure_modern_python():
    """Resolve an interpreter that meets MIN_PIPX_PY for pipx tools that require it.
    Prefers the system python3 when it is already new enough; otherwise co-installs
    python3.11 from the deadsnakes PPA (leaving the system default untouched). Returns
    the interpreter name/path to hand pipx via --python, or '' if none is available."""
    def _ensure_dev(dev_pkg):
        """Install the interpreter's dev headers if missing. NetExec's netifaces (and
        other C extensions) compile against Python.h; without the matching -dev package
        the wheel build fails. Idempotent - filter_uninstalled_apt skips it if present."""
        if filter_uninstalled_apt([dev_pkg]):
            install_one("apt",
                        f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {dev_pkg}",
                        dev_pkg)

    sys_ver = _py_version("python3")
    if sys_ver and sys_ver >= MIN_PIPX_PY:
        print(f"System python3 is {sys_ver[0]}.{sys_ver[1]} (>= {MIN_PIPX_PY[0]}.{MIN_PIPX_PY[1]}); "
              "no separate interpreter needed.")
        _ensure_dev("python3-dev")
        return "python3"

    # Already co-installed from a previous run? Still make sure its -dev headers exist
    # (an earlier run may have installed the interpreter without them).
    want = f"python{MIN_PIPX_PY[0]}.{MIN_PIPX_PY[1]}"
    if subprocess.run(f"command -v {want}", shell=True,
                      capture_output=True).returncode == 0:
        print(f"{want} already present for pipx tools that need it.")
        _ensure_dev(f"{want}-dev")
        return want

    print(f"System python3 is {sys_ver[0]}.{sys_ver[1] if sys_ver else '?'}; "
          f"installing {want} alongside it (system default unchanged).")
    # deadsnakes carries current Python builds for LTS releases; add it, then install
    # the interpreter, its venv module, AND its dev headers. The headers ({want}-dev)
    # are required: NetExec pulls C-extension deps (netifaces) that compile against
    # Python.h, and without the matching 3.11 headers the wheel build fails. No
    # update-alternatives, no symlink swap - the system default stays put.
    run_command("sudo add-apt-repository -y ppa:deadsnakes/ppa")
    run_command("sudo DEBIAN_FRONTEND=noninteractive apt-get update")
    if not run_command(
            f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "
            f"{want} {want}-venv {want}-dev"):
        print(f"  WARNING: could not install {want} (+ venv/dev). Tools requiring "
              f">= {MIN_PIPX_PY[0]}.{MIN_PIPX_PY[1]} (e.g. NetExec) will not install.")
        FAILED_PACKAGES.append(f"apt: {want} (needed for NetExec and other modern pipx tools)")
        return ""

    if subprocess.run(f"command -v {want}", shell=True,
                      capture_output=True).returncode == 0:
        print(f"  {want}: installed.")
        return want
    return ""


def install_kismet():
    """Install Kismet from the official kismetwireless.net apt repo, matched to
    the running Ubuntu release. Ubuntu ships no kismet package. Kismet builds
    per-codename packages (jammy != noble) against each release's libs, so the
    repo suite MUST match the OS or dependencies break. Installed suid-root
    non-interactively; NOT started. Idempotent on the kismet binary."""
    if subprocess.run("command -v kismet", shell=True,
                      capture_output=True).returncode == 0:
        print("Kismet already installed, skipping.")
        return

    # Resolve the running release locally and install the repo that matches this host
    codename = detect_ubuntu_codename()
    supported = {"jammy", "noble"}  # kismet release-channel coverage for current Ubuntu
    if codename not in supported:
        print(f"  WARNING: no Kismet release repo for Ubuntu '{codename or 'unknown'}'. "
              "Skipping (check kismetwireless.net/packages for coverage).")
        FAILED_PACKAGES.append(f"apt: kismet (no repo for {codename or 'unknown'})")
        return

    print(f"Installing Kismet (official {codename} repo)")
    run_command("sudo install -d -m 0755 /etc/apt/keyrings")
    # Kismet's release key is armored; signed-by reads the .asc directly (as with Mozilla's)
    run_command(
        "wget -qO- https://www.kismetwireless.net/repos/kismet-release.gpg.key "
        "| sudo tee /etc/apt/keyrings/kismet-archive-keyring.asc >/dev/null")
    run_command(
        f"echo 'deb [signed-by=/etc/apt/keyrings/kismet-archive-keyring.asc] "
        f"https://www.kismetwireless.net/repos/apt/release/{codename} {codename} main' "
        "| sudo tee /etc/apt/sources.list.d/kismet.list >/dev/null")

    # Preseed the suid-root debconf prompt so the install never blocks for input
    run_command(
        "echo 'kismet-core kismet-core/install-setuid boolean true' "
        "| sudo debconf-set-selections")

    run_command("sudo DEBIAN_FRONTEND=noninteractive apt-get update")
    if not run_command(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y kismet"):
        FAILED_PACKAGES.append("apt: kismet")
        return

    # Group membership is required to run kismet unprivileged; installed, not started
    run_command("sudo usermod -aG kismet $USER")

    ver = subprocess.run("kismet --version 2>/dev/null", shell=True,
                         capture_output=True, text=True).stdout.strip()
    print(f"  kismet: {ver or 'installed (version query returned nothing)'}")


def update_kismet():
    """Update Kismet from its apt repo; install it first if absent. install_kismet()
    already added the codename-matched repo, so this just refreshes and upgrades."""
    if subprocess.run("command -v kismet", shell=True,
                      capture_output=True).returncode != 0:
        # not present yet - run the full repo-add + install path
        install_kismet()
        return

    print("Updating Kismet")
    run_command("sudo DEBIAN_FRONTEND=noninteractive apt-get update")
    run_command(
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade kismet")

    ver = subprocess.run("kismet --version 2>/dev/null", shell=True,
                         capture_output=True, text=True).stdout.strip()
    print(f"  kismet: {ver or 'version query returned nothing'}")


# Services the base install pulls in that default to start-on-boot but are only
# needed on demand during an engagement. Each maps to the systemd unit(s) that
# actually ship. openssh-server is deliberately absent: disabling its boot-start
# can lock the operator out of a remote box. The firewall (ufw) is managed
# separately and left alone here.
MANAGED_SERVICES = {
    "apache2":    ["apache2"],
    "postgresql": ["postgresql"],
    "docker":     ["docker", "docker.socket"],
    "samba":      ["smbd", "nmbd"],
    "tftpd-hpa":  ["tftpd-hpa"],
    "gpsd":       ["gpsd", "gpsd.socket"],
}

def _unit_exists(unit):
    """True if systemd knows this unit (installed), regardless of run state."""
    out = subprocess.run(
        f"systemctl list-unit-files {unit}.service {unit} 2>/dev/null",
        shell=True, capture_output=True, text=True).stdout
    return unit in out

def _unit_is_enabled(unit):
    return subprocess.run(f"systemctl is-enabled {unit} 2>/dev/null",
                          shell=True, capture_output=True,
                          text=True).stdout.strip() == "enabled"

def manage_boot_services():
    """Stop and disable the on-demand services the toolkit installs, then prompt
    per service whether to re-enable boot-start. Default posture is disabled: these
    are engagement-time daemons, not things that should listen on every reboot. Only
    units that actually exist on this host are touched; ssh and ufw are never managed
    here. Idempotent - safe to re-run; a service already disabled just stays that way
    unless the operator opts to enable it."""
    print("\nReviewing boot-start for toolkit support services...")

    # Collect the (friendly_name, [present units]) actually installed on this host.
    present = []
    for name, units in MANAGED_SERVICES.items():
        live = [u for u in units if _unit_exists(u)]
        if live:
            present.append((name, live))

    if not present:
        print("None of the managed support services are installed; nothing to do.")
        return

    # Default action: stop + disable boot-start for each present unit.
    for name, units in present:
        for u in units:
            run_command(f"sudo systemctl disable {u} >/dev/null 2>&1")
            run_command(f"sudo systemctl stop {u} >/dev/null 2>&1")
    print(f"Disabled boot-start for: {', '.join(n for n, _ in present)}")

    # Per-service prompt to re-enable. Blank / anything but 'y' keeps it disabled.
    print("\nFor each service, enter 'y' to enable boot-start (and start it now), "
          "anything else to leave it disabled:")
    for name, units in present:
        ans = input(f"  Enable {name} on boot? (y/N): ").strip().lower()
        if ans == "y":
            for u in units:
                run_command(f"sudo systemctl enable {u} >/dev/null 2>&1")
                run_command(f"sudo systemctl start {u} >/dev/null 2>&1")
            print(f"    {name}: enabled and started.")
        else:
            print(f"    {name}: left disabled.")

    # Report final state so the operator has a clear record.
    print("\nSupport service boot-start summary:")
    for name, units in present:
        states = ", ".join(
            f"{u}={'enabled' if _unit_is_enabled(u) else 'disabled'}" for u in units)
        print(f"  {name}: {states}")


def configure_time_sync():
    """Ensure the clock is NTP-synced via systemd-timesyncd, the modern Ubuntu time
    source. Replaces the old one-shot `ntpdate`, which on 22.04+ is transitional and
    can drag in the full `ntp` (ntpd) server - and ntpd's postinst fails whenever
    timesyncd (or any other daemon) already holds UDP/123, breaking the whole apt run.
    timesyncd ships with systemd and is mutually exclusive with ntpd, so this never
    fights for the port. Idempotent."""
    print("Configuring time synchronization (systemd-timesyncd)...")

    # On minimal/container images timesyncd may be a split-out package; install only
    # if its unit is absent. On a normal desktop/server image it is already present.
    have_unit = subprocess.run(
        "systemctl list-unit-files systemd-timesyncd.service 2>/dev/null",
        shell=True, capture_output=True, text=True).stdout
    if "systemd-timesyncd" not in have_unit:
        install_one("apt",
                    "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-timesyncd",
                    "systemd-timesyncd")

    # Enable NTP (this is what activates timesyncd) and start it. timedatectl is the
    # supported control surface; it refuses if a conflicting daemon like ntpd is active,
    # so a clean host with no ntpd just works.
    run_command("sudo systemctl enable --now systemd-timesyncd >/dev/null 2>&1")
    run_command("sudo timedatectl set-ntp true")

    status = subprocess.run("timedatectl show -p NTP -p NTPSynchronized 2>/dev/null",
                            shell=True, capture_output=True, text=True).stdout.strip()
    print(f"  {status or 'timedatectl status unavailable'}")


def finalize_pipx_path():
    """Make pipx-installed console scripts (netexec/nxc, impacket, dnsrecon, etc.)
    reachable. `pipx ensurepath` adds ~/.local/bin to the login PATH by editing the
    shell rc, but that only affects FUTURE shells - this installer's own process and
    the operator's current shell won't see it until a re-login. So: run ensurepath to
    persist it, prepend ~/.local/bin to THIS process's PATH so any later step in the
    same run can find pipx tools, and tell the operator to open a new shell / source
    their rc. A running process cannot alter its parent shell, so `source ~/.bashrc`
    is an instruction to the operator, not something the installer can do for them."""
    run_command("pipx ensurepath")
    local_bin = os.path.expanduser("~/.local/bin")
    if os.path.isdir(local_bin) and local_bin not in os.environ.get("PATH", "").split(":"):
        os.environ["PATH"] = f"{local_bin}:{os.environ['PATH']}"
    print(f"pipx tools are in {local_bin} (added to PATH for future shells).")
    print("  -> For your CURRENT shell, run:  source ~/.bashrc   (or open a new terminal)")


def install_base_dependencies():
    global PIP
    print("Performing system update and upgrade before installing package dependencies...")
    run_command("sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq -o Dpkg::Options::=--force-confold")

    # Base apt set: everything NOT specific to radios. Wireless-only apt packages
    # (radios, monitor-mode/AP, SDR, captive-portal) live in WIRELESS_APT and install
    # with the 'wireless' category instead, so a WSL/no-radio host never pulls them.
    # Dual-use packages that happen to be used by the wireless framework but also by
    # other tooling (wget, iptables, network-manager, python3-bs4, ethtool, usbutils,
    # tshark/tcpdump) stay in base deliberately.
    apt_packages = [
        "vim", "subversion", "landscape-common", "ufw", "openssh-server", "net-tools",
        "plocate", "screen", "whois", "libtool-bin", "make", "gcc", "ncftp",
        "rar", "p7zip-full", "curl", "libpcap-dev", "libssl-dev", "hping3", "libssh-dev",
        "g++", "arp-scan", "ruby-bundler", "freerdp2-dev", "libsqlite3-dev",
        "nbtscan", "dsniff", "apache2", "secure-delete", "autoconf", "libpq-dev",
        "libmysqlclient-dev", "libsvn-dev", "libsmbclient-dev", "libgcrypt20-dev",
        "libbson-dev", "libmongoc-dev", "python3-pip", "netsniff-ng", "httptunnel",
        "ptunnel-ng", "udptunnel", "pipx", "python3-venv", "ruby-dev", "webhttrack",
        "minicom", "openjdk-21-jre", "gnome-tweaks", "recordmydesktop",
        "postgresql", "hydra-gtk", "hydra", "wine-development",
        "libcurl4-openssl-dev", "smbclient", "nfs-common", "samba",
        "snmp", "libsnmp-dev", "libsnmp-perl", "snmp-mibs-downloader", "docker.io",
        "docker-compose", "httrack", "tshark", "git", "python-is-python3",
        "tig", "tftpd-hpa", "libimage-exiftool-perl", "wkhtmltopdf", "libffi-dev",
        "libyaml-dev", "libreadline-dev", "libncurses5-dev", "libgdbm-dev", "zlib1g-dev",
        "build-essential", "bison", "libedit-dev", "libxml2-utils", "automake", "libtool",
        "pkg-config", "ethtool", "shtool",
        "libpcre3-dev", "libhwloc-dev", "libcmocka-dev",
        "tcpdump", "usbutils", "python3-dnspython", "python3-aiofiles",
        "python3-watchdog", "python3-pandas",
        # dual-use (wireless framework + general): kept in base on purpose.
        "python3-bs4", "wget", "network-manager", "iptables"
    ]

    missing_apt = filter_uninstalled_apt(apt_packages)
    if missing_apt:
        print(f"Installing {len(missing_apt)} missing apt packages...")
        apt_install(missing_apt)
    else:
        print("All apt packages already installed, skipping.")

    # refresh PEP 668 flag detection now that pip may have just been installed/upgraded
    PIP = "pip3 install" + pip_flags()

    # Clock sync via systemd-timesyncd (replaces ntpdate, which could pull ntpd and
    # fail on the already-bound NTP port).
    configure_time_sync()

    run_command("sudo usermod -aG docker $USER")
    run_command("sudo snap install powershell --classic")

    # Kismet is a wireless tool; it installs with the 'wireless' category, not in
    # base deps - a WSL/no-radio host should never pull it just for base setup.

    print("Installing Python Packages and Dependencies")
    pip_packages = [
        "build", "dnspython", "kerberoast", "certipy-ad", "knowsmore", "sherlock-project",
        "wafw00f", "pypykatz", "zeep", "netaddr", "ujson", "aiomultiprocess", "censys",
        "shodan", "playwright", "uvloop", "easysnmp", "pysnmp", "tftpy", "aiohttp", "fierce", "aioquic"
    ]

    missing_pip = filter_uninstalled_pip(pip_packages)
    if missing_pip:
        print(f"Installing {len(missing_pip)} missing pip packages...")
        pip_install(missing_pip)
    else:
        print("All pip packages already installed, skipping.")

    pipx_packages = ["urh", "scoutsuite", "checkov", "dnsrecon"]
    for package in pipx_packages:
        install_one("pipx", f"pipx install {package}", package)

    # --force claims impacket's ~/.local/bin scripts cleanly over stale copies
    install_one("pipx", "pipx install --force impacket", "impacket")

    # install managed Go toolchain, then point the environment at /usr/local/go
    install_go()

    go_lines = [
        'export GOROOT=/usr/local/go',
        'export GOPATH=$HOME/go',
        'export PATH=$PATH:/usr/local/go/bin',
        'export PATH=$PATH:$GOPATH/bin',
    ]
    for line in go_lines:
        run_command(f"grep -qxF '{line}' ~/.bashrc || echo '{line}' >> ~/.bashrc")

    # Make Go usable for the rest of this run regardless of .bashrc state
    os.environ['GOROOT'] = '/usr/local/go'
    os.environ.setdefault('GOPATH', os.path.expanduser('~/go'))
    go_paths = f"/usr/local/go/bin:{os.path.expanduser('~/go/bin')}"
    if go_paths not in os.environ.get('PATH', ''):
        os.environ['PATH'] = f"{go_paths}:{os.environ['PATH']}"

    # Install Rust (skip if already present)
    cargo_bin = os.path.expanduser("~/.cargo/bin/rustc")
    if os.path.exists(cargo_bin) or subprocess.run("command -v rustc", shell=True, capture_output=True, text=True).returncode == 0:
        print("Rust already installed, skipping.")
    else:
        print("Installing Rust...")
        if not run_command("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"):
            FAILED_PACKAGES.append("rust: toolchain")

    # Make cargo usable for the rest of this run regardless of .bashrc state
    # (both install and skip paths) so Rust-built wheels like aardwolf/NetExec find rustc
    cargo_path = os.path.expanduser("~/.cargo/bin")
    if os.path.isdir(cargo_path) and cargo_path not in os.environ.get('PATH', ''):
        os.environ['PATH'] = f"{cargo_path}:{os.environ['PATH']}"

    # Install NetExec (skip if already present). NetExec requires Python >= 3.11,
    # which 22.04's system 3.10 does not meet - pin its venv to a modern interpreter
    # rather than the pipx default.
    netexec_check = subprocess.run("pipx list", shell=True, capture_output=True, text=True)
    if "netexec" in netexec_check.stdout.lower():
        print("NetExec already installed, skipping.")
    else:
        print("Installing NetExec...")
        py = ensure_modern_python()
        if py:
            install_one("pipx",
                        f"pipx install --python {py} git+https://github.com/Pennyw0rth/NetExec",
                        "netexec")
        else:
            print("  Skipping NetExec: no interpreter meeting its Python floor is available.")
            FAILED_PACKAGES.append("pipx: netexec (no Python >= 3.11 interpreter)")

    # All base-deps pipx installs are done; persist ~/.local/bin on PATH and make it
    # usable for the rest of this run.
    finalize_pipx_path()

    # Ruby via rbenv (self-contained and idempotent)
    install_ruby()

    if not os.path.isfile("/usr/local/bin/cpanm"):
        print("CPANminus not found. Installing CPANminus...")
        run_command("mkdir -p /vapt/temp")
        run_command("cd /vapt/temp && git clone https://github.com/miyagawa/cpanminus.git")
        run_command("cd /vapt/temp/cpanminus/App-cpanminus && perl Makefile.PL")
        run_command("cd /vapt/temp/cpanminus/App-cpanminus && make")
        run_command("cd /vapt/temp/cpanminus/App-cpanminus && sudo make install")
        run_command("rm -rf /vapt/temp/cpanminus")
        print("CPANminus installation complete.")
    else:
        print("CPANminus is already installed, skipping installation.")

    # Perl CPAN modules
    cpan_modules = [
        "Cisco::CopyConfig", "Net::Netmask", "XML::Writer",
        "String::Random", "Net::IP", "Net::DNS"
    ]
    missing_cpan = filter_uninstalled_cpan(cpan_modules)
    if missing_cpan:
        for module in missing_cpan:
            install_one("cpan", f"sudo cpanm {module}", module)
    else:
        print("All Perl modules already installed, skipping.")

    # bettercap precompiled release binary; runs as root, so placed in /usr/local/bin
    if os.path.exists("/usr/local/bin/bettercap"):
        print("bettercap already installed, skipping.")
    else:
        print("Installing bettercap")
        run_command("cd /tmp && curl -sL -o bettercap.zip https://github.com/bettercap/bettercap/releases/latest/download/bettercap_linux_amd64.zip")
        run_command("cd /tmp && 7z x bettercap.zip -y")
        run_command("cd /tmp && sudo install -m 755 bettercap /usr/local/bin/bettercap")
        run_command("cd /tmp && rm -f bettercap.zip bettercap bettercap_linux_amd64.sha256")

    # Set up firewall rules (idempotent; --force avoids the interactive y/n prompt)
    print("Configuring firewall rules...")
    ufw_status = subprocess.run("sudo ufw status", shell=True, capture_output=True, text=True)
    if "Status: active" in ufw_status.stdout and "22/tcp" in ufw_status.stdout:
        print("Firewall already configured, skipping.")
    else:
        run_command("sudo ufw default deny incoming")
        run_command("sudo ufw default allow outgoing")
        run_command("sudo ufw allow 22/tcp")
        run_command("sudo ufw --force enable")

    # Toolkit support services (apache2/postgresql/docker/samba/tftpd/gpsd) default
    # to start-on-boot; disable them and let the operator opt any back in.
    manage_boot_services()

    print("Base toolkit dependency install pass complete.")
    print_failure_summary()

def _toolkit_path_env():
    """Put rbenv shims, Go, and GOPATH bin on PATH for this process. rbenv shims
    first so Metasploit's bundle resolves the 3.3.9 Ruby, not system Ruby. Shared
    by the install and update passes so both build against the same toolchain."""
    os.environ['GOROOT'] = '/usr/local/go'
    os.environ.setdefault('GOPATH', os.path.expanduser('~/go'))
    os.environ['PATH'] = (
        f"{os.path.expanduser('~/.rbenv/shims')}:"
        f"{os.path.expanduser('~/.rbenv/bin')}:"
        f"/usr/local/go/bin:{os.path.expanduser('~/go/bin')}:"
        f"{os.environ.get('PATH', '')}"
    )

def build_metasploit():
    """Metasploit Framework (vendored bundle install to avoid system gem path / sudo)."""
    msf_dir = "/vapt/exploits/metasploit-framework"
    if os.path.exists(msf_dir):
        print("Metasploit Framework already installed, skipping.")
        return
    print("Installing Metasploit Framework")
    run_command(f"git clone https://github.com/rapid7/metasploit-framework.git {msf_dir}")
    # pin MSF to the rbenv Ruby this installer provides (3.3.9), not the upstream .ruby-version
    run_command(f"echo '3.3.9' > {msf_dir}/.ruby-version")
    run_command(f"cd {msf_dir} && bundle config set --local path vendor/bundle")
    run_command(f"cd {msf_dir} && bundle install")

def build_johntheripper():
    """JohnTheRipper (source build)."""
    jtr_dir = "/vapt/passwords/JohnTheRipper"
    if os.path.exists(jtr_dir):
        print("JohnTheRipper already installed, skipping.")
        return
    print("Installing JohnTheRipper")
    run_command("cd /vapt/passwords && git clone https://github.com/magnumripper/JohnTheRipper.git")
    run_command("cd /vapt/passwords/JohnTheRipper/src && ./configure")
    run_command("cd /vapt/passwords/JohnTheRipper/src && make -s clean && make -sj4")
    run_command("cd /vapt/passwords/JohnTheRipper/src && make install")

# Wireless-only apt packages: radios/SDR (hackrf), 802.11 capture/attack
# (hcxtools, wifite, mdk4), monitor-mode/AP (hostapd, wpasupplicant, iw, rfkill),
# MAC spoofing (macchanger), aircrack-ng nl80211 build deps (libnl-3-dev,
# libnl-genl-3-dev), captive-portal DHCP/DNS (dnsmasq-base), and GPS (gpsd). These
# install with the 'wireless' category, never in base deps, so a no-radio host
# (WSL, VM without USB passthrough) skips them. Dual-use packages the wireless
# framework also touches (wget, iptables, network-manager, python3-bs4) stay in base.
WIRELESS_APT = [
    "wifite", "hackrf", "hcxtools", "macchanger", "rfkill", "hostapd",
    "wpasupplicant", "iw", "mdk4", "dnsmasq-base", "gpsd",
    "libnl-3-dev", "libnl-genl-3-dev",
]

def install_wireless_apt():
    """Install the radio-specific apt packages for the wireless category, fail-soft,
    skipping any already present. Runs before the wireless source-builds (aircrack-ng
    needs libnl-*-dev) and clones, so its deps are in place first."""
    missing = filter_uninstalled_apt(WIRELESS_APT)
    if not missing:
        print("All wireless apt packages already installed, skipping.")
        return
    print(f"Installing {len(missing)} wireless apt packages...")
    apt_install(missing)

def build_aircrack():
    """Aircrack-ng (source build; tarball, not a git repo)."""
    aircrack_dir = "/vapt/wireless/aircrack-ng-1.7"
    if os.path.exists(aircrack_dir):
        print("Aircrack-ng already installed, skipping.")
        return
    print("Installing Aircrack-ng")
    run_command("cd /vapt/wireless && wget https://download.aircrack-ng.org/aircrack-ng-1.7.tar.gz")
    run_command("cd /vapt/wireless && tar -zxvf aircrack-ng-1.7.tar.gz")
    run_command(f"cd {aircrack_dir} && autoreconf -i")
    run_command(f"cd {aircrack_dir} && ./configure --with-experimental")
    run_command(f"cd {aircrack_dir} && make")
    run_command(f"cd {aircrack_dir} && sudo make install")
    run_command("sudo ldconfig")
    run_command("cd /vapt/wireless && rm -rf aircrack-ng-1.7.tar.gz")

def build_zap():
    """OWASP ZAP (release tarball)."""
    zap_dir = "/vapt/web/zap"
    if os.path.exists(zap_dir):
        print("OWASP ZAP already installed, skipping.")
        return
    print("Installing OWASP ZAP")
    run_command("cd /vapt/web && wget https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz")
    run_command("cd /vapt/web && tar xvf ZAP_2.17.0_Linux.tar.gz")
    run_command("cd /vapt/web && rm -rf ZAP_2.17.0_Linux.tar.gz")
    run_command("cd /vapt/web && mv ZAP_2.17.0/ zap/")

def install_bettercap():
    """bettercap precompiled release binary; runs as root, so placed in /usr/local/bin.
    Used for both first install and update (pull-latest-over-existing is the same op)."""
    print("Installing/updating bettercap")
    run_command("cd /tmp && curl -sL -o bettercap.zip https://github.com/bettercap/bettercap/releases/latest/download/bettercap_linux_amd64.zip")
    run_command("cd /tmp && 7z x bettercap.zip -y")
    run_command("cd /tmp && sudo install -m 755 bettercap /usr/local/bin/bettercap")
    run_command("cd /tmp && rm -f bettercap.zip bettercap bettercap_linux_amd64.sha256")

def tool_categories():
    """Single source of truth for tool categories, consumed by both the install
    and update passes so they can never drift. Built inside a function (not at
    module level) because the clone setup commands bake in {PIP}, which is only
    finalized after install_base_dependencies() runs its PEP 668 detection.

    Each category carries:
      label        - human name for menus and progress output
      clone_tools  - (repo_url, install_dir, setup_commands) for check_and_install()
      builders     - callables run on install for source-builds / release binaries
      update_paths - git-pull dirs on update (the clone_tools dirs that are plain pulls)
      go_tools     - (name, path, build_cmd) rebuilt on update only when the pull changed
      post         - callables run after this category's install/update (kismet upgrade,
                     searchsploit-rc fix)
    """
    return {
        "exploitation": {
            "label": "Exploitation / C2",
            "clone_tools": [
                ("https://github.com/trustedsec/social-engineer-toolkit.git", "/vapt/exploits/social-engineer-toolkit", [f"{PIP} -r requirements.txt"]),
                ("https://gitlab.com/exploit-database/exploitdb.git", "/vapt/exploits/exploitdb", None),
                ("https://github.com/Tantalum-Labs/Responder-NG.git", "/vapt/exploits/Responder-NG", None),
                ("https://github.com/beefproject/beef.git", "/vapt/exploits/beef", None),
                ("https://github.com/xFreed0m/ADFSpray.git", "/vapt/exploits/ADFSpray", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/gentilkiwi/mimikatz.git", "/vapt/exploits/mimikatz", None),
                ("https://github.com/byt3bl33d3r/DeathStar.git", "/vapt/exploits/DeathStar", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/cobbr/Covenant.git", "/vapt/exploits/Covenant", None),
                ("https://github.com/Ne0nd0g/merlin.git", "/vapt/exploits/merlin", ["sed -i '/^toolchain/d' go.mod", "PATH=/usr/local/go/bin:$PATH /usr/local/go/bin/go mod tidy", "PATH=/usr/local/go/bin:$PATH make"]),
                ("https://github.com/byt3bl33d3r/SILENTTRINITY.git", "/vapt/exploits/SILENTTRINITY", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/MatheuZSecurity/D3m0n1z3dShell.git", "/vapt/exploits/D3m0n1z3dShell", ["chmod +x demonizedshell.sh"]),
            ],
            "builders": [build_metasploit],
            "update_paths": [
                "/vapt/exploits/social-engineer-toolkit", "/vapt/exploits/metasploit-framework",
                "/vapt/exploits/ADFSpray", "/vapt/exploits/beef", "/vapt/exploits/DeathStar",
                "/vapt/exploits/mimikatz", "/vapt/exploits/Responder-NG",
                "/vapt/exploits/exploitdb", "/vapt/exploits/Covenant",
                "/vapt/exploits/SILENTTRINITY", "/vapt/exploits/D3m0n1z3dShell",
            ],
            "go_tools": [
                ("merlin", "/vapt/exploits/merlin",
                 "sed -i '/^toolchain/d' go.mod && PATH=/usr/local/go/bin:$PATH /usr/local/go/bin/go mod tidy && PATH=/usr/local/go/bin:$PATH make"),
            ],
            # exploitdb's upstream .searchsploit_rc points at /opt/exploitdb; a pull can
            # restore it, so the correction re-applies on both install and update.
            "post": [fix_searchsploit_rc],
        },
        "web": {
            "label": "Web application",
            "clone_tools": [
                ("https://github.com/assetnote/kiterunner.git", "/vapt/web/kiterunner", ["make build"]),
                ("https://github.com/projectdiscovery/httpx.git", "/vapt/web/httpx", ["/usr/local/go/bin/go install ./cmd/httpx"]),
                ("https://github.com/ffuf/ffuf.git", "/vapt/web/ffuf", ["/usr/local/go/bin/go build"]),
                ("https://github.com/maurosoria/dirsearch.git", "/vapt/web/dirsearch", None),
                ("https://github.com/sullo/nikto.git", "/vapt/web/nikto", None),
                ("https://github.com/JohnTroony/php-webshells.git", "/vapt/web/php-webshells", None),
                ("https://github.com/wireghoul/htshells.git", "/vapt/web/htshells", None),
                ("https://github.com/urbanadventurer/WhatWeb.git", "/vapt/web/WhatWeb", None),
                ("https://github.com/siberas/watobo.git", "/vapt/web/watobo", None),
                ("https://github.com/projectdiscovery/nuclei.git", "/vapt/web/nuclei", ["/usr/local/go/bin/go build -o nuclei ./cmd/nuclei", "sudo install -m 755 nuclei /usr/local/bin/nuclei"]),
                ("https://github.com/projectdiscovery/katana.git", "/vapt/web/katana", ["/usr/local/go/bin/go build -o katana ./cmd/katana", "sudo install -m 755 katana /usr/local/bin/katana"]),
                ("https://github.com/rezasp/joomscan.git", "/vapt/web/joomscan", None),
                ("https://github.com/s0md3v/XSStrike.git", "/vapt/web/XSStrike", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/wapiti-scanner/wapiti.git", "/vapt/web/wapiti", [f"sudo {PIP} ."]),
                ("https://github.com/com-puter-tips/Links-Extractor.git", "/vapt/web/Links-Extractor", [f"{PIP} -r requirements.txt"]),
            ],
            # ZAP's AJAX spider needs a real .deb Firefox + geckodriver, installed here.
            "builders": [build_zap, install_firefox_headless],
            "update_paths": [
                "/vapt/web/htshells", "/vapt/web/joomscan", "/vapt/web/nikto",
                "/vapt/web/php-webshells", "/vapt/web/watobo", "/vapt/web/WhatWeb",
                "/vapt/web/XSStrike", "/vapt/web/wapiti", "/vapt/web/Links-Extractor",
                "/vapt/web/kiterunner", "/vapt/web/dirsearch",
            ],
            "go_tools": [
                ("httpx",  "/vapt/web/httpx", "/usr/local/go/bin/go install ./cmd/httpx"),
                ("ffuf",   "/vapt/web/ffuf",  "/usr/local/go/bin/go build"),
                ("nuclei", "/vapt/web/nuclei",
                 "/usr/local/go/bin/go build -o nuclei ./cmd/nuclei && sudo install -m 755 nuclei /usr/local/bin/nuclei"),
                ("katana", "/vapt/web/katana",
                 "/usr/local/go/bin/go build -o katana ./cmd/katana && sudo install -m 755 katana /usr/local/bin/katana"),
            ],
            "post": [],
        },
        "container_cloud": {
            "label": "Container & cloud",
            "clone_tools": [
                ("https://github.com/aquasecurity/trivy.git", "/vapt/cloud/trivy", None),
                ("https://github.com/RhinoSecurityLabs/pacu.git", "/vapt/cloud/pacu", ["pipx install /vapt/cloud/pacu"]),
            ],
            "builders": [],
            "update_paths": ["/vapt/cloud/trivy", "/vapt/cloud/pacu"],
            "go_tools": [],
            "post": [],
        },
        "ad_windows": {
            "label": "Active Directory / Windows",
            "clone_tools": [
                ("https://github.com/BloodHoundAD/BloodHound.git", "/vapt/ad_windows/BloodHound", None),
                ("https://github.com/mattifestation/PowerSploit.git", "/vapt/ad_windows/PowerSploit", None),
                ("https://github.com/CroweCybersecurity/ps1encode.git", "/vapt/ad_windows/ps1encode", None),
                ("https://github.com/Kevin-Robertson/Invoke-TheHash.git", "/vapt/ad_windows/Invoke-TheHash", None),
                ("https://github.com/p3nt4/PowerShdll.git", "/vapt/ad_windows/PowerShdll", None),
                ("https://github.com/GhostPack/Rubeus.git", "/vapt/ad_windows/Rubeus", None),
                ("https://github.com/dirkjanm/ldapdomaindump.git", "/vapt/ad_windows/ldapdomaindump", ["pipx install /vapt/ad_windows/ldapdomaindump"]),
                ("https://github.com/adityatelange/evil-winrm-py.git", "/vapt/ad_windows/evil-winrm-py", [f"sudo {PIP} ."]),
            ],
            "builders": [],
            "update_paths": [
                "/vapt/ad_windows/BloodHound", "/vapt/ad_windows/PowerSploit", "/vapt/ad_windows/ps1encode",
                "/vapt/ad_windows/Invoke-TheHash", "/vapt/ad_windows/PowerShdll",
                "/vapt/ad_windows/Rubeus", "/vapt/ad_windows/ldapdomaindump", "/vapt/ad_windows/evil-winrm-py",
            ],
            "go_tools": [],
            "post": [],
        },
        "mobile": {
            "label": "Mobile security",
            "clone_tools": [
                ("https://github.com/MobSF/Mobile-Security-Framework-MobSF.git", "/vapt/mobile/MobSF", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/sensepost/objection.git", "/vapt/mobile/objection", [f"{PIP} objection"]),
            ],
            "builders": [],
            "update_paths": ["/vapt/mobile/MobSF", "/vapt/mobile/objection"],
            "go_tools": [],
            "post": [],
        },
        "network": {
            "label": "Network & infrastructure",
            "clone_tools": [
                ("https://github.com/robertdavidgraham/masscan.git", "/vapt/network/masscan", ["make"]),
                ("https://github.com/OWASP/Amass.git", "/vapt/network/Amass", ["/usr/local/go/bin/go install -v ./cmd/amass/..."]),
            ],
            "builders": [],
            "update_paths": ["/vapt/network/masscan"],
            "go_tools": [
                ("amass", "/vapt/network/Amass", "/usr/local/go/bin/go install -v ./cmd/amass/..."),
            ],
            "post": [],
        },
        "password": {
            # Crackers and wordlist-generators only - no bulk dictionaries, so this
            # stays light enough for a thin/WSL install. SecLists lives in its own
            # 'dictionaries' category because it is multiple GB of static data.
            "label": "Password cracking",
            "clone_tools": [
                ("https://github.com/hashcat/hashcat.git", "/vapt/passwords/hashcat", None),
                ("https://github.com/digininja/CeWL.git", "/vapt/passwords/CeWL", None),
            ],
            "builders": [build_johntheripper],
            "update_paths": [
                "/vapt/passwords/JohnTheRipper", "/vapt/passwords/hashcat",
                "/vapt/passwords/CeWL",
            ],
            "go_tools": [],
            "post": [],
        },
        "dictionaries": {
            # Bulk wordlists / dictionaries - large on disk, split out so password
            # cracking can be installed without pulling multiple GB. The Weakpass
            # dictionary (menu option 3) is separate again; this is the git-cloned set.
            "label": "Dictionaries / wordlists (large)",
            "clone_tools": [
                ("https://github.com/danielmiessler/SecLists.git", "/vapt/passwords/SecLists", None),
            ],
            "builders": [],
            "update_paths": ["/vapt/passwords/SecLists"],
            "go_tools": [],
            "post": [],
        },
        "fuzzers": {
            "label": "Fuzzers",
            "clone_tools": [
                ("https://github.com/jtpereyda/boofuzz.git", "/vapt/fuzzers/boofuzz", None),
            ],
            "builders": [],
            "update_paths": ["/vapt/fuzzers/boofuzz"],
            "go_tools": [],
            "post": [],
        },
        "audit": {
            "label": "Audit / posture",
            "clone_tools": [
                ("https://github.com/hausec/PowerZure.git", "/vapt/audit/PowerZure", None),
                ("https://github.com/PlumHound/PlumHound.git", "/vapt/audit/PlumHound", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/wireghoul/graudit.git", "/vapt/audit/graudit", None),
            ],
            "builders": [],
            "update_paths": ["/vapt/audit/PowerZure", "/vapt/audit/PlumHound", "/vapt/audit/graudit"],
            "go_tools": [],
            "post": [],
        },
        "vulnerability_scanners": {
            "label": "Vulnerability scanners",
            "clone_tools": [
                ("https://github.com/sqlmapproject/sqlmap.git", "/vapt/scanners/sqlmap", None),
                ("https://github.com/nmap/nmap.git", "/vapt/scanners/nmap", ["./configure --without-zenmap --without-ndiff", "make", "sudo make install"]),
                ("https://github.com/makefu/dnsmap.git", "/vapt/scanners/dnsmap", ["gcc -o dnsmap dnsmap.c"]),
                ("https://github.com/fwaeytens/dnsenum.git", "/vapt/scanners/dnsenum", None),
                ("https://github.com/nccgroup/cisco-SNMP-enumeration.git", "/vapt/scanners/cisco-SNMP-enumeration", None),
                ("https://github.com/aas-n/spraykatz.git", "/vapt/scanners/spraykatz", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/p0dalirius/pyFindUncommonShares.git", "/vapt/scanners/pyFindUncommonShares", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/CiscoCXSecurity/enum4linux.git", "/vapt/scanners/enum4linux", None),
            ],
            "builders": [],
            # fierce is a pip package, not a cloned repo, so it is not pulled here.
            "update_paths": [
                "/vapt/scanners/sqlmap", "/vapt/scanners/nmap",
                "/vapt/scanners/dnsmap", "/vapt/scanners/dnsenum",
                "/vapt/scanners/cisco-SNMP-enumeration", "/vapt/scanners/spraykatz",
                "/vapt/scanners/pyFindUncommonShares", "/vapt/scanners/enum4linux",
            ],
            "go_tools": [],
            "post": [],
        },
        "osint": {
            "label": "OSINT / intel",
            "clone_tools": [
                ("https://github.com/lanmaster53/recon-ng.git", "/vapt/intel/recon-ng", [f"{PIP} -r REQUIREMENTS"]),
                ("https://github.com/smicallef/spiderfoot.git", "/vapt/intel/spiderfoot", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/laramies/theHarvester.git", "/vapt/intel/theHarvester", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/nccgroup/scrying.git", "/vapt/intel/scrying", None),
                ("https://github.com/FortyNorthSecurity/EyeWitness.git", "/vapt/intel/EyeWitness", None),
                ("https://github.com/l4rm4nd/LinkedInDumper.git", "/vapt/intel/LinkedInDumper", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/OsmanKandemir/indicator-intelligence.git", "/vapt/intel/indicator-intelligence", [f"{PIP} -r requirements.txt", f"sudo {PIP} ."]),
            ],
            "builders": [],
            "update_paths": [
                "/vapt/intel/recon-ng", "/vapt/intel/spiderfoot", "/vapt/intel/theHarvester",
                "/vapt/intel/scrying", "/vapt/intel/EyeWitness", "/vapt/intel/LinkedInDumper",
                "/vapt/intel/indicator-intelligence",
            ],
            "go_tools": [],
            "post": [],
        },
        "wireless": {
            # One combined category spanning 802.11 attack tooling and SDR/RF. Skip
            # the whole category on WSL and other hosts with no real radio access.
            "label": "Wireless (802.11 + SDR/RF)",
            "clone_tools": [
                ("https://github.com/g4ixt/QtTinySA.git", "/vapt/wireless/QtTinySA", [f"{PIP} -r requirements.txt"]),
                ("https://github.com/xmikos/qspectrumanalyzer.git", "/vapt/wireless/qspectrumanalyzer", [f"sudo {PIP} ."]),
                # eaphammer: EAP/WPA-Enterprise rogue AP, front-ended by tools/eap_rogue.py.
                # Its ubuntu-unattended-setup pulls its own apt deps and builds a local
                # OpenSSL + patched hostapd; --bootstrap generates the one-time self-signed
                # RADIUS cert non-interactively.
                ("https://github.com/s0lst1c3/eaphammer.git", "/vapt/wireless/eaphammer",
                 ["sudo ./ubuntu-unattended-setup", "sudo ./eaphammer --bootstrap"]),
            ],
            "builders": [install_wireless_apt, build_aircrack, install_kismet],
            "update_paths": [
                "/vapt/wireless/QtTinySA", "/vapt/wireless/qspectrumanalyzer",
                "/vapt/wireless/eaphammer",
            ],
            "go_tools": [],
            "post": [update_kismet],
        },
    }

# Categories whose tools run as root (L2/MITM, rogue AP, raw sockets). Informational
# for now - selection is host-driven, not privilege-gated - but kept explicit so a
# future WSL/unprivileged profile can default these off.
ROOT_CATEGORIES = {"wireless"}

def install_selected_categories(selected):
    """Install only the named categories, then record them in the manifest. Each
    category installs its clone_tools (fail-soft via check_and_install), runs its
    builders (source-builds / release binaries), then its post hooks. bettercap is
    installed once if any L2/MITM-adjacent category is selected."""
    _toolkit_path_env()
    cats = tool_categories()
    print(f"Installing toolkit packages for: {', '.join(sorted(selected))}")

    for slug in sorted(selected):
        spec = cats.get(slug)
        if not spec:
            print(f"  WARNING: unknown category '{slug}', skipping.")
            continue
        print(f"\n=== {spec['label']} ===")
        for tool in spec["clone_tools"]:
            check_and_install(*tool)
        for builder in spec["builders"]:
            builder()
        for hook in spec["post"]:
            hook()

    # bettercap is shared L2/MITM tooling; install it when exploitation or wireless
    # is in scope (the categories whose workflows drive it).
    if selected & {"exploitation", "wireless"}:
        install_bettercap()

    # Some categories install pipx tools (pacu, ldapdomaindump); make sure their
    # console scripts are on PATH and the operator knows to refresh their shell.
    finalize_pipx_path()

    write_manifest(selected)
    print("\nToolkit packages install pass complete.")
    print_failure_summary()

def install_toolkit_packages():
    """Menu entry point: let the operator install all categories or a chosen subset,
    then hand off to install_selected_categories()."""
    selected = choose_categories(action="install")
    if not selected:
        print("No categories selected, returning to menu.")
        return
    install_selected_categories(selected)

def update_toolsets():
    """Update only the tool categories recorded in the install manifest, so a host
    that skipped (e.g.) wireless never tries to pull or rebuild tools it never cloned.
    With no manifest (a pre-manifest install), fall back to updating every category -
    the old behavior - and record the full set so later runs are scoped."""
    _toolkit_path_env()
    cats = tool_categories()

    installed = read_manifest()
    if installed is None:
        print("No install manifest found; updating all categories (legacy host).")
        installed = set(cats.keys())
        write_manifest(installed)
    else:
        unknown = installed - set(cats.keys())
        installed = installed & set(cats.keys())
        if unknown:
            print(f"  NOTE: manifest lists unknown categories (ignored): {', '.join(sorted(unknown))}")
        if not installed:
            print("Manifest records no known categories; nothing to update.")
            return
        print(f"Updating installed categories: {', '.join(sorted(installed))}")

    # Refresh the managed Go toolchain first so Go-based rebuilds use current Go.
    install_go()
    os.environ['GOROOT'] = '/usr/local/go'
    os.environ.setdefault('GOPATH', os.path.expanduser('~/go'))
    go_paths = f"/usr/local/go/bin:{os.path.expanduser('~/go/bin')}"
    if go_paths not in os.environ.get('PATH', ''):
        os.environ['PATH'] = f"{go_paths}:{os.environ['PATH']}"

    for slug in sorted(installed):
        spec = cats[slug]
        print(f"\n=== Updating {spec['label']} ===")
        for path in spec["update_paths"]:
            if os.path.exists(path):
                run_command(f"cd {path} && git pull")
        # Go-based tools: pull each, rebuild only when the pull brought in changes.
        for name, path, build in spec["go_tools"]:
            if not os.path.exists(path):
                continue
            if git_pull_changed(path):
                run_command(f"cd {path} && {build}")
        # post hooks (searchsploit-rc fix, kismet upgrade) run per-category on update too.
        for hook in spec["post"]:
            hook()

    # bettercap ships as a precompiled release binary; refresh if a category that
    # uses it is installed. Same gate as install_selected_categories().
    if installed & {"exploitation", "wireless"}:
        install_bettercap()

    print("\nUpdating all pipx installed tools")
    run_command("pipx upgrade-all")

    print("Updating VA-PT")
    run_command("cd /vapt/misc/va-pt && git pull")

    print("Toolsets update complete.")

def choose_categories(action="install"):
    """Interactive toggle checklist. Returns the set of selected category slugs,
    or an empty set if the operator backs out. Pre-seeds current state from the
    manifest so re-running shows what is already installed. 'A' = all, numbers
    toggle, Enter/blank confirms, 'q' cancels."""
    cats = tool_categories()
    order = list(cats.keys())
    already = read_manifest() or set()
    # Default selection: everything already installed stays checked; a fresh host
    # starts with nothing checked so the operator opts in explicitly.
    selected = set(already)

    while True:
        print(f"\n\033[91mSelect tool categories to {action}:\033[0m")
        for i, slug in enumerate(order, 1):
            mark = "x" if slug in selected else " "
            tag = "  (installed)" if slug in already else ""
            print(f"  [{mark}] {i:>2} - {cats[slug]['label']}{tag}")
        print("   A - select all")
        print("   N - select none")
        print("   Enter - confirm selection")
        print("   q - cancel, back to menu")

        raw = input("Toggle # / A / N / Enter / q: ").strip().lower()

        if raw == "q":
            return set()
        if raw == "":
            return selected
        if raw == "a":
            selected = set(order)
            continue
        if raw == "n":
            selected = set()
            continue

        # Accept space- or comma-separated numbers to toggle several at once.
        toggled_any = False
        for tok in re.split(r"[,\s]+", raw):
            if not tok:
                continue
            if tok.isdigit() and 1 <= int(tok) <= len(order):
                slug = order[int(tok) - 1]
                selected ^= {slug}
                toggled_any = True
            else:
                print(f"  Ignoring invalid entry: {tok}")
        if not toggled_any:
            print("  Nothing toggled.")

def main_menu():
    check_directory_structure()
    cleanup_old_directories()

    while True:
        print("\033[91m1 - Install Base Toolkit Dependencies\033[0m")
        print("\033[91m2 - Install Toolkit Packages (all or selected categories)\033[0m")
        print("\033[91m3 - Install Weakpass Dictionary for Password Cracking (30G)\033[0m")
        print("\033[91m4 - Update Toolsets\033[0m")
        print("\033[91m0 - Exit\033[0m")

        choice = input("Enter your choice: ")

        if choice == '1':
            install_base_dependencies()
        elif choice == '2':
            install_toolkit_packages()
        elif choice == '3':
            install_wordlist_files()
        elif choice == '4':
            update_toolsets()
        elif choice == '0':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    if os.geteuid() == 0:
        print("This script should not be run as root..", file=sys.stderr)
        sys.exit(1)

    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)

    display_logo()
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting...")
        sys.exit(130)
