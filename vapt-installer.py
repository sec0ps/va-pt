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
import datetime

LOG_PATH = "/vapt/install_failures.log"

# Names of packages that failed to install, collected for an end-of-run summary.
FAILED_PACKAGES = []

def run_command(command):
    """Execute a command, suppressing output. On failure, log captured
    stdout/stderr to LOG_PATH for later review. Returns True on success."""
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
    """Return extra pip flags this environment needs. On PEP 668 marked
    interpreters (Ubuntu 23.04+, and 24.04 hosts) a plain system pip3 install
    is refused, so add --break-system-packages when the marker is present and
    the installed pip is new enough to accept the flag. On Ubuntu 22.04 there
    is no marker, so this returns an empty string and behavior is unchanged."""
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
    """Attempt a single package install. Always returns rather than raising, so
    the caller moves on to the next package whether this one succeeded or not.
    Failures are logged by run_command and recorded for the end-of-run summary."""
    print(f"  [{kind}] {name} ...", end=" ", flush=True)
    if run_command(install_cmd):
        print("ok")
        return True
    print("FAILED")
    FAILED_PACKAGES.append(f"{kind}: {name}")
    return False

def apt_install(packages):
    """Install apt packages one at a time. A failure on any single package does
    not stop the rest; each is attempted independently. apt-get is used rather
    than apt because apt warns that its CLI is not stable for scripting.
    DEBIAN_FRONTEND=noninteractive so debconf prompts (macchanger auto-run,
    wireshark non-root capture) take defaults instead of blocking on hidden
    whiptail dialogs that capture_output would swallow."""
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

def git_pull_changed(path):
    """Run 'git pull' in path, logging failures the same way run_command does.
    Returns True only if the pull actually brought in changes. A repo that was
    already current, or a pull that failed, returns False so nothing is rebuilt
    needlessly."""
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

        # Remove the old directory
        run_command(f"rm -rf {old_powershell_dir}")
        print("Old powershell directory cleaned up successfully.")

    # Handle old FindUncommonShares directory
    if os.path.exists(old_findshares_dir):
        print("Cleaning up old FindUncommonShares directory...")
        run_command(f"rm -rf {old_findshares_dir}")
        print("Old FindUncommonShares directory removed. Will be reinstalled as pyFindUncommonShares.")

    # Handle old GRecon directory
    if os.path.exists(old_grecon_dir):
        print("Cleaning up old GRecon directory...")
        run_command(f"rm -rf {old_grecon_dir}")
        print("Old GRecon directory removed.")

    # Cleanup Arachni if it exists
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
    """Install a tool only if it is not already present. If install_dir exists,
    the tool is considered installed and is skipped — no git pull, no rerun of
    setup commands. Upgrading existing tools is handled separately by the Update
    Toolsets menu option, so this stays a pure install pass: a fresh clone runs
    its setup commands once, and everything already on disk is left untouched so
    the install does not slow down as the toolkit grows."""
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

def install_go():
    """Install a current Go toolchain to /usr/local/go from go.dev.

    nuclei v3 and the other projectdiscovery tools require Go 1.24.2 or newer,
    which is newer than the distro golang packages carry on some releases, so a
    managed toolchain avoids apt version and availability problems. The latest
    stable is fetched at runtime with a pinned fallback. Skips the download if a
    Go at least this new is already present at /usr/local/go.

    Assumes linux/amd64, which matches the x86_64 dropbox and tester VM base."""
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
    """Install Ruby 3.3.9 through rbenv with an explicitly managed ruby-build
    plugin. The key reliability fixes over the prior version:
      - ruby-build is cloned if missing and always updated, so the 3.3.9
        definition is present (a stale plugin causes
        'ruby-build: definition not found: 3.3.9').
      - ruby-build is ensured even when rbenv is already installed from a
        prior partial run, instead of only as a side effect of installing rbenv.
      - the rbenv shims directory is placed on PATH for this process, so the
        install can be verified and later steps (Metasploit's bundle) resolve
        the 3.3.9 Ruby rather than system Ruby.
      - the critical install call's return code is actually checked."""
    print("Checking Ruby version...")

    ruby_check = subprocess.run("ruby -v", shell=True, capture_output=True, text=True)
    if ruby_check.returncode == 0 and "3.3.9" in ruby_check.stdout:
        print("Ruby 3.3.9 already installed and active, skipping.")
        return

    rbenv_root = os.path.expanduser("~/.rbenv")
    rbenv_bin = f"{rbenv_root}/bin/rbenv"
    ruby_build_dir = f"{rbenv_root}/plugins/ruby-build"

    # 1. rbenv itself
    if not os.path.exists(rbenv_bin):
        print("Installing rbenv...")
        run_command(f"git clone https://github.com/rbenv/rbenv.git {rbenv_root}")
        for line in ['export PATH="$HOME/.rbenv/bin:$PATH"', 'eval "$(rbenv init - bash)"']:
            run_command(f"grep -qxF '{line}' ~/.bashrc || echo '{line}' >> ~/.bashrc")

    # 2. ruby-build plugin: clone if missing, always update definitions
    if not os.path.exists(ruby_build_dir):
        print("Installing ruby-build plugin...")
        run_command(f"git clone https://github.com/rbenv/ruby-build.git {ruby_build_dir}")
    else:
        print("Updating ruby-build definitions...")
        run_command(f"cd {ruby_build_dir} && git pull")

    # 3. Make rbenv and its shims usable for the rest of THIS process
    os.environ["RBENV_ROOT"] = rbenv_root
    os.environ["PATH"] = f"{rbenv_root}/bin:{rbenv_root}/shims:{os.environ.get('PATH', '')}"

    # 4. Confirm the definition exists before a multi-minute compile
    if not os.path.exists(f"{ruby_build_dir}/share/ruby-build/3.3.9"):
        print("  ERROR: ruby-build has no 3.3.9 definition even after update. "
              f"Confirm the ruby-build git pull succeeded (see {LOG_PATH}).")

    # 5. Build, checking the result this time
    print("Installing Ruby 3.3.9 (compiles from source, several minutes)...")
    if not run_command(f"{rbenv_bin} install -s 3.3.9"):
        print("  ERROR: rbenv install 3.3.9 failed. Usual causes: stale "
              f"ruby-build definitions or a missing compile header (see {LOG_PATH}).")
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

def install_base_dependencies():
    global PIP
    print("Performing system update and upgrade before installing package dependencies...")
    run_command("sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq -o Dpkg::Options::=--force-confold")

    apt_packages = [
        "vim", "subversion", "landscape-common", "ufw", "openssh-server", "net-tools",
        "mlocate", "ntpdate", "screen", "whois", "libtool-bin", "make", "gcc", "ncftp",
        "rar", "p7zip-full", "curl", "libpcap-dev", "libssl-dev", "hping3", "libssh-dev",
        "g++", "arp-scan", "wifite", "ruby-bundler", "freerdp2-dev", "libsqlite3-dev",
        "nbtscan", "dsniff", "apache2", "secure-delete", "autoconf", "libpq-dev",
        "libmysqlclient-dev", "libsvn-dev", "libsmbclient-dev", "libgcrypt20-dev",
        "libbson-dev", "libmongoc-dev", "python3-pip", "netsniff-ng", "httptunnel",
        "ptunnel-ng", "udptunnel", "pipx", "python3-venv", "ruby-dev", "webhttrack",
        "minicom", "openjdk-21-jre", "gnome-tweaks", "macchanger", "recordmydesktop",
        "postgresql", "hydra-gtk", "hydra", "wine-development",
        "libcurl4-openssl-dev", "smbclient", "hackrf", "nfs-common", "samba", "gpsd",
        "snmp", "libsnmp-dev", "libsnmp-perl", "snmp-mibs-downloader", "docker.io",
        "docker-compose", "hcxtools", "httrack", "tshark", "git", "python-is-python3",
        "tig", "tftpd-hpa", "libimage-exiftool-perl", "wkhtmltopdf", "libffi-dev",
        "libyaml-dev", "libreadline-dev", "libncurses5-dev", "libgdbm-dev", "zlib1g-dev",
        "build-essential", "bison", "libedit-dev", "libxml2-utils", "automake", "libtool",
        "pkg-config", "libnl-3-dev", "libnl-genl-3-dev", "ethtool", "shtool", "rfkill",
        "libpcre3-dev", "libhwloc-dev", "libcmocka-dev", "hostapd", "wpasupplicant",
        "tcpdump", "iw", "usbutils", "python3-dnspython", "python3-aiofiles",
        "python3-watchdog", "python3-pandas"
    ]

    missing_apt = filter_uninstalled_apt(apt_packages)
    if missing_apt:
        print(f"Installing {len(missing_apt)} missing apt packages...")
        apt_install(missing_apt)
    else:
        print("All apt packages already installed, skipping.")

    # pip may have just been installed or upgraded; refresh the flag detection
    # so PEP 668 handling reflects the interpreter that is actually present.
    PIP = "pip3 install" + pip_flags()

    run_command("sudo usermod -aG docker $USER")
    run_command("sudo snap install powershell --classic")

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

    # Install each pipx package separately
    pipx_packages = ["urh", "scoutsuite", "checkov", "dnsrecon"]
    for package in pipx_packages:
        install_one("pipx", f"pipx install {package}", package)

    # impacket forced: it drops many scripts into ~/.local/bin that can collide
    # with stale copies from older installs; --force claims them cleanly
    install_one("pipx", "pipx install --force impacket", "impacket")

    # Install a current Go toolchain (see install_go), then point the
    # environment at it. GOROOT is /usr/local/go rather than a distro path so
    # the build tools all use the managed toolchain.
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
        run_command("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y")
        run_command('bash -c "source $HOME/.cargo/env"')

    # Install NetExec (skip if already present)
    netexec_check = subprocess.run("pipx list", shell=True, capture_output=True, text=True)
    if "netexec" in netexec_check.stdout.lower():
        print("NetExec already installed, skipping.")
    else:
        print("Installing NetExec...")
        run_command("pipx ensurepath")
        run_command("pipx install git+https://github.com/Pennyw0rth/NetExec")

    # Ruby via rbenv (self-contained and idempotent)
    install_ruby()

    # Check if CPANminus is installed
    if not os.path.isfile("/usr/local/bin/cpanm"):
        print("CPANminus not found. Installing CPANminus...")

        # Clone the cpanminus repository
        run_command("mkdir -p /vapt/temp")
        run_command("cd /vapt/temp && git clone https://github.com/miyagawa/cpanminus.git")

        # Navigate to the directory and install CPANminus
        run_command("cd /vapt/temp/cpanminus/App-cpanminus && perl Makefile.PL")
        run_command("cd /vapt/temp/cpanminus/App-cpanminus && make")
        run_command("cd /vapt/temp/cpanminus/App-cpanminus && sudo make install")

        # Cleanup after installation
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

    # bettercap (precompiled release binary; the source build needs a newer Go
    # than this toolkit installs. Runs as root for interface manipulation and
    # packet injection, so the binary is placed in /usr/local/bin)
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

    print("Base toolkit dependency install pass complete.")
    print_failure_summary()

# =============================================================================
# Replacement functions for vapt-installer.py to add katana.
# Replace the existing install_toolkit_packages() and update_toolsets()
# with the versions below. Only the katana entries are added; everything
# else is unchanged.
# =============================================================================

def install_toolkit_packages():
    # Put rbenv shims (Ruby 3.3.9), rbenv bin, and Go on PATH for this process.
    # rbenv shims first so Metasploit's bundle resolves the 3.3.9 Ruby pinned by
    # its .ruby-version rather than the system Ruby.
    os.environ['GOROOT'] = '/usr/local/go'
    os.environ.setdefault('GOPATH', os.path.expanduser('~/go'))
    os.environ['PATH'] = (
        f"{os.path.expanduser('~/.rbenv/shims')}:"
        f"{os.path.expanduser('~/.rbenv/bin')}:"
        f"/usr/local/go/bin:{os.path.expanduser('~/go/bin')}:"
        f"{os.environ.get('PATH', '')}"
    )
    print("Installing toolkit packages...")

    # Define installations for exploitation tools
    exploitation_tools = [
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
        ("https://github.com/assetnote/kiterunner.git", "/vapt/web/kiterunner", ["make build"]),
        ("https://github.com/projectdiscovery/httpx.git", "/vapt/web/httpx", ["/usr/local/go/bin/go install ./cmd/httpx"]),
        ("https://github.com/ffuf/ffuf.git", "/vapt/web/ffuf", ["/usr/local/go/bin/go build"]),
        ("https://github.com/maurosoria/dirsearch.git", "/vapt/web/dirsearch", None),
        ("https://github.com/MatheuZSecurity/D3m0n1z3dShell.git", "/vapt/exploits/D3m0n1z3dShell", ["chmod +x demonizedshell.sh"])
    ]

    # Metasploit Framework (vendored bundle install to avoid system gem path / sudo)
    msf_dir = "/vapt/exploits/metasploit-framework"
    if os.path.exists(msf_dir):
        print("Metasploit Framework already installed, skipping.")
    else:
        print("Installing Metasploit Framework")
        run_command(f"git clone https://github.com/rapid7/metasploit-framework.git {msf_dir}")
        # pin MSF to the rbenv Ruby this installer provides (3.3.9), not the upstream .ruby-version
        run_command(f"echo '3.3.9' > {msf_dir}/.ruby-version")
        run_command(f"cd {msf_dir} && bundle config set --local path vendor/bundle")
        run_command(f"cd {msf_dir} && bundle install")

    # Container and cloud security tools
    container_cloud_tools = [
        ("https://github.com/aquasecurity/trivy.git", "/vapt/cloud/trivy", None),
        ("https://github.com/RhinoSecurityLabs/pacu.git", "/vapt/cloud/pacu", ["pipx install /vapt/cloud/pacu"]),
    ]

    # Define installations for web testing tools
    web_tools = [
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
    ]

    # Active Directory and Windows security tools
    ad_windows_tools = [
       ("https://github.com/BloodHoundAD/BloodHound.git", "/vapt/ad_windows/BloodHound", None),
       ("https://github.com/mattifestation/PowerSploit.git", "/vapt/ad_windows/PowerSploit", None),
       ("https://github.com/CroweCybersecurity/ps1encode.git", "/vapt/ad_windows/ps1encode", None),
       ("https://github.com/Kevin-Robertson/Invoke-TheHash.git", "/vapt/ad_windows/Invoke-TheHash", None),
       ("https://github.com/p3nt4/PowerShdll.git", "/vapt/ad_windows/PowerShdll", None),
       ("https://github.com/GhostPack/Rubeus.git", "/vapt/ad_windows/Rubeus", None),
       ("https://github.com/dirkjanm/ldapdomaindump.git", "/vapt/ad_windows/ldapdomaindump", ["pipx install /vapt/ad_windows/ldapdomaindump"]),
       ("https://github.com/adityatelange/evil-winrm-py.git", "/vapt/ad_windows/evil-winrm-py", [f"sudo {PIP} ."]),
    ]

    # Mobile security testing tools
    mobile_tools = [
        ("https://github.com/MobSF/Mobile-Security-Framework-MobSF.git", "/vapt/mobile/MobSF", [f"{PIP} -r requirements.txt"]),
        ("https://github.com/sensepost/objection.git", "/vapt/mobile/objection", [f"{PIP} objection"]),
    ]

    # network and infrastructure tools
    network_tools = [
        ("https://github.com/robertdavidgraham/masscan.git", "/vapt/network/masscan", ["make"]),
        ("https://github.com/OWASP/Amass.git", "/vapt/network/Amass", ["/usr/local/go/bin/go install -v ./cmd/amass/..."]),
    ]

    # Password cracking tools
    jtr_dir = "/vapt/passwords/JohnTheRipper"
    if os.path.exists(jtr_dir):
        print("JohnTheRipper already installed, skipping.")
    else:
        print("Installing JohnTheRipper")
        run_command("cd /vapt/passwords && git clone https://github.com/magnumripper/JohnTheRipper.git")
        run_command("cd /vapt/passwords/JohnTheRipper/src && ./configure")
        run_command("cd /vapt/passwords/JohnTheRipper/src && make -s clean && make -sj4")
        run_command("cd /vapt/passwords/JohnTheRipper/src && make install")

    password_tools = [
        ("https://github.com/hashcat/hashcat.git", "/vapt/passwords/hashcat", None),
        ("https://github.com/digininja/CeWL.git", "/vapt/passwords/CeWL", None),
        ("https://github.com/danielmiessler/SecLists.git", "/vapt/passwords/SecLists", None)
    ]

    # Fuzzers
    fuzzer_tools = [
        ("https://github.com/jtpereyda/boofuzz.git", "/vapt/fuzzers/boofuzz", None)
    ]

    # Misc Audit tools
    audit_tools = [
        ("https://github.com/hausec/PowerZure.git", "/vapt/audit/PowerZure", None),
        ("https://github.com/PlumHound/PlumHound.git", "/vapt/audit/PlumHound", [f"{PIP} -r requirements.txt"]),
        ("https://github.com/wireghoul/graudit.git", "/vapt/audit/graudit", None),
    ]

    # Wireless Signal Analysis tools (git repos only; aircrack-ng is built separately below)
    wireless_tools = [
        # QtTinySA spectrum analyzer frontend
        (
            "https://github.com/g4ixt/QtTinySA.git",
            "/vapt/wireless/QtTinySA",
            [f"{PIP} -r requirements.txt"]
        ),

        # qspectrumanalyzer
        (
            "https://github.com/xmikos/qspectrumanalyzer.git",
            "/vapt/wireless/qspectrumanalyzer",
            [f"sudo {PIP} ."]
        ),
    ]

    # Aircrack-ng (source build; tarball, not a git repo)
    aircrack_dir = "/vapt/wireless/aircrack-ng-1.7"
    if os.path.exists(aircrack_dir):
        print("Aircrack-ng already installed, skipping.")
    else:
        print("Installing Aircrack-ng")
        run_command("cd /vapt/wireless && wget https://download.aircrack-ng.org/aircrack-ng-1.7.tar.gz")
        run_command("cd /vapt/wireless && tar -zxvf aircrack-ng-1.7.tar.gz")
        run_command(f"cd {aircrack_dir} && autoreconf -i")
        run_command(f"cd {aircrack_dir} && ./configure --with-experimental")
        run_command(f"cd {aircrack_dir} && make")
        run_command(f"cd {aircrack_dir} && sudo make install")
        run_command("sudo ldconfig")
        run_command("cd /vapt/wireless && rm -rf aircrack-ng-1.7.tar.gz")

    # OWASP ZAP installation
    zap_dir = "/vapt/web/zap"
    if os.path.exists(zap_dir):
        print("OWASP ZAP already installed, skipping.")
    else:
        print("Installing OWASP ZAP")
        run_command("cd /vapt/web && wget https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz")
        run_command("cd /vapt/web && tar xvf ZAP_2.17.0_Linux.tar.gz")
        run_command("cd /vapt/web && rm -rf ZAP_2.17.0_Linux.tar.gz")
        run_command("cd /vapt/web && mv ZAP_2.17.0/ zap/")

    # Vulnerability scanner tools
    vulnerability_scanners = [
        ("https://github.com/sqlmapproject/sqlmap.git", "/vapt/scanners/sqlmap", None),
        ("https://github.com/nmap/nmap.git", "/vapt/scanners/nmap", ["./configure --without-zenmap", "make", "sudo make install"]),
        ("https://github.com/makefu/dnsmap.git", "/vapt/scanners/dnsmap", ["gcc -o dnsmap dnsmap.c"]),
        ("https://github.com/fwaeytens/dnsenum.git", "/vapt/scanners/dnsenum", None),
        ("https://github.com/nccgroup/cisco-SNMP-enumeration.git", "/vapt/scanners/cisco-SNMP-enumeration", None),
        ("https://github.com/aas-n/spraykatz.git", "/vapt/scanners/spraykatz", [f"{PIP} -r requirements.txt"]),
        ("https://github.com/p0dalirius/pyFindUncommonShares.git", "/vapt/scanners/pyFindUncommonShares", [f"{PIP} -r requirements.txt"]),
        ("https://github.com/CiscoCXSecurity/enum4linux.git", "/vapt/scanners/enum4linux", None)
    ]

    # OSINT/Intel tools
    osint_tools = [
        ("https://github.com/lanmaster53/recon-ng.git", "/vapt/intel/recon-ng", [f"{PIP} -r REQUIREMENTS"]),
        ("https://github.com/smicallef/spiderfoot.git", "/vapt/intel/spiderfoot", [f"{PIP} -r requirements.txt"]),
        ("https://github.com/laramies/theHarvester.git", "/vapt/intel/theHarvester", [f"{PIP} -r requirements.txt"]),
        ("https://github.com/nccgroup/scrying.git", "/vapt/intel/scrying", None),
        ("https://github.com/FortyNorthSecurity/EyeWitness.git", "/vapt/intel/EyeWitness", None),
        ("https://github.com/l4rm4nd/LinkedInDumper.git", "/vapt/intel/LinkedInDumper", [f"{PIP} -r requirements.txt"]),
        ("https://github.com/OsmanKandemir/indicator-intelligence.git", "/vapt/intel/indicator-intelligence", [f"{PIP} -r requirements.txt", f"sudo {PIP} ."])
    ]

    # Install all tools
    for tool in (exploitation_tools + web_tools + container_cloud_tools + ad_windows_tools +
                mobile_tools + network_tools + password_tools + fuzzer_tools +
                audit_tools + vulnerability_scanners + osint_tools + wireless_tools):
        check_and_install(*tool)

    print("Toolkit packages install pass complete.")
    print_failure_summary()

def update_toolsets():
    """Update all toolsets by performing a git pull in each directory."""
    # Refresh the managed Go toolchain first so any Go-based tool rebuilt during
    # this run (and anyone pulling toolkit updates) builds against current Go.
    install_go()
    os.environ['GOROOT'] = '/usr/local/go'
    os.environ.setdefault('GOPATH', os.path.expanduser('~/go'))
    go_paths = f"/usr/local/go/bin:{os.path.expanduser('~/go/bin')}"
    if go_paths not in os.environ.get('PATH', ''):
        os.environ['PATH'] = f"{go_paths}:{os.environ['PATH']}"

    print("Updating Exploit Tools")
    exploit_tools = [
        "/vapt/exploits/social-engineer-toolkit", "/vapt/exploits/metasploit-framework",
        "/vapt/exploits/ADFSpray", "/vapt/exploits/beef", "/vapt/exploits/DeathStar",
        "/vapt/exploits/mimikatz", "/vapt/exploits/Responder-NG",
        "/vapt/exploits/exploitdb", "/vapt/exploits/Covenant",
        "/vapt/exploits/SILENTTRINITY", "/vapt/exploits/D3m0n1z3dShell"
    ]
    for tool in exploit_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Web Tools")
    web_tools = [
        "/vapt/web/htshells", "/vapt/web/joomscan", "/vapt/web/nikto",
        "/vapt/web/php-webshells", "/vapt/web/watobo", "/vapt/web/WhatWeb",
        "/vapt/web/XSStrike", "/vapt/web/wapiti", "/vapt/web/Links-Extractor",
        "/vapt/web/kiterunner", "/vapt/web/dirsearch"
    ]
    for tool in web_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Container & Cloud Security Tools")
    container_cloud_tools = [
        "/vapt/cloud/trivy", "/vapt/cloud/pacu"
    ]
    for tool in container_cloud_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Active Directory & Windows Tools")
    ad_windows_tools = [
        "/vapt/ad_windows/BloodHound", "/vapt/ad_windows/PowerSploit", "/vapt/ad_windows/ps1encode",
        "/vapt/ad_windows/Invoke-TheHash", "/vapt/ad_windows/PowerShdll",
        "/vapt/ad_windows/Rubeus", "/vapt/ad_windows/ldapdomaindump", "/vapt/ad_windows/evil-winrm-py"
    ]
    for tool in ad_windows_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Mobile Security Tools")
    mobile_tools = [
        "/vapt/mobile/MobSF", "/vapt/mobile/objection"
    ]
    for tool in mobile_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Network & Infrastructure Tools")
    network_tools = [
        "/vapt/network/masscan"
    ]
    for tool in network_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Password Tools")
    password_tools = [
        "/vapt/passwords/JohnTheRipper", "/vapt/passwords/hashcat",
        "/vapt/passwords/CeWL", "/vapt/passwords/SecLists"
    ]
    for tool in password_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Fuzzer Tools")
    fuzzer_tools = [
        "/vapt/fuzzers/boofuzz"
    ]
    for tool in fuzzer_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Audit Tools")
    audit_tools = [
        "/vapt/audit/PowerZure", "/vapt/audit/PlumHound", "/vapt/audit/graudit"
    ]
    for tool in audit_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Vulnerability Scanners")
    # fierce is a pip package, not a cloned repo, so it is not pulled here.
    vulnerability_scanners = [
        "/vapt/scanners/sqlmap", "/vapt/scanners/nmap",
        "/vapt/scanners/dnsmap", "/vapt/scanners/dnsenum",
        "/vapt/scanners/cisco-SNMP-enumeration", "/vapt/scanners/spraykatz",
        "/vapt/scanners/pyFindUncommonShares", "/vapt/scanners/enum4linux"
    ]
    for tool in vulnerability_scanners:
        run_command(f"cd {tool} && git pull")

    print("Updating OSINT/Intel Tools")
    osint_tools = [
        "/vapt/intel/recon-ng", "/vapt/intel/spiderfoot", "/vapt/intel/theHarvester",
        "/vapt/intel/scrying", "/vapt/intel/EyeWitness", "/vapt/intel/LinkedInDumper",
        "/vapt/intel/indicator-intelligence"
    ]
    for tool in osint_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Wireless Signal Analysis Tools")
    wireless_tools = [
        "/vapt/wireless/QtTinySA", "/vapt/wireless/qspectrumanalyzer"
    ]
    for tool in wireless_tools:
        run_command(f"cd {tool} && git pull")

    # Go-based tools: pull each one, and rebuild only when the pull actually
    # brought in changes. A repo already up to date is left alone so the update
    # does not burn time recompiling unchanged source. These are handled here
    # rather than in the plain git-pull loops above so each is pulled once.
    print("Updating Go-based tools")
    go_tools = [
        ("httpx",  "/vapt/web/httpx",      "/usr/local/go/bin/go install ./cmd/httpx"),
        ("ffuf",   "/vapt/web/ffuf",       "/usr/local/go/bin/go build"),
        ("amass",  "/vapt/network/Amass",  "/usr/local/go/bin/go install -v ./cmd/amass/..."),
        ("merlin", "/vapt/exploits/merlin",
         "sed -i '/^toolchain/d' go.mod && PATH=/usr/local/go/bin:$PATH /usr/local/go/bin/go mod tidy && PATH=/usr/local/go/bin:$PATH make"),
        ("nuclei", "/vapt/web/nuclei",
         "/usr/local/go/bin/go build -o nuclei ./cmd/nuclei && sudo install -m 755 nuclei /usr/local/bin/nuclei"),
        ("katana", "/vapt/web/katana",
         "/usr/local/go/bin/go build -o katana ./cmd/katana && sudo install -m 755 katana /usr/local/bin/katana"),
    ]
    for name, path, build in go_tools:
        if not os.path.exists(path):
            continue
        if git_pull_changed(path):
            print(f"  {name}: changes pulled, rebuilding")
            run_command(f"cd {path} && {build}")
        else:
            print(f"  {name}: already up to date, skipping rebuild")

    # bettercap ships as a precompiled release binary, so updating pulls the
    # latest release over the existing binary rather than doing a git pull
    print("Updating bettercap")
    run_command("cd /tmp && curl -sL -o bettercap.zip https://github.com/bettercap/bettercap/releases/latest/download/bettercap_linux_amd64.zip")
    run_command("cd /tmp && 7z x bettercap.zip -y")
    run_command("cd /tmp && sudo install -m 755 bettercap /usr/local/bin/bettercap")
    run_command("cd /tmp && rm -f bettercap.zip bettercap bettercap_linux_amd64.sha256")

    print("Updating all pipx installed tool")
    run_command("pipx upgrade-all")

    print("Updating VA-PT")
    run_command("cd /vapt/misc/va-pt && git pull")

    print("Toolsets update complete.")

def main_menu():
    # Ensure directory structure is in place
    check_directory_structure()

    # Run cleanup for old installations
    cleanup_old_directories()

    while True:
        print("\033[91m1 - Install Base Toolkit Dependencies\033[0m")
        print("\033[91m2 - Install Toolkit Packages\033[0m")
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
