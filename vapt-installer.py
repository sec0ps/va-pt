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
import subprocess
import sys
import re

def run_command(command):
    """Execute a command in the shell, and continue even if an error occurs."""
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\033[91mError occurred while executing: {command}\033[0m")
        print(f"\033[91mError details: {e}\033[0m")
        print("Continuing with the next command...\n")

def display_logo():
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
    print(logo_ascii)

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

def check_and_install(repo_url, install_dir, setup_commands=None):
    """Clone the repo if it doesn't exist and run optional setup commands."""
    if not os.path.exists(install_dir):
        print(f"Installing {os.path.basename(install_dir)}")
        run_command(f"git clone {repo_url} {install_dir}")
        if setup_commands:
            for command in setup_commands:
                run_command(f"cd {install_dir} && {command}")

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

def install_base_dependencies():
    print("Installing base toolkit dependencies...")
    run_command("sudo apt update && sudo apt upgrade -y")
    run_command("sudo apt install -y vim subversion landscape-common ufw openssh-server net-tools mlocate ntpdate screen whois libtool-bin")
    run_command("sudo apt install -y make gcc ncftp rar p7zip-full curl libpcap-dev libssl-dev hping3 libssh-dev g++ arp-scan wifite ruby-bundler freerdp2-dev")
    run_command("sudo apt install -y libsqlite3-dev nbtscan dsniff apache2 secure-delete autoconf libpq-dev libmysqlclient-dev libsvn-dev libssh-dev libsmbclient-dev")
    run_command("sudo apt install -y libgcrypt-dev libbson-dev libmongoc-dev python3-pip netsniff-ng httptunnel ptunnel-ng udptunnel pipx python3-venv ruby-dev")
    run_command("sudo apt install -y webhttrack minicom openjdk-21-jre gnome-tweaks macchanger recordmydesktop postgresql golang-1.23-go hydra-gtk hydra")
    run_command("sudo apt install -y ncftp wine-development libcurl4-openssl-dev smbclient hackrf nfs-common samba gpsd")
    run_command("sudo apt install -y docker.io docker-compose hcxtools httrack tshark git python-is-python3 tig")
    run_command("sudo apt install -y libffi-dev libyaml-dev libreadline-dev libncurses5-dev libgdbm-dev zlib1g-dev build-essential bison libedit-dev libxml2-utils")
    run_command("sudo usermod -aG docker $USER")
    run_command("sudo snap install powershell --classic")
    #Adding these in for the eventual move to Ubuntu 24+
    run_command("sudo apt install -y python3-aiofiles python3-watchdog python3-pandas")

    print("Installing Python Packages and Dependencies")
    run_command("pip3 install build dnspython kerberoast certipy-ad knowsmore sherlock-project wafw00f pypykatz")
    run_command("python -m pip install dnspython==1.16.0")

    # Install each pipx package separately
    pipx_packages = ["urh", "scoutsuite", "checkov", "impacket", "dnsrecon"]
    for package in pipx_packages:
        run_command(f"pipx install {package}")

    # Configure Go environment
    go_config = """
    # Go programming language
    export PATH=$PATH:/usr/lib/go-1.23/bin
    export GOROOT=/usr/lib/go-1.23
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    """

    bashrc_path = os.path.expanduser("~/.bashrc")
    with open(bashrc_path, 'r') as f:
        if 'go-1.23' not in f.read():
            with open(bashrc_path, 'a') as f:
                f.write(go_config)
            print("Go environment configured. Changes will apply to new shells.")
            os.environ['PATH'] += f":/usr/lib/go-1.23/bin:{os.path.expanduser('~/go/bin')}"

    # Install Rust and NetExec
    print("Installing Rust and NetExec...")
    run_command("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y")
    run_command('bash -c "source $HOME/.cargo/env"')
    run_command("pipx ensurepath")
    run_command("pipx install git+https://github.com/Pennyw0rth/NetExec")

    print("Checking Ruby version...")

    # Check if Ruby 3.3.9 is already installed and active
    ruby_check = subprocess.run("ruby -v", shell=True, capture_output=True, text=True)
    if ruby_check.returncode == 0 and "3.3.9" in ruby_check.stdout:
        print("Ruby 3.3.9 already installed and active, skipping.")
    else:
            # Check if rbenv exists in the expected location instead of just checking PATH
            rbenv_path = os.path.expanduser("~/.rbenv/bin/rbenv")
            if not os.path.exists(rbenv_path):
                print("Installing rbenv...")
                run_command("curl -fsSL https://github.com/rbenv/rbenv-installer/raw/HEAD/bin/rbenv-installer | bash")
                run_command('grep -q "rbenv init" ~/.bashrc || echo \'export PATH="$HOME/.rbenv/bin:$PATH"\' >> ~/.bashrc')
                run_command('grep -q "rbenv init" ~/.bashrc || echo \'eval "$(rbenv init - bash)"\' >> ~/.bashrc')
                # Source rbenv in the current session
                os.environ['PATH'] = f"{os.path.expanduser('~/.rbenv/bin')}:{os.environ.get('PATH', '')}"
                print("rbenv installed and configured.")

            print("Installing Ruby 3.3.9...")
            # Use the full path to rbenv if it's not in PATH yet
            rbenv_cmd = rbenv_path if os.path.exists(rbenv_path) else "rbenv"
            run_command(f"{rbenv_cmd} install -s 3.3.9")  # -s flag skips if already installed
            run_command(f"{rbenv_cmd} global 3.3.9")
            run_command(f"{rbenv_cmd} rehash")
            print("Ruby 3.3.9 installed. Restart terminal or run: source ~/.bashrc")

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
    run_command("sudo cpanm Cisco::CopyConfig && sudo cpanm Net::Netmask")
    run_command("sudo cpanm XML::Writer && sudo cpanm String::Random")
    run_command("sudo cpanm Net::IP && sudo cpanm Net::DNS")

    # Set up firewall rules
    run_command("sudo ufw default deny incoming")
    run_command("sudo ufw default allow outgoing")
    run_command("sudo ufw allow 22/tcp")
    run_command("sudo ufw enable")

    print("Base toolkit dependencies installed successfully.")

def install_toolkit_packages():
    print("Installing toolkit packages...")

    # Define installations for exploitation tools
    exploitation_tools = [
        ("https://github.com/rapid7/metasploit-framework.git", "/vapt/exploits/metasploit-framework", ["bundle install"]),
        ("https://github.com/trustedsec/social-engineer-toolkit.git", "/vapt/exploits/social-engineer-toolkit", ["pip3 install -r requirements.txt"]),
        ("https://gitlab.com/exploit-database/exploitdb.git", "/vapt/exploits/exploitdb", None),
        ("https://github.com/lgandx/Responder.git", "/vapt/exploits/Responder", None),
        ("https://github.com/CoreSecurity/impacket.git", "/vapt/exploits/impacket", ["pip3 install -r requirements.txt", "sudo python3 setup.py install"]),
        ("https://github.com/beefproject/beef.git", "/vapt/exploits/beef", None),
        ("https://github.com/xFreed0m/ADFSpray.git", "/vapt/exploits/ADFSpray", ["pip3 install -r requirements.txt"]),
        ("https://github.com/gentilkiwi/mimikatz.git", "/vapt/exploits/mimikatz", None),
        ("https://github.com/byt3bl33d3r/DeathStar.git", "/vapt/exploits/DeathStar", ["pip3 install -r requirements.txt"]),
        ("https://github.com/cobbr/Covenant.git", "/vapt/exploits/Covenant", None),
        ("https://github.com/Ne0nd0g/merlin.git", "/vapt/exploits/merlin", ["sed -i 's/go 1.23.0/go 1.23/' go.mod", "sed -i '/^toolchain/d' go.mod", "make"]),
        ("https://github.com/byt3bl33d3r/SILENTTRINITY.git", "/vapt/exploits/SILENTTRINITY", ["pip3 install -r requirements.txt"]),
        ("https://github.com/assetnote/kiterunner.git", "/vapt/web/kiterunner", ["make build"]),
        ("https://github.com/projectdiscovery/httpx.git", "/vapt/web/httpx", ["go install"]),
        ("https://github.com/ffuf/ffuf.git", "/vapt/web/ffuf", ["go build"]),
        ("https://github.com/maurosoria/dirsearch.git", "/vapt/web/dirsearch", None),
        ("https://github.com/MatheuZSecurity/D3m0n1z3dShell.git", "/vapt/exploits/D3m0n1z3dShell", ["chmod +x demonizedshell.sh"])
    ]

    # Container and cloud security tools
    container_cloud_tools = [
        ("https://github.com/aquasecurity/trivy.git", "/vapt/cloud/trivy", None),
        ("https://github.com/RhinoSecurityLabs/pacu.git", "/vapt/cloud/pacu", ["pipx install ."]),
    ]

    # Define installations for web testing tools
    web_tools = [
        ("https://github.com/sullo/nikto.git", "/vapt/web/nikto", None),
        ("https://github.com/JohnTroony/php-webshells.git", "/vapt/web/php-webshells", None),
        ("https://github.com/wireghoul/htshells.git", "/vapt/web/htshells", None),
        ("https://github.com/urbanadventurer/WhatWeb.git", "/vapt/web/WhatWeb", None),
        ("https://github.com/siberas/watobo.git", "/vapt/web/watobo", None),
        ("https://github.com/rezasp/joomscan.git", "/vapt/web/joomscan", None),
        ("https://github.com/s0md3v/XSStrike.git", "/vapt/web/XSStrike", ["python3 -m pip install -r requirements.txt"]),
        ("https://github.com/wapiti-scanner/wapiti.git", "/vapt/web/wapiti", ["sudo python3 setup.py install"]),
        ("https://github.com/com-puter-tips/Links-Extractor.git", "/vapt/web/Links-Extractor", ["pip3 install -r requirements.txt"]),
    ]

    # Active Directory and Windows security tools
    ad_windows_tools = [
       ("https://github.com/BloodHoundAD/BloodHound.git", "/vapt/ad_windows/BloodHound", None),
       ("https://github.com/mattifestation/PowerSploit.git", "/vapt/ad_windows/PowerSploit", None),
       ("https://github.com/CroweCybersecurity/ps1encode.git", "/vapt/ad_windows/ps1encode", None),
       ("https://github.com/Kevin-Robertson/Invoke-TheHash.git", "/vapt/ad_windows/Invoke-TheHash", None),
       ("https://github.com/p3nt4/PowerShdll.git", "/vapt/ad_windows/PowerShdll", None),
       ("https://github.com/GhostPack/Rubeus.git", "/vapt/ad_windows/Rubeus", None),
       ("https://github.com/dirkjanm/ldapdomaindump.git", "/vapt/ad_windows/ldapdomaindump", ["pipx install ."]),
       ("https://github.com/adityatelange/evil-winrm-py.git", "/vapt/ad_windows/evil-winrm-py", ["sudo python3 setup.py install"]),
    ]

    # Mobile security testing tools
    mobile_tools = [
        ("https://github.com/MobSF/Mobile-Security-Framework-MobSF.git", "/vapt/mobile/MobSF", ["pip3 install -r requirements.txt"]),
        ("https://github.com/sensepost/objection.git", "/vapt/mobile/objection", ["pip3 install objection"]),
    ]

    # network and infrastructure tools
    network_tools = [
        ("https://github.com/robertdavidgraham/masscan.git", "/vapt/network/masscan", ["make"]),
        ("https://github.com/projectdiscovery/nuclei.git", "/vapt/network/nuclei", None),
        ("https://github.com/OWASP/Amass.git", "/vapt/network/Amass", ["go install -v ./cmd/amass/..."]),
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
        ("https://github.com/PlumHound/PlumHound.git", "/vapt/audit/PlumHound", ["pip3 install -r requirements.txt"]),
        ("https://github.com/wireghoul/graudit.git", "/vapt/audit/graudit", None),
    ]

    # Wireless Signal Analysis tools
    wireless_tools = [
        ("https://github.com/g4ixt/QtTinySA.git", "/vapt/wireless/QtTinySA", ["pip3 install -r requirements.txt"]),
        ("https://github.com/xmikos/qspectrumanalyzer.git", "/vapt/wireless/qspectrumanalyzer", ["sudo python3 setup.py install"])
    ]

    # OWASP ZAP installation
    zap_dir = "/vapt/web/zap"
    if os.path.exists(zap_dir):
        print("OWASP ZAP already installed, skipping.")
    else:
        print("Installing OWASP ZAP")
        run_command("cd /vapt/web && wget https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Linux.tar.gz")
        run_command("cd /vapt/web && tar xvf ZAP_2.16.1_Linux.tar.gz")
        run_command("cd /vapt/web && rm -rf ZAP_ZAP_2.16.1_Linux.tar.gz")
        run_command("cd /vapt/web && mv ZAP_2.16.1/ zap/")

    # Arachni installation
    arachni_dir = "/vapt/web/arachni"
    if os.path.exists(arachni_dir):
        print("Arachni already installed, skipping.")
    else:
        print("Installing Arachni")
        run_command("cd /vapt/web && wget https://github.com/Arachni/arachni/releases/download/v1.6.1.3/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz")
        run_command("cd /vapt/web && tar xvf arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz")
        run_command("cd /vapt/web && mv arachni-1.6.1.3-0.6.1.1/ arachni/")
        run_command("cd /vapt/web && rm -rf arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz")

    # Vulnerability scanner tools
    vulnerability_scanners = [
        ("https://github.com/sqlmapproject/sqlmap.git", "/vapt/scanners/sqlmap", None),
        ("https://github.com/nmap/nmap.git", "/vapt/scanners/nmap", ["./configure", "make", "sudo make install"]),
        ("https://github.com/mschwager/fierce.git", "/vapt/scanners/fierce", ["python3 -m pip install -r requirements.txt", "sudo python3 setup.py install"]),
        ("https://github.com/makefu/dnsmap.git", "/vapt/scanners/dnsmap", ["gcc -o dnsmap dnsmap.c"]),
        ("https://github.com/fwaeytens/dnsenum.git", "/vapt/scanners/dnsenum", None),
        ("https://github.com/nccgroup/cisco-SNMP-enumeration.git", "/vapt/scanners/cisco-SNMP-enumeration", None),
        ("https://github.com/aas-n/spraykatz.git", "/vapt/scanners/spraykatz", ["pip3 install -r requirements.txt"]),
        ("https://github.com/p0dalirius/pyFindUncommonShares.git", "/vapt/scanners/pyFindUncommonShares", ["pip install -r requirements.txt"]),
        ("https://github.com/CiscoCXSecurity/enum4linux.git", "/vapt/scanners/enum4linux", None)
    ]

    # OSINT/Intel tools
    osint_tools = [
        ("https://github.com/lanmaster53/recon-ng.git", "/vapt/intel/recon-ng", ["pip3 install -r REQUIREMENTS"]),
        ("https://github.com/smicallef/spiderfoot.git", "/vapt/intel/spiderfoot", ["pip3 install -r requirements.txt"]),
        ("https://github.com/laramies/theHarvester.git", "/vapt/intel/theHarvester", ["pip3 install -r requirements.txt"]),
        ("https://github.com/nccgroup/scrying.git", "/vapt/intel/scrying", None),
        ("https://github.com/FortyNorthSecurity/EyeWitness.git", "/vapt/intel/EyeWitness", None),
        ("https://github.com/l4rm4nd/LinkedInDumper.git", "/vapt/intel/LinkedInDumper", ["pip install -r requirements.txt"]),
        ("https://github.com/OsmanKandemir/indicator-intelligence.git", "/vapt/intel/indicator-intelligence", ["pip3 install -r requirements.txt", "sudo python3 setup.py install"])
    ]

    # Install all tools
    for tool in (exploitation_tools + web_tools + container_cloud_tools + ad_windows_tools +
                mobile_tools + network_tools + password_tools + fuzzer_tools +
                audit_tools + vulnerability_scanners + osint_tools + wireless_tools):
        check_and_install(*tool)

    print("Toolkit packages installation complete.")

def update_toolsets():
    """Update all toolsets by performing a git pull in each directory."""
    print("Updating Exploit Tools")
    exploit_tools = [
        "/vapt/exploits/social-engineer-toolkit", "/vapt/exploits/metasploit-framework",
        "/vapt/exploits/ADFSpray", "/vapt/exploits/beef", "/vapt/exploits/DeathStar",
        "/vapt/exploits/impacket", "/vapt/exploits/mimikatz", "/vapt/exploits/Responder",
        "/vapt/exploits/exploitdb", "/vapt/exploits/Covenant", "/vapt/exploits/merlin",
        "/vapt/exploits/SILENTTRINITY", "/vapt/exploits/D3m0n1z3dShell"
    ]
    for tool in exploit_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Web Tools")
    web_tools = [
        "/vapt/web/htshells", "/vapt/web/joomscan", "/vapt/web/nikto",
        "/vapt/web/php-webshells", "/vapt/web/watobo", "/vapt/web/WhatWeb",
        "/vapt/web/XSStrike", "/vapt/web/wapiti", "/vapt/web/Links-Extractor",
        "/vapt/web/kiterunner", "/vapt/web/httpx", "/vapt/web/ffuf",
        "/vapt/web/dirsearch"
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
        "/vapt/network/masscan", "/vapt/network/nuclei", "/vapt/network/Amass"
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
    vulnerability_scanners = [
        "/vapt/scanners/sqlmap", "/vapt/scanners/nmap",
        "/vapt/scanners/fierce", "/vapt/scanners/dnsmap", "/vapt/scanners/dnsenum",
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

    display_logo()
    main_menu()
