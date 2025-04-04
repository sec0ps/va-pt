import os
import subprocess
import sys

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
        f"{base_path}/powershell", f"{base_path}/exfiltrate"
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
    run_command("sudo apt install -y webhttrack minicom default-jre gnome-tweaks macchanger recordmydesktop postgresql golang-go hydra-gtk hydra")
    run_command("sudo apt install -y ncftp wine-development libcurl4-openssl-dev smbclient hackrf nfs-common samba")
    run_command("sudo snap install powershell --classic")
    run_command("sudo snap install crackmapexec")

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
    
    print("Installing Python Packages and Dependencies")
    run_command("pip3 install build dnspython kerberoast certipy-ad knowsmore sherlock-project")
    run_command("pipx install urh")
    run_command("python -m pip install dnspython==1.16.0")
    
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
        ("https://github.com/MatheuZSecurity/D3m0n1z3dShell.git", "/vapt/exploits/D3m0n1z3dShell", ["chmod +x demonizedshell.sh"])
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

    # Powershell tools
    powershell_tools = [
        ("https://github.com/mattifestation/PowerSploit.git", "/vapt/powershell/PowerSploit", None),
        ("https://github.com/CroweCybersecurity/ps1encode.git", "/vapt/powershell/ps1encode", None),
        ("https://github.com/Kevin-Robertson/Invoke-TheHash.git", "/vapt/powershell/Invoke-TheHash", None),
        ("https://github.com/p3nt4/PowerShdll.git", "/vapt/powershell/PowerShdll", None)
    ]

    # Misc Audit tools
    audit_tools = [
        ("https://github.com/hausec/PowerZure.git", "/vapt/audit/PowerZure", None),
        ("https://github.com/PlumHound/PlumHound.git", "/vapt/audit/PlumHound", ["pip3 install -r requirements.txt"]),
        ("https://github.com/wireghoul/graudit.git", "/vapt/audit/graudit", None),
        ("https://github.com/TerminalFi/NessusParser-Excel.git", "/vapt/audit/NessusParser-Excel", ["pip install -r requirements.txt"])
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
        run_command("cd /vapt/web && wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz")
        run_command("cd /vapt/web && tar xvf ZAP_2.15.0_Linux.tar.gz")
        run_command("cd /vapt/web && rm -rf ZAP_2.15.0_Linux.tar.gz")
        run_command("cd /vapt/web && mv ZAP_2.15.0/ zap/")

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
        ("https://github.com/darkoperator/dnsrecon.git", "/vapt/scanners/dnsrecon", ["pip install -r requirements.txt"]),
        ("https://github.com/sqlmapproject/sqlmap.git", "/vapt/scanners/sqlmap", None),
        ("https://github.com/nmap/nmap.git", "/vapt/scanners/nmap", ["./configure", "make", "sudo make install"]),
        ("https://github.com/mschwager/fierce.git", "/vapt/scanners/fierce", ["python3 -m pip install -r requirements.txt", "sudo python3 setup.py install"]),
        ("https://github.com/makefu/dnsmap.git", "/vapt/scanners/dnsmap", ["gcc -o dnsmap dnsmap.c"]),
        ("https://github.com/fwaeytens/dnsenum.git", "/vapt/scanners/dnsenum", None),
        ("https://github.com/nccgroup/cisco-SNMP-enumeration.git", "/vapt/scanners/cisco-SNMP-enumeration", None),
        ("https://github.com/aas-n/spraykatz.git", "/vapt/scanners/spraykatz", ["pip3 install -r requirements.txt"]),
        ("https://github.com/p0dalirius/FindUncommonShares.git", "/vapt/scanners/FindUncommonShares", ["pip install -r requirements.txt"]),
        ("https://github.com/CiscoCXSecurity/enum4linux.git", "/vapt/scanners/enum4linux", None)
    ]
    
    # OSINT/Intel tools
    osint_tools = [
        ("https://github.com/lanmaster53/recon-ng.git", "/vapt/intel/recon-ng", ["pip3 install -r REQUIREMENTS"]),
        ("https://github.com/smicallef/spiderfoot.git", "/vapt/intel/spiderfoot", ["pip3 install -r requirements.txt"]),
        ("https://github.com/laramies/theHarvester.git", "/vapt/intel/theHarvester", ["pip3 install -r requirements.txt"]),
        ("https://github.com/nccgroup/scrying.git", "/vapt/intel/scrying", None),
        ("https://github.com/FortyNorthSecurity/EyeWitness.git", "/vapt/intel/EyeWitness", None),
        ("https://github.com/adnane-X-tebbaa/GRecon.git", "/vapt/intel/GRecon", ["python3 -m pip install -r requirements.txt"]),
        ("https://github.com/l4rm4nd/LinkedInDumper.git", "/vapt/intel/LinkedInDumper", ["pip install -r requirements.txt"]),
        ("https://github.com/OsmanKandemir/indicator-intelligence.git", "/vapt/intel/indicator-intelligence", ["pip3 install -r requirements.txt", "sudo python3 setup.py install"])
    ]

    # Install all other tools
    for tool in (exploitation_tools + web_tools + password_tools + fuzzer_tools + powershell_tools + audit_tools + vulnerability_scanners + osint_tools + wireless_tools):
        check_and_install(*tool)

    print("Toolkit packages installation complete.")

def update_toolsets():
    """Update all toolsets by performing a git pull in each directory."""
    print("Updating Exploit Tools")
    exploit_tools = [
        "/vapt/exploits/social-engineer-toolkit", "/vapt/exploits/metasploit-framework",
        "/vapt/exploits/ADFSpray", "/vapt/exploits/beef", "/vapt/exploits/DeathStar",
        "/vapt/exploits/impacket", "/vapt/exploits/mimikatz", "/vapt/exploits/Responder",
        "/vapt/exploits/exploitdb"
    ]
    for tool in exploit_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Web Tools")
    web_tools = [
        "/vapt/web/htshells", "/vapt/web/joomscan", "/vapt/web/nikto",
        "/vapt/web/php-webshells", "/vapt/web/watobo", "/vapt/web/WhatWeb",
        "/vapt/web/XSStrike", "/vapt/web/wapiti"
    ]
    for tool in web_tools:
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

    print("Updating Powershell Tools")
    powershell_tools = [
        "/vapt/powershell/PowerSploit", "/vapt/powershell/ps1encode",
        "/vapt/powershell/Invoke-TheHash", "/vapt/powershell/PowerShdll"
    ]
    for tool in powershell_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Audit Tools")
    audit_tools = [
        "/vapt/audit/PowerZure", "/vapt/audit/PlumHound", "/vapt/audit/graudit",
        "/vapt/audit/NessusParser-Excel"
    ]
    for tool in audit_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Vulnerability Scanners")
    vulnerability_scanners = [
        "/vapt/scanners/dnsrecon", "/vapt/scanners/sqlmap", "/vapt/scanners/nmap",
        "/vapt/scanners/fierce", "/vapt/scanners/dnsmap", "/vapt/scanners/dnsenum",
        "/vapt/scanners/cisco-SNMP-enumeration", "/vapt/scanners/spraykatz",
        "/vapt/scanners/FindUncommonShares", "/vapt/scanners/enum4linux"
    ]
    for tool in vulnerability_scanners:
        run_command(f"cd {tool} && git pull")

    print("Updating OSINT/Intel Tools")
    osint_tools = [
        "/vapt/intel/recon-ng", "/vapt/intel/spiderfoot", "/vapt/intel/theHarvester",
        "/vapt/intel/scrying", "/vapt/intel/EyeWitness", "/vapt/intel/GRecon",
        "/vapt/intel/LinkedInDumper", "/vapt/intel/indicator-intelligence"
    ]
    for tool in osint_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating Wireless Signal Analysis Tools")
    wireless_tools = [
        "/vapt/wireless/QtTinySA", "/vapt/wireless/qspectrumanalyzer"
    ]
    for tool in wireless_tools:
        run_command(f"cd {tool} && git pull")

    print("Updating VA-PT")
    run_command("cd /vapt/misc/va-pt && git pull")

    print("Toolsets update complete.")

def main_menu():
    # Ensure directory structure is in place
    check_directory_structure()
    
    while True:
        print("\033[91m1 - Install Base Toolkit Dependencies\033[0m")
        print("\033[91m2 - Install Toolkit Packages\033[0m")
        print("\033[91m3 - Install Weakpass Dictionary for Password Cracking (30G)\033[0m")
        print("\033[91m4 - Install OpenVAS\033[0m")
        print("\033[91m5 - Update Toolsets\033[0m")
        print("\033[91m0 - Exit\033[0m")

        choice = input("Enter your choice: ")

        if choice == '1':
            install_base_dependencies()
        elif choice == '2':
            install_toolkit_packages()
        elif choice == '3':
            install_wordlist_files()
        elif choice == '4':
            install_openvas()
        elif choice == '5':
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
