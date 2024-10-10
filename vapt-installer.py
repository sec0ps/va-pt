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

def check_and_install(repo_url, install_dir, setup_commands=None):
    """Clone the repo if it doesn't exist and run optional setup commands."""
    if not os.path.exists(install_dir):
        print(f"Installing {os.path.basename(install_dir)}")
        run_command(f"git clone {repo_url} {install_dir}")
        if setup_commands:
            for command in setup_commands:
                run_command(f"cd {install_dir} && {command}")

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
    
    # Set up firewall rules
    run_command("sudo ufw default deny incoming")
    run_command("sudo ufw default allow outgoing")
    run_command("sudo ufw allow 22/tcp")
    run_command("sudo ufw enable")

    print("Base toolkit dependencies installed successfully.")

def install_toolkit_packages():
    print("Installing toolkit packages...")
    exploitation_tools = [
        ("https://github.com/rapid7/metasploit-framework.git", "/vapt/exploits/metasploit-framework", ["bundle install"]),
        ("https://github.com/trustedsec/social-engineer-toolkit.git", "/vapt/exploits/social-engineer-toolkit", ["pip3 install -r requirements.txt"]),
        ("https://github.com/offensive-security/exploit-database.git", "/vapt/exploits/exploit-database", None),
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

    # OWASP ZAP installation
    print("Installing OWASP ZAP")
    run_command("cd /vapt/web && wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz")
    run_command("cd /vapt/web && tar xvf ZAP_2.15.0_Linux.tar.gz")
    run_command("cd /vapt/web && rm -rf ZAP_2.15.0_Linux.tar.gz")
    run_command("cd /vapt/web && mv ZAP* zap/")

    # Install all other tools
    for tool in (exploitation_tools + web_tools):
        check_and_install(*tool)

    print("Toolkit packages installation complete.")

def update_toolsets():
    """Update all toolsets by performing a git pull in each directory."""
    print("Updating Exploit Tools")
    exploit_tools = [
        "/vapt/exploits/social-engineer-toolkit", "/vapt/exploits/metasploit-framework",
        "/vapt/exploits/ADFSpray", "/vapt/exploits/beef", "/vapt/exploits/DeathStar",
        "/vapt/exploits/impacket", "/vapt/exploits/mimikatz", "/vapt/exploits/Responder"
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

    print("Updating VA-PT")
    run_command("cd /vapt/misc/va-pt && git pull")

    print("Toolsets update complete.")

def main_menu():
    while True:
        print("\033[91m1 - Install Base Toolkit Dependencies\033[0m")
        print("\033[91m2 - Install Toolkit Packages\033[0m")
        print("\033[91m3 - Install Wordlist Files for Password Cracking\033[0m")
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
