import os
import sys
import json
import time
import logging
import requests
import re
import socket
import subprocess
import shutil
import ssl
import ipaddress
from tqdm import tqdm
from cryptography.fernet import Fernet
from ipaddress import ip_network
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import subprocess
import xml.etree.ElementTree as ET
from web import *
from utils import check_target_defined, change_target
from nmap import *
from sql import *
from config import LOG_DIR, LOG_FILE, find_sqlmap, find_nikto, TARGET_FILE, find_zap

def is_valid_url(url):
    """Validate a given URL."""
    parsed_url = urlparse(url)
    return all([parsed_url.scheme, parsed_url.netloc])

def check_target_defined():
    display_logo()
    """Check if the target is defined in the configuration file."""
    data = get_encrypted_data()
    target = data.get("target")
    if target:
        logging.info(f"Target is set: {target}")
        return target
    else:
        target = input("Enter target (IP, FQDN, or Netblock): ").strip()
        encrypt_and_store_data("target", target)
        return target

def check_web_service(ip):
    """Determine if the given IP has an active web service and return the correct URL."""
    ports = [(443, "https"), (80, "http")]  # Prioritize HTTPS first
    for port, scheme in ports:
        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                detected_url = f"{scheme}://{ip}:{port}"
                logging.info(f"✅ Secure web service detected: {detected_url}")
                return detected_url  # Return single string instead of a list
        except (socket.timeout, ConnectionRefusedError):
            continue  # Try the next port

    return None  # Return None if no web service is found

def full_automation():
    logging.info("Running full automation...")

def automated_network_enumeration():
    logging.info("Running automated network enumeration...")

def purge_target_prompt():
    """Ask the user if they want to purge the stored target and delete `network.enumeration` and `automation.config` before exiting."""
    if not os.path.exists(TARGET_FILE):  # ✅ Use TARGET_FILE from config.py
        logging.info("⚠ No stored target found.")
        return

    choice = input("\n⚠ Do you want to purge the stored target data? (yes/no): ").strip().lower()

    if choice == "yes":
        try:
            # Delete automation.config file if it exists
            if os.path.exists(TARGET_FILE):
                os.remove(TARGET_FILE)
                logging.info("✅ `automation.config` file deleted.")

            # Delete network.enumeration file if it exists
            if os.path.exists(NETWORK_ENUMERATION_FILE):
                os.remove(NETWORK_ENUMERATION_FILE)
                logging.info("✅ `network.enumeration` file deleted.")
            else:
                logging.info("⚠ `network.enumeration` file not found.")

        except Exception as e:
            logging.error(f"❌ Failed to purge target data or delete files: {e}")
    else:
        logging.info("⚠ Target data was not purged.")

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
    """
    print(logo_ascii)

def main():
    """Main function to execute the menu and handle user input."""
    check_zap_running()

    # Locate tools dynamically
    sqlmap_path = find_sqlmap()  # ✅ Find sqlmap
    nikto_path = find_nikto()  # ✅ Find Nikto
    zap_path = find_zap()

    # Ensure a valid target is set
    target = check_target_defined()

    # Display paths and target
    print(f"\n🎯 Current Target: {target}")
    print(f"🛠 SQLMAP Path: {sqlmap_path if sqlmap_path else '❌ Not Found'}")
    print(f"🛠 Nikto Path: {nikto_path if nikto_path else '❌ Not Found'}")
    print(f"🛠 OWASP ZAP Path: {zap_path if zap_path else '❌ Not Found'}\n")

    def network_enumeration():
        """Prompt for scan type and run Nmap scan."""
        print("\n[🔍 Network Enumeration Options]")
        print("1️⃣ Fast Scan: Quick service discovery and fingerprinting")
        print("2️⃣ Thorough Scan: In-depth analysis including vulnerability detection")

        scan_type = input("\nSelect an option (1 or 2): ").strip()
        if scan_type not in ["1", "2"]:
            print("❌ Invalid selection. Returning to menu.")
            return
        run_nmap_scan(target, scan_type)

    actions = {
        "1": full_automation,
        "2": network_enumeration,
        "3": process_network_enumeration,
        "4": lambda: sqli_testing_automation(sqlmap_path),
        "5": change_target,  # ✅ New option for changing the target
    }

    while True:
        print("\n[ ⚙ Automated Security Testing Framework ⚙ ]")
        print("1️⃣ Full Automation - Not Available Yet")
        print("2️⃣ Automated Network Enumeration")
        print("3️⃣ Web Application Enumeration & Testing")
        print("4️⃣ SQLi Testing Automation")
        print("5️⃣ Change Target")
        print("6️⃣ Exit (or type 'exit')")

        choice = input("\n🔹 Select an option (1-6 or 'exit'): ").strip().lower()

        if choice in ("exit", "6"):
            purge_target_prompt()
            logging.info("🔚 Exiting program.")
            break

        action = actions.get(choice)
        if action:
            action()
        else:
            logging.error("❌ Invalid selection. Please try again.")

if __name__ == "__main__":
    main()
