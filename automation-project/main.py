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
from tqdm import tqdm
from cryptography.fernet import Fernet
from ipaddress import ip_network
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import subprocess
import xml.etree.ElementTree as ET
import web  # Import the standalone web module
import nmap  # Import the renamed Nmap scanning module
from sqlmap import sqli_testing_automation  # Ensure SQLMap functions are in sqlmap.py
from utils import check_zap_running, find_sqlmap, purge_target_prompt, full_automation  # Keep utility functions modular

# Define log directory and log file
LOG_DIR = "./automation-logs"
LOG_FILE = os.path.join(LOG_DIR, "automation.log")

# Define report directory
REPORT_DIR = "./raw_reports"

ZAP_API_KEY = load_api_key()
ZAP_API_URL = "http://127.0.0.1:8080"

ENUMERATION_FILE = ".tmp.enumeration"

# Ensure log directory exists and is secured
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)
    os.chmod(LOG_DIR, 0o700)  # Secure directory: only accessible by current user

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),  # Store logs in automation-logs directory
        logging.StreamHandler()  # Also print logs to console
    ]
)

logging.info("✅ Logging initialized. Log file: %s", LOG_FILE)

target_file = "automation.config"
KEY_FILE = "./.key"
ZAP_API_URL = "http://localhost:8080"
ENUMERATION_FILE = ".tmp.enumeration"
SQLMAP_PATH = None  # Global variable to store sqlmap path
#SQLMAP_PATH = "/path/to/sqlmap.py"  # Ensure this is set correctly

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
    """Ask the user if they want to purge the stored target before exiting."""
    if not os.path.exists(target_file):
        logging.info("⚠ No stored target found.")
        return

    choice = input("\n⚠ Do you want to purge the stored target? (yes/no): ").strip().lower()

    if choice == "yes":
        try:
            data = get_encrypted_data()  # Load existing config
            if "target" in data:
                del data["target"]  # Remove only the target variable

                # Write updated config back to file
                with open(target_file, "w", encoding="utf-8") as file:
                    json.dump(data, file, ensure_ascii=False, indent=4)

                logging.info("✅ Target purged successfully.")
            else:
                logging.info("⚠ No target variable found in automation.config.")
        except Exception as e:
            logging.error(f"❌ Failed to purge target: {e}")
    else:
        logging.info("⚠ Target was NOT purged.")

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
    sqlmap_path = find_sqlmap()  # Find sqlmap locally
    target = check_target_defined()

    print(f"\n🎯 Current Target: {target}")
    print(f"🛠 SQLMAP Path: {sqlmap_path if sqlmap_path else '❌ Not Found'}\n")

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
        "2": network_enumeration,  # Modified to first prompt for scan_type
        "3": web_application_enumeration,
        "4": lambda: sqli_testing_automation(sqlmap_path)
    }

    while True:
        print("\n[ ⚙ Automated Security Testing Framework ⚙ ]")
        print("1️⃣ Full Automation")
        print("2️⃣ Automated Network Enumeration")
        print("3️⃣ Web Application Enumeration")
        print("4️⃣ SQLi Testing Automation")
        print("5️⃣ Exit (or type 'exit')")

        choice = input("\n🔹 Select an option (1-5 or 'exit'): ").strip().lower()

        if choice in ("exit", "5"):
            purge_target_prompt()  # 🔴 Always ask to purge before exit
            logging.info("🔚 Exiting program.")
            break

        action = actions.get(choice)
        if action:
            action()  # Call the function (network_enumeration() prompts user first)
        else:
            logging.error("❌ Invalid selection. Please try again.")

if __name__ == "__main__":
    main()
