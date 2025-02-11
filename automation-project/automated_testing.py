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

# Define log directory and log file
LOG_DIR = "./automation-logs"
LOG_FILE = os.path.join(LOG_DIR, "automation.log")

# Define report directory
REPORT_DIR = "./raw_reports"

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
API_KEY_FILE = "./.zap_api_key"
KEY_FILE = "./.key"
ZAP_API_URL = "http://localhost:8080"
ENUMERATION_FILE = ".tmp.enumeration"
SQLMAP_PATH = None  # Global variable to store sqlmap path

def load_encryption_key():
    """Load the encryption key from a file or generate one if it doesn't exist."""
    if not os.path.exists(KEY_FILE):
        encryption_key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(encryption_key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            encryption_key = key_file.read()
    return Fernet(encryption_key)

cipher_suite = load_encryption_key()  # Load once and reuse globally

def encrypt_and_store_data(key, value):
    """Encrypt and store a key-value pair persistently in the config file, preventing corruption."""
    try:
        data = get_encrypted_data()  # Load existing encrypted data

        if not isinstance(value, str):
            raise ValueError("🔒 Value to encrypt must be a string!")

        encrypted_value = cipher_suite.encrypt(value.encode()).decode()
        data[key] = encrypted_value

        temp_file = f"{target_file}.tmp"  # Write to a temp file first

        with open(temp_file, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=4)  # Proper formatting

        os.replace(temp_file, target_file)  # Prevent corruption

        logging.info(f"✅ Stored {key} securely in automation.config")

    except Exception as e:
        logging.error(f"❌ Failed to encrypt and store {key}: {e}")

def get_encrypted_data():
    """Retrieve and decrypt stored data from the configuration file."""
    if not os.path.exists(target_file):
        return {}

    try:
        with open(target_file, "r", encoding="utf-8") as file:
            data = json.load(file)

        decrypted_data = {}
        for key, value in data.items():
            try:
                decrypted_data[key] = cipher_suite.decrypt(value.encode()).decode()
            except Exception as e:
                logging.error(f"❌ Failed to decrypt {key}: {e}")
                continue  # Skip corrupted entries

        return decrypted_data

    except json.JSONDecodeError:
        logging.error("❌ automation.config is corrupted. Deleting and resetting...")
        os.remove(target_file)
        return {}

    except Exception as e:
        logging.error(f"❌ Unexpected error reading automation.config: {e}")
        return {}

def is_valid_url(url):
    """Validate a given URL."""
    parsed_url = urlparse(url)
    return all([parsed_url.scheme, parsed_url.netloc])

def load_api_key():
    """Retrieve or prompt the user for the OWASP ZAP API key and store it once."""
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as file:
            return file.read().strip()

    api_key = input("Enter your OWASP ZAP API key: ").strip()
    with open(API_KEY_FILE, "w") as file:
        file.write(api_key)
    os.chmod(API_KEY_FILE, 0o600)
    return api_key

ZAP_API_KEY = load_api_key()  # Load once

def get_api_key():
    """Return the cached API key instead of reading from the file multiple times."""
    return ZAP_API_KEY

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

import subprocess
import xml.etree.ElementTree as ET

def run_nmap_scan(target):
    scan_type = input("Select enumeration type (fast/thorough): ").strip().lower()
    output = "nmap_scan_results"

    if scan_type == "fast":
        command = [
            "nmap", "-p-", "-sV", "-T5", "--open", "-oN", f"{output}.txt", "-oX", f"{output}.xml", "--script=default", target
        ]
    elif scan_type == "thorough":
        command = [
            "nmap", "-A", "-T4", "--open", "--script", "vulners", "-oN", f"{output}.txt", "-oX", f"{output}.xml", target
        ]
    else:
        print("Invalid selection. Please choose either 'fast' or 'thorough'.")
        return

    print(f"Running Nmap scan: {' '.join(command)}")
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    parse_nmap_results(f"{output}.xml")

def parse_nmap_results(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    results = []

    for host in root.findall(".//host"):
        ip_addr = host.find("address").get("addr")
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            service = port.find("service")
            if service is not None:
                service_name = service.get("name", "")
                if "http" in service_name:
                    protocol = "https" if "ssl" in service_name or port_id in ["443", "8443", "4443"] else "http"
                    results.append(f"{protocol}://{ip_addr}:{port_id}")

    with open("network.enumeration", "w") as f:
        for result in results:
            f.write(result + "\n")

    print("HTTP/HTTPS services have been written to network.enumeration")

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

def web_application_enumeration():
    """Scan web applications found in a CIDR range or a single target with a progress bar."""
    target = check_target_defined()

    try:
        ip_network(target)  # If this doesn't raise an error, it's a CIDR block
        is_cidr = True
    except ValueError:
        is_cidr = False

    if not is_cidr:
        if not is_valid_url(target):
            logging.error("❌ Invalid URL format. Please enter a valid URL.")
            return
        try:
            logging.info(f"🚀 Starting active scan on: {target}")
            scan_target_with_zap(target)  # Ensure a string URL is passed
        except Exception as e:
            logging.error(f"❌ Error scanning {target}: {e}")
        return

    # 🔹 CIDR Handling: Expand and scan each IP
    logging.info(f"🌍 Expanding CIDR network: {target}")

    target_ips = list(ip_network(target).hosts())  # Get all hosts in the network
    estimated_time = len(target_ips) * 2  # Estimate 2 seconds per IP

    with tqdm(total=len(target_ips), desc="Scanning Progress", unit="host", dynamic_ncols=True) as pbar:
        for ip in target_ips:
            ip_str = str(ip)
            try:
                target_url = check_web_service(ip_str)
                if target_url:
                    logging.info(f"🚀 Starting active scan on: {target_url}")
                    scan_target_with_zap(target_url)  # Ensure a single string is passed
                time.sleep(2)  # Simulate processing time
            except Exception as e:
                if "No route to host" not in str(e):  # Suppress only connection errors
                    logging.error(f"❌ Error scanning {ip_str}: {e}")
            finally:
                pbar.update(1)  # Update progress bar

    logging.info("✅ Scanning job completed.")

def get_enumerated_targets():
    """Retrieve stored enumerated targets from .tmp.enumeration (plain text)."""
    if not os.path.exists(ENUMERATION_FILE):
        return []

    try:
        with open(ENUMERATION_FILE, "r") as file:
            targets = file.read().splitlines()
        return targets
    except Exception as e:
        logging.error(f"❌ Failed to retrieve enumerated targets: {e}")
        return []

def export_zap_xml_report(target_url):
    """Fetch the OWASP ZAP scan report in XML format for a specific target and save it separately."""
    try:
        # Ensure report directory exists
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR, exist_ok=True)
            os.chmod(REPORT_DIR, 0o700)  # Secure directory

        # Extract domain or IP from target URL for naming
        parsed_url = urlparse(target_url)
        target_name = parsed_url.hostname.replace(".", "_")  # Convert dots to underscores

        # Define unique report filename for this target
        report_file = os.path.join(REPORT_DIR, f"zap_report_{target_name}.xml")

        # ZAP API URL for XML report
        url = f"{ZAP_API_URL}/OTHER/core/other/xmlreport/?apikey={ZAP_API_KEY}"
        logging.info(f"📄 Fetching XML report for {target_url} from {url}")

        # Send GET request to fetch XML report
        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            # Save the report to raw_reports directory
            with open(report_file, "wb") as file:
                file.write(response.content)
            logging.info(f"✅ XML report saved: {report_file}")
        else:
            logging.error(f"❌ Failed to fetch XML report for {target_url}. Status Code: {response.status_code}")

    except requests.RequestException as e:
        logging.error(f"❌ Error connecting to ZAP API for {target_url}: {e}")

def scan_target_with_zap(target_url):
    """Scan a detected web service using OWASP ZAP."""
    logging.info(f"🚀 scan_target_with_zap() called for target: {target_url}")

    session = requests.Session()
    headers = {"Content-Type": "application/json"}

    # 🔹 Step 1: Start Spider (Crawl)
    try:
        spider_url = f"{ZAP_API_URL}/JSON/spider/action/scan/?apikey={ZAP_API_KEY}&url={requests.utils.quote(target_url)}&recurse=true"
        logging.info(f"🔍 Sending Spider scan request to ZAP: {spider_url}")

        response = session.get(spider_url, headers=headers, timeout=10)
        response.raise_for_status()

        scan_id = response.json().get("scan", "-1")
        logging.info(f"✅ Spider started for {target_url} with Scan ID: {scan_id}")
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Failed to start Spider for {target_url}: {e}")
        return

    # 🔹 Step 2: Monitor Spider Progress
    spider_status_url = f"{ZAP_API_URL}/JSON/spider/view/status/?apikey={ZAP_API_KEY}&scanId={scan_id}"

    while True:
        try:
            response = session.get(spider_status_url, headers=headers, timeout=10)
            status = response.json().get("status", "0")
            logging.info(f"🕷 Spider Progress for {target_url}: {status}%")

            if status == "100":
                logging.info(f"✅ Spider completed for {target_url}. Starting Active Scan...")
                break
        except requests.exceptions.RequestException as e:
            logging.error(f"❌ Error checking Spider progress: {e}")
            break

        time.sleep(10)  # Wait before checking again

    # 🔹 Step 3: Start Active Scan
    try:
        active_scan_url = f"{ZAP_API_URL}/JSON/ascan/action/scan/?apikey={ZAP_API_KEY}&url={requests.utils.quote(target_url)}"
        logging.info(f"🔍 Sending Active scan request to ZAP: {active_scan_url}")

        response = session.get(active_scan_url, headers=headers, timeout=10)
        response.raise_for_status()

        scan_id = response.json().get("scan", "-1")
        logging.info(f"✅ Active scan started for {target_url} with Scan ID: {scan_id}")
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Failed to start Active Scan for {target_url}: {e}")
        return

    # 🔹 Step 4: Monitor Active Scan Progress
    scan_status_url = f"{ZAP_API_URL}/JSON/ascan/view/status/?apikey={ZAP_API_KEY}&scanId={scan_id}"

    while True:
        try:
            response = session.get(scan_status_url, headers=headers, timeout=10)
            status = response.json().get("status", "0")
            logging.info(f"🔥 Active Scan Progress for {target_url}: {status}%")

            if status == "100":
                logging.info(f"✅ Active Scan Completed for {target_url}.")
                break
        except requests.exceptions.RequestException as e:
            logging.error(f"❌ Error checking Active Scan progress: {e}")
            break

        time.sleep(10)  # Wait before checking again

    # 🔹 Step 5: Export XML Report for this Target
    export_zap_xml_report(target_url)

def check_zap_running():
    """Check if OWASP ZAP API is accessible with retries."""
    max_retries = 5
    retry_delay = 3
    api_url = f"{ZAP_API_URL}/JSON/core/view/version/?apikey={get_api_key()}"

    for attempt in range(1, max_retries + 1):
        try:
            logging.info(f"🔍 Checking OWASP ZAP API availability (Attempt {attempt}/{max_retries})...")
            response = requests.get(api_url, timeout=5)
            response.raise_for_status()
            zap_version = response.json().get('version', 'Unknown')
            logging.info(f"✅ Connected to ZAP Proxy at {ZAP_API_URL}, version: {zap_version}")
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"⚠ ZAP API connection issue: {e}")

        time.sleep(retry_delay)

    logging.error("❌ Max retries reached. ZAP API is not accessible. Exiting...")
    sys.exit(1)

def find_sqlmap():
    """Find sqlmap.py dynamically at runtime and return its absolute path."""
    logging.info("🔍 Searching for sqlmap.py...")

    # Try system-wide installation first
    sqlmap_exec = shutil.which("sqlmap")
    if sqlmap_exec:
        logging.info(f"✅ Found sqlmap at: {sqlmap_exec}")
        return sqlmap_exec

    # Use locate (faster) before find (slower)
    try:
        locate_cmd = ["locate", "sqlmap.py"]
        result = subprocess.run(locate_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        sqlmap_paths = [path for path in result.stdout.strip().split("\n") if os.path.isfile(path)]

        if sqlmap_paths:
            logging.info(f"✅ Found sqlmap at: {sqlmap_paths[0]}")
            return sqlmap_paths[0]
    except Exception:
        logging.warning("⚠ locate command failed, falling back to `find`.")

    # Use find command (last resort, slower)
    try:
        find_cmd = ["find", "/", "-name", "sqlmap.py", "-type", "f", "-not", "-path", "'*/proc/*'", "2>/dev/null"]
        result = subprocess.run(" ".join(find_cmd), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, shell=True)
        sqlmap_paths = [path for path in result.stdout.strip().split("\n") if os.path.isfile(path)]

        if sqlmap_paths:
            logging.info(f"✅ Found sqlmap at: {sqlmap_paths[0]}")
            return sqlmap_paths[0]
    except Exception:
        logging.error("❌ `find` command failed. sqlmap.py not found.")

    logging.error("❌ sqlmap.py not found! Ensure sqlmap is installed.")
    return None  # Explicit None if not found

def sqli_automation_enumeration():
    """Run SQLi spider enumeration on all targets stored in .tmp.enumeration using sqlmap in parallel."""

    data = get_encrypted_data()
    SQLMAP_PATH = data.get("SQLMAP_PATH", None)

    if not SQLMAP_PATH or not os.path.exists(SQLMAP_PATH):
        logging.error("❌ SQLMAP_PATH is not set or invalid. Run set_sqlmap_path() first.")
        return

    if not os.path.exists(ENUMERATION_FILE):
        logging.error("❌ Enumeration file not found. Ensure web application enumeration has been run.")
        return

    with open(ENUMERATION_FILE, "r") as file:
        targets = file.read().splitlines()

    if not targets:
        logging.warning("⚠ No targets found in enumeration file.")
        return

    logging.info(f"🔍 Starting parallel SQLi automation for {len(targets)} targets...")

import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

SQLMAP_PATH = "/path/to/sqlmap.py"  # Ensure this is set correctly

def run_sqlmap(target):
    """Execute SQLMap for a single target."""
    try:
        logging.info(f"🚀 Running sqlmap spider on: {target}")

        sqlmap_cmd = [
            "python3", SQLMAP_PATH,
            "--url", target,
            "--level", "50",
            "--crawl", "20",
            "--batch",
            "--unstable",
            "--sql-shell"
        ]

        result = subprocess.run(sqlmap_cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            logging.info(f"✅ SQLi scan completed for: {target}")
        else:
            logging.error(f"❌ SQLmap failed on {target}: {result.stderr.strip()}")

    except Exception as e:
        logging.error(f"❌ Unexpected SQLmap error on {target}: {e}")


# ✅ Run SQLMap in parallel (Properly indented)
def run_bulk_sqlmap(targets):
    """Run SQLMap on multiple targets in parallel."""
    if not SQLMAP_PATH:
        logging.error("❌ SQLMAP_PATH is not set. Exiting SQLi automation.")
        return

    if not targets:
        logging.warning("⚠ No targets found. Skipping SQLi scanning.")
        return

    logging.info(f"🔍 Starting SQLi automation for {len(targets)} targets...")

    with ThreadPoolExecutor(max_workers=5) as executor:
        list(tqdm(executor.map(run_sqlmap, targets), total=len(targets), desc="SQLi Scanning", unit="target"))

def full_automation():
    logging.info("Running full automation...")

def automated_network_enumeration():
    logging.info("Running automated network enumeration...")

def sqli_testing_automation(sqlmap_path):
    """Run SQLi spider enumeration using sqlmap on all targets stored in .tmp.enumeration."""
    if not sqlmap_path or not os.path.exists(sqlmap_path):
        logging.error("❌ SQLMAP_PATH is invalid. Ensure sqlmap is installed.")
        return

    if not os.path.exists(ENUMERATION_FILE):
        logging.error("❌ Enumeration file not found. Ensure web application enumeration has been run.")
        return

    with open(ENUMERATION_FILE, "r") as file:
        targets = [line.strip() for line in file if line.strip()]

    if not targets:
        logging.warning("⚠ No targets found in enumeration file.")
        return

    logging.info(f"🔍 Starting SQLi automation for {len(targets)} targets...")

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

    actions = {
        "1": full_automation,
        "2": run_nmap_scan,
        "3": web_application_enumeration,
        "4": lambda: sqli_testing_automation(sqlmap_path)  # 🔴 Explicitly pass sqlmap_path
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
            action()
        else:
            logging.error("❌ Invalid selection. Please try again.")

if __name__ == "__main__":
    main()

