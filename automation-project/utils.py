import os
import json
import logging
import utils
import shutil
import subprocess
import ipaddress
import requests
import time
import re
from cryptography.fernet import Fernet
from config import NETWORK_ENUMERATION_FILE, TARGET_FILE
#from config import NETWORK_ENUMERATION_FILE, SQLMAP_PATH, ZAP_API_URL, ZAP_API_KEY
#from web import ZAP_API_URL, ZAP_API_KEY

### **✅ Load Encryption Key Inside `utils.py`**
def load_encryption_key():
    """Load the encryption key from a file or generate one if it doesn't exist."""
    from config import KEY_FILE  # ✅ Import only inside function to prevent circular import

    if not os.path.exists(KEY_FILE):
        encryption_key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(encryption_key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            encryption_key = key_file.read()

    return Fernet(encryption_key)

# ✅ Initialize cipher_suite within `utils.py` instead of `config.py`
cipher_suite = load_encryption_key()

def encrypt_and_store_data(key, value):
    """Encrypt and store a key-value pair persistently in the config file."""
    try:
        if not isinstance(value, str):
            raise ValueError("🔒 Value to encrypt must be a string!")

        encrypted_value = cipher_suite.encrypt(value.encode()).decode()
        data = get_encrypted_data()  # Load existing data

        data[key] = encrypted_value

        temp_file = f"{TARGET_FILE}.tmp"
        with open(temp_file, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=4)

        os.replace(temp_file, TARGET_FILE)  # Prevent corruption

        logging.info(f"✅ Stored {key} securely in {TARGET_FILE}")

    except Exception as e:
        logging.error(f"❌ Failed to encrypt and store {key}: {e}")

def get_encrypted_data():
    """Retrieve and decrypt stored data from the configuration file."""
    if not os.path.exists(TARGET_FILE):
        return {}

    try:
        with open(TARGET_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        decrypted_data = {}
        for stored_key, encrypted_value in data.items():
            try:
                decrypted_data[stored_key] = cipher_suite.decrypt(encrypted_value.encode()).decode()
            except Exception as e:
                logging.error(f"❌ Failed to decrypt {stored_key}: {e}")
                continue  # Skip corrupted entries

        return decrypted_data

    except json.JSONDecodeError:
        logging.error(f"❌ {TARGET_FILE} is corrupted. Deleting and resetting...")
        os.remove(TARGET_FILE)
        return {}

def get_enumerated_targets():
    """Retrieve stored enumerated targets from network.enumeration."""
    if not os.path.exists(ENUMERATION_FILE):
        return []

    try:
        with open(ENUMERATION_FILE, "r") as file:
            targets = file.read().splitlines()
        return targets
    except Exception as e:
        logging.error(f"❌ Failed to retrieve enumerated targets: {e}")
        return []

### ✅ **Validation Functions (Keep these in `utils.py`)** ###
def is_valid_ipv4(ip):
    """Validate an IPv4 address format."""
    try:
        return bool(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        return False

def is_valid_ipv6(ip):
    """Validate an IPv6 address format."""
    try:
        return bool(ipaddress.IPv6Address(ip))
    except ipaddress.AddressValueError:
        return False

def is_valid_fqdn(domain):
    """Validate a Fully Qualified Domain Name (FQDN)."""
    fqdn_pattern = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    return bool(fqdn_pattern.match(domain))

def is_valid_cidr(netblock):
    """Validate an IPv4 or IPv6 CIDR netblock format."""
    try:
        ipaddress.ip_network(netblock, strict=False)  # strict=False allows host identifiers
        return True
    except ValueError:
        return False

def check_target_defined():
    """Ensure the target is a valid IPv4, IPv6, FQDN, or CIDR Netblock before storing it."""
    data = get_encrypted_data()
    target = data.get("target")

    if target:
        # ✅ Strip protocol from stored target before validation
        clean_target = target.strip().replace("http://", "").replace("https://", "")

        if is_valid_ipv4(clean_target) or is_valid_ipv6(clean_target) or is_valid_fqdn(clean_target) or is_valid_cidr(clean_target):
            logging.info(f"✅ Target is set: {clean_target}")

            # ✅ If it's an FQDN, return a list with both HTTP and HTTPS
            if is_valid_fqdn(clean_target):
                http_target = f"http://{clean_target}"
                https_target = f"https://{clean_target}"

                # ✅ Store only clean FQDN target
                encrypt_and_store_data("target", clean_target)
                encrypt_and_store_data("target_http", http_target)
                encrypt_and_store_data("target_https", https_target)

                return [http_target, https_target]  # ✅ Correct return type for FQDNs

            return clean_target  # ✅ Return a string for IPs and CIDRs

    while True:
        target = input("Enter target (IPv4, IPv6, FQDN, or CIDR Netblock): ").strip()
        clean_target = target.replace("http://", "").replace("https://", "").strip()  # ✅ Strip protocol

        if is_valid_ipv4(clean_target) or is_valid_ipv6(clean_target) or is_valid_fqdn(clean_target) or is_valid_cidr(clean_target):
            encrypt_and_store_data("target", clean_target)
            logging.info(f"✅ Target stored: {clean_target}")

            if is_valid_fqdn(clean_target):  # ✅ Store separate HTTP/HTTPS versions for testing
                http_target = f"http://{clean_target}"
                https_target = f"https://{clean_target}"
                encrypt_and_store_data("target_http", http_target)
                encrypt_and_store_data("target_https", https_target)
                return [http_target, https_target]  # ✅ Correct return type for FQDNs

            return clean_target  # ✅ Correct return type for IPs and CIDRs

        logging.error("❌ Invalid target. Please enter a valid IPv4, IPv6, FQDN, or CIDR netblock.")

def change_target():
    """Prompt the user to change the target and update it securely."""
    while True:
        new_target = input("\n🔹 Enter the new target (IPv4, IPv6, FQDN, or CIDR Netblock): ").strip()

        if is_valid_ipv4(new_target) or is_valid_ipv6(new_target) or is_valid_fqdn(new_target) or is_valid_cidr(new_target):
            encrypt_and_store_data("target", new_target)  # ✅ Store securely
            logging.info(f"✅ Target updated successfully: {new_target}")

            # ✅ Write the new target to `network.enumeration` WITHOUT expanding CIDR
            with open(NETWORK_ENUMERATION_FILE, "w") as file:
                file.write(new_target + "\n")
                logging.info(f"📄 Target written to {NETWORK_ENUMERATION_FILE}")

            print(f"\n✅ Target changed to: {new_target}\n")
            return
        else:
            logging.error("❌ Invalid target format. Please enter a valid IP, FQDN, or CIDR netblock.")

def stop_zap():
    """Gracefully stop OWASP ZAP if it is running."""
    from config import ZAP_API_URL, ZAP_API_KEY  # ✅ Import inside function to avoid circular import

    api_url = f"{ZAP_API_URL}/JSON/core/action/shutdown/?apikey={ZAP_API_KEY}"

    try:
        logging.info("🛑 Attempting to shut down OWASP ZAP...")
        response = requests.get(api_url, timeout=5)

        if response.status_code == 200:
            logging.info("✅ OWASP ZAP shutdown request sent successfully.")
        else:
            logging.warning(f"⚠ Failed to shut down ZAP. Status Code: {response.status_code}")

        # Wait briefly for ZAP to terminate
        time.sleep(10)

        # Verify process termination
        if is_zap_running():
            logging.error("❌ ZAP is still running! Forcing termination...")
            force_kill_zap()
        else:
            logging.info("✅ OWASP ZAP has been successfully terminated.")

    except requests.RequestException as e:
        logging.error(f"❌ Error sending shutdown request: {e}")
        force_kill_zap()  # If API shutdown fails, force kill

def is_zap_running():
    """Check if OWASP ZAP is still running."""
    from config import ZAP_API_URL, ZAP_API_KEY  # ✅ Import inside function to avoid circular import

    try:
        response = requests.get(f"{ZAP_API_URL}/JSON/core/view/version/?apikey={ZAP_API_KEY}", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False  # Connection refused means it's not running

def force_kill_zap():
    """Force terminate OWASP ZAP if it doesn't shut down gracefully."""
    try:
        subprocess.run(["pkill", "-f", "zap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info("✅ ZAP process forcefully terminated.")
    except Exception as e:
        logging.error(f"❌ Error forcefully terminating ZAP: {e}")


def purge_target_prompt():
    """Ask the user if they want to purge the stored target and delete network.enumeration and automation.config before exiting."""
    if not os.path.exists(TARGET_FILE):  # ✅ Use TARGET_FILE from config.py
        logging.info("⚠ No stored target found.")
        return

    choice = input("\n⚠ Do you want to purge the stored target data? (yes/no): ").strip().lower()

    if choice == "yes":
        try:
            # Delete automation.config file if it exists
            if os.path.exists(TARGET_FILE):
                os.remove(TARGET_FILE)
                logging.info("✅ automation.config file deleted.")

            # Delete network.enumeration file if it exists
            if os.path.exists(NETWORK_ENUMERATION_FILE):
                os.remove(NETWORK_ENUMERATION_FILE)
                logging.info("✅ network.enumeration file deleted.")
            else:
                logging.info("⚠ network.enumeration file not found.")

        except Exception as e:
            logging.error(f"❌ Failed to purge target data or delete files: {e}")
    else:
        logging.info("⚠ Target data was not purged.")

    # Ensure OWASP ZAP is terminated before exiting
    stop_zap()

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
