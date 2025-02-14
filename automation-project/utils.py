import os
import json
import logging
import utils
import shutil
import subprocess
import ipaddress
import re
from config import NETWORK_ENUMERATION_FILE, TARGET_FILE, cipher_suite, SQLMAP_PATH
#from utils import encrypt_and_store_data, is_valid_ipv4, is_valid_ipv6, is_valid_fqdn, is_valid_cidr

### ✅ **Using Encryption Functions from `config.py`** ###
def encrypt_and_store_data(key, value):
    """Encrypt and store a key-value pair persistently in the config file."""
    try:
        data = get_encrypted_data()  # Load existing encrypted data

        if not isinstance(value, str):
            raise ValueError("🔒 Value to encrypt must be a string!")

        encrypted_value = cipher_suite.encrypt(value.encode()).decode()
        data[key] = encrypted_value

        temp_file = f"{TARGET_FILE}.tmp"  # Write to a temp file first

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
        for key, value in data.items():
            try:
                decrypted_data[key] = cipher_suite.decrypt(value.encode()).decode()
            except Exception as e:
                logging.error(f"❌ Failed to decrypt {key}: {e}")  # ✅ Show exact decryption error
                continue  # ✅ Skip failed decryption attempts instead of breaking

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
    data = get_encrypted_data()
    target = data.get("target")

    if target and (is_valid_ipv4(target) or is_valid_ipv6(target) or is_valid_fqdn(target) or is_valid_cidr(target)):
        logging.info(f"✅ Target is set: {target}")
        return [target]  # Always return as a list
    while True:
        target = input("Enter target (IPv4, IPv6, FQDN, or CIDR Netblock): ").strip()
        if is_valid_ipv4(target) or is_valid_ipv6(target) or is_valid_fqdn(target) or is_valid_cidr(target):
            encrypt_and_store_data("target", target)
            logging.info(f"✅ Target stored: {target}")
            return [target]
        else:
            logging.error("❌ Invalid target. Please enter a valid IPv4 address, IPv6 address, FQDN, or CIDR netblock.")

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
