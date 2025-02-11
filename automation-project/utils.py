import os
import json
import logging
import shutil
import subprocess
import ipaddress
import re
from config import NETWORK_ENUMERATION_FILE, TARGET_FILE, cipher_suite  # ✅ Use NETWORK_ENUMERATION_FILE from config.py

# Ensure necessary directories exist
#os.makedirs(LOG_DIR, exist_ok=True)
#os.makedirs(REPORT_DIR, exist_ok=True)
#os.makedirs(RAW_NMAP_DIR, exist_ok=True)

# Logging Configuration
#logging.basicConfig(
#    level=logging.INFO,
#    format="%(asctime)s - %(levelname)s - %(message)s",
#    handlers=[
#        logging.FileHandler(LOG_FILE),
#        logging.StreamHandler()
#    ]
#)

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

### ✅ **Using Decryption from `config.py`** ###
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
                logging.error(f"❌ Failed to decrypt {key}: {e}")
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

    if target and (is_valid_ipv4(target) or is_valid_ipv6(target) or is_valid_fqdn(target) or is_valid_cidr(target)):
        logging.info(f"✅ Target is set: {target}")
        return target

    while True:
        target = input("Enter target (IPv4, IPv6, FQDN, or CIDR Netblock): ").strip()

        if is_valid_ipv4(target) or is_valid_ipv6(target) or is_valid_fqdn(target) or is_valid_cidr(target):
            encrypt_and_store_data("target", target)
            logging.info(f"✅ Target stored: {target}")
            return target
        else:
            logging.error("❌ Invalid target. Please enter a valid IPv4 address, IPv6 address, FQDN, or CIDR netblock.")

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
