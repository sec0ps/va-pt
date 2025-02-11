import os
import json
import logging
import shutil
import subprocess
import ipaddress
import re
from cryptography.fernet import Fernet

### ✅ **Define Constants First**
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Get project base path
LOG_DIR = os.path.join(BASE_DIR, "automation-logs")
REPORT_DIR = os.path.join(BASE_DIR, "raw_reports")
RAW_NMAP_DIR = os.path.join(BASE_DIR, "raw_nmap")
KEY_FILE = os.path.join(BASE_DIR, ".key")
TARGET_FILE = os.path.join(BASE_DIR, "automation.config")
NETWORK_ENUMERATION_FILE = os.path.join(BASE_DIR, "network.enumeration")  # ✅ Ensure it's defined
API_KEY_FILE = os.path.join(BASE_DIR, ".zap_api_key")
LOG_FILE = os.path.join(LOG_DIR, "automation.log")  # ✅ Define LOG_FILE

### ✅ **Ensure Directories Exist**
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(RAW_NMAP_DIR, exist_ok=True)

### ✅ **Logging Configuration**
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)


def load_api_key():
    """Retrieve or prompt the user for the OWASP ZAP API key and store it."""
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as file:
            return file.read().strip()

    api_key = input("Enter your OWASP ZAP API key: ").strip()
    with open(API_KEY_FILE, "w") as file:
        file.write(api_key)
    os.chmod(API_KEY_FILE, 0o600)
    return api_key

### **✅ Load Encryption Key**
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

cipher_suite = load_encryption_key()

### **✅ Retrieve & Decrypt Stored Data**
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
                continue

        return decrypted_data

    except json.JSONDecodeError:
        logging.error(f"❌ {TARGET_FILE} is corrupted. Deleting and resetting...")
        os.remove(TARGET_FILE)
        return {}

### **✅ Encrypt and Store Data Securely**
def encrypt_and_store_data(key, value):
    """Encrypt and store a key-value pair persistently in the config file."""
    try:
        data = get_encrypted_data()  # Load existing encrypted data

        if not isinstance(value, str):
            raise ValueError("🔒 Value to encrypt must be a string!")

        encrypted_value = cipher_suite.encrypt(value.encode()).decode()
        temp_file = f"{TARGET_FILE}.tmp"  # Write to a temp file first

        data[key] = encrypted_value
        with open(temp_file, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=4)

        os.replace(temp_file, TARGET_FILE)  # Prevent corruption
        logging.info(f"✅ Stored {key} securely in {TARGET_FILE}")

    except Exception as e:
        logging.error(f"❌ Failed to encrypt and store {key}: {e}")

### **✅ Validation Functions**
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
        ipaddress.ip_network(netblock, strict=False)
        return True
    except ValueError:
        return False

### **✅ Ensure the Target is Defined**
def check_target_defined():
    """Ensure the target is valid before storing it."""
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
            logging.error("❌ Invalid target. Enter a valid IPv4, IPv6, FQDN, or CIDR netblock.")
