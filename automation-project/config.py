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
SQLMAP_DIR = os.path.join(BASE_DIR, "sqlmap_reports")
TARGET_FILE = os.path.join(BASE_DIR, "automation.config")
NETWORK_ENUMERATION_FILE = os.path.join(BASE_DIR, "network.enumeration")  # ✅ Ensure it's defined
API_KEY_FILE = os.path.join(BASE_DIR, ".zap_api_key")
LOG_FILE = os.path.join(LOG_DIR, "automation.log")  # ✅ Define LOG_FILE

# Ensure log directory exists and is secured
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)
    os.chmod(LOG_DIR, 0o700)  # Secure directory: only accessible by current user

### ✅ **Ensure Directories Exist**
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(RAW_NMAP_DIR, exist_ok=True)
os.makedirs(RAW_NMAP_DIR, exist_ok=True)
os.makedirs(SQLMAP_DIR, exist_ok=True)

### ✅ **Logging Configuration**
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logging.info("✅ Logging initialized. Log file: %s", LOG_FILE)

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
            logging.error("❌ Invalid target. Enter a valid IPv4, IPv6, FQDN, or CIDR netblock.")

### **✅ Find SQLMAP_PATH Properly**
def find_sqlmap():
    """Find sqlmap.py dynamically at runtime and return its absolute path."""
    logging.info("🔍 Searching for sqlmap.py...")

    # **First Check System Path**
    sqlmap_exec = shutil.which("sqlmap")
    if sqlmap_exec:
        logging.info(f"✅ Found sqlmap at: {sqlmap_exec}")
        return sqlmap_exec

    # **Use `locate` (Faster)**
    try:
        locate_cmd = ["locate", "sqlmap.py"]
        result = subprocess.run(locate_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        sqlmap_paths = [path for path in result.stdout.strip().split("\n") if os.path.isfile(path)]
        if sqlmap_paths:
            logging.info(f"✅ Found sqlmap at: {sqlmap_paths[0]}")
            return sqlmap_paths[0]
    except Exception:
        logging.warning("⚠ locate command failed, falling back to `find`.")

    # **Use `find` (Slower, Last Resort)**
    try:
        find_cmd = ["find", "/", "-name", "sqlmap.py", "-type", "f", "-not", "-path", "*/proc/*"]
        result = subprocess.run(find_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        sqlmap_paths = [path for path in result.stdout.strip().split("\n") if os.path.isfile(path)]
        if sqlmap_paths:
            logging.info(f"✅ Found sqlmap at: {sqlmap_paths[0]}")
            return sqlmap_paths[0]
    except Exception:
        logging.error("❌ `find` command failed. sqlmap.py not found.")

# **✅ Ensure SQLMAP_PATH is Set at the End of config.py**
SQLMAP_PATH = find_sqlmap()
logging.info(f"✅ SQLMAP_PATH set to: {SQLMAP_PATH}" if SQLMAP_PATH else "❌ SQLMAP_PATH not found!")

def find_nikto():
    """Locate nikto.pl dynamically using `locate` or `find`."""
    try:
        # Try using `locate` to find nikto.pl
        result = subprocess.run(["locate", "nikto.pl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        paths = result.stdout.strip().split("\n")

        if paths:
            return paths[0]  # Return the first found path

    except subprocess.CalledProcessError:
        pass  # `locate` is not available or failed

    try:
        # If `locate` fails, use `find` (slower but reliable)
        result = subprocess.run(["find", "/", "-name", "nikto.pl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        paths = result.stdout.strip().split("\n")

        if paths:
            return paths[0]  # Return the first found path

    except subprocess.CalledProcessError:
        pass  # `find` failed or permission error

    return None  # Nikto not found

# Set the Nikto path as a global variable in config
NIKTO_PATH = find_nikto()
