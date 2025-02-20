import os
import json
import logging
import shutil
import subprocess
import ipaddress
import re
#from cryptography.fernet import Fernet


### ✅ **Define Constants First**
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Get project base path
LOG_DIR = os.path.join(BASE_DIR, "automation-logs")
REPORT_DIR = os.path.join(BASE_DIR, "raw_reports")
RAW_NMAP_DIR = os.path.join(BASE_DIR, "raw_nmap")
KEY_FILE = os.path.join(BASE_DIR, ".key")
SQLMAP_DIR = os.path.join(BASE_DIR, "sqlmap_reports")
ZAP_DIR = os.path.join(BASE_DIR, "zap_exports")
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
os.makedirs(ZAP_DIR, exist_ok=True)

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

def get_api_key():
    """Return the cached API key."""
    return ZAP_API_KEY

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

ZAP_API_URL = "http://127.0.0.1:8080"
ZAP_API_KEY = load_api_key()  # Ensure this function loads the key correctly

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

def find_sqlmap():
    """Find sqlmap.py dynamically at runtime and return its absolute path, or exit if not found."""
#    logging.info("🔍 Searching for sqlmap...")

    # **First Check System Path**
    sqlmap_exec = shutil.which("sqlmap")
    if sqlmap_exec:
#        logging.info(f"✅ Found sqlmap at: {sqlmap_exec}")
        return sqlmap_exec

    # **Use `locate` (Faster)**
    try:
        locate_cmd = ["locate", "sqlmap.py"]
        result = subprocess.run(locate_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        sqlmap_paths = [path for path in result.stdout.strip().split("\n") if os.path.isfile(path)]
        if sqlmap_paths:
#            logging.info(f"✅ Found sqlmap at: {sqlmap_paths[0]}")
            return sqlmap_paths[0]
    except Exception:
        logging.warning("⚠ locate command failed, falling back to `find`.")

    # **Use `find` (Slower, Last Resort)**
    try:
        find_cmd = ["find", "/", "-name", "sqlmap.py", "-type", "f", "-not", "-path", "*/proc/*"]
        result = subprocess.run(find_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        sqlmap_paths = [path for path in result.stdout.strip().split("\n") if os.path.isfile(path)]
        if sqlmap_paths:
            logging.info(f"✅ Found sqlmap at: {sqlmap_paths[0]}")
            return sqlmap_paths[0]
    except Exception:
        logging.error("❌ `find` command failed.")

    # **Exit Gracefully if sqlmap is Not Found**
    print("\n❌ ERROR: sqlmap not found! Please install it before running this script.")
    print("\nExecute: git clone https://github.com/sec0ps/va-pt.git")
    print("Run the installation script: python3 vapt-installer.py")
    print("Once installation is completed, then run main.py\n")
    sys.exit(1)

# **Ensure SQLMAP_PATH is Set**
SQLMAP_PATH = find_sqlmap()
logging.info(f"✅ SQLMAP_PATH set to: {SQLMAP_PATH}")


def find_nikto():
    """Find nikto.pl dynamically at runtime and return its absolute path, or exit if not found."""
#    logging.info("🔍 Searching for nikto...")

    # **First Check System Path**
    nikto_exec = shutil.which("nikto")
    if nikto_exec:
#        logging.info(f"✅ Found nikto at: {nikto_exec}")
        return nikto_exec

    # **Use `locate` (Faster)**
    try:
        locate_cmd = ["locate", "nikto.pl"]
        result = subprocess.run(locate_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        nikto_paths = [path for path in result.stdout.strip().split("\n") if os.path.isfile(path)]
        if nikto_paths:
#            logging.info(f"✅ Found nikto at: {nikto_paths[0]}")
            return nikto_paths[0]
    except Exception:
        logging.warning("⚠ locate command failed, falling back to `find`.")

    # **Use `find` (Slower, Last Resort)**
    try:
        find_cmd = ["find", "/", "-name", "nikto.pl", "-type", "f", "-not", "-path", "*/proc/*"]
        result = subprocess.run(find_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        nikto_paths = [path for path in result.stdout.strip().split("\n") if os.path.isfile(path)]
        if nikto_paths:
#            logging.info(f"✅ Found nikto at: {nikto_paths[0]}")
            return nikto_paths[0]
    except Exception:
        logging.error("❌ `find` command failed.")

    # **Exit Gracefully if nikto is Not Found**
    print("\n❌ ERROR: Nikto not found! Please install it before running this script.")
    print("\nExecute: git clone https://github.com/sec0ps/va-pt.git")
    print("Run the installation script: python3 vapt-installer.py")
    print("Once installation is completed, then run main.py\n")
    sys.exit(1)

# **Ensure NIKTO_PATH is Set**
NIKTO_PATH = find_nikto()
logging.info(f"✅ NIKTO_PATH set to: {NIKTO_PATH}")

def find_zap():
    """Locate zap.sh dynamically using `locate` or `find`, excluding 'Program Files' in WSL."""
#    logging.info("🔍 Searching for zap.sh...")

    # Try using `locate` first (fastest method)
    try:
        result = subprocess.run(["locate", "zap.sh"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        paths = [p for p in result.stdout.strip().split("\n") if "Program Files" not in p]

        if paths:
#            logging.info(f"✅ Found zap.sh at: {paths[0]}")
            return paths[0]  # Return the first valid result

    except subprocess.CalledProcessError:
        logging.warning("⚠ `locate` command failed, falling back to `find`.")

    # Fallback to using `find` if `locate` is not available
    try:
        find_cmd = ["find", "/", "-name", "zap.sh", "-type", "f", "-not", "-path", "'*/proc/*'", "-not", "-path", "'*/mnt/c/Program Files/*'", "2>/dev/null"]
        result = subprocess.run(" ".join(find_cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        paths = [p for p in result.stdout.strip().split("\n") if "Program Files" not in p]

        if paths:
#            logging.info(f"✅ Found zap.sh at: {paths[0]}")
            return paths[0]

    except subprocess.CalledProcessError:
        logging.error("❌ `find` command failed. zap.sh not found.")

    logging.error("❌ zap.sh not found! Ensure OWASP ZAP is installed.")
    return None  # Return None if not found

# Set the ZAP path as a global variable in config
ZAP_PATH = find_zap()
logging.info(f"✅ ZAP_PATH set to: {ZAP_PATH}" if ZAP_PATH else "❌ ZAP_PATH not found!")
