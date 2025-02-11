import os
import json
import logging
import shutil
import subprocess
from cryptography.fernet import Fernet

# Configuration files
KEY_FILE = "encryption.key"
target_file = "automation.config"
ENUMERATION_FILE = ".tmp.enumeration"
API_KEY_FILE = "./.zap_api_key"

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

        logging.info(f"✅ Stored {key} securely in {target_file}")

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
        logging.error(f"❌ {target_file} is corrupted. Deleting and resetting...")
        os.remove(target_file)
        return {}

    except Exception as e:
        logging.error(f"❌ Unexpected error reading {target_file}: {e}")
        return {}

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

def check_target_defined():
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
