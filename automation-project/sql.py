import os
import logging
import subprocess
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import utils  # ✅ Import utils as a module to avoid circular import
from config import NETWORK_ENUMERATION_FILE  # ✅ Import the correct constant

ENUMERATION_FILE_PATH = os.path.abspath(NETWORK_ENUMERATION_FILE)
logging.info(f"🔍 Checking for enumeration file at: {ENUMERATION_FILE_PATH}")

def sqli_automation_enumerations():
    """Run SQLi spider enumeration on all targets stored in network.enumeration using sqlmap in parallel.

    - If `network.enumeration` exists, use it.
    - If it does not exist, use the stored `target` from the config.
    """

    data = utils.get_encrypted_data()
    SQLMAP_PATH = data.get("SQLMAP_PATH", None)

    if not SQLMAP_PATH or not os.path.exists(SQLMAP_PATH):
        logging.error("❌ SQLMAP_PATH is not set or invalid. Run set_sqlmap_path() first.")
        return

    targets = []

    if os.path.exists(ENUMERATION_FILE_PATH):  # ✅ Check if the enumeration file exists
        logging.info(f"📄 Using targets from {ENUMERATION_FILE_PATH}.")
        try:
            with open(ENUMERATION_FILE_PATH, "r") as file:
                targets = file.read().splitlines()
        except Exception as e:
            logging.error(f"❌ Failed to read {ENUMERATION_FILE_PATH}: {e}")

    # ✅ Check if enumeration file was empty
    if not targets:
        logging.warning(f"⚠ {ENUMERATION_FILE_PATH} not found or empty. Falling back to stored target.")

        # ✅ Fetch the stored target securely
        target = utils.get_encrypted_data("target")

        if target:
            if isinstance(target, list):  # Handle list-based FQDNs with http/https
                targets = target
            else:
                targets = [target]  # Convert single string to a list

        else:
            logging.error("❌ No valid target found. Ensure you set a target before running SQLi testing.")
            return

    logging.info(f"🔍 Starting parallel SQLi automation for {len(targets)} targets...")
    run_bulk_sqlmap(targets)

def run_sqlmap(target):
    """Execute SQLMap for a single target."""

    from config import SQLMAP_PATH  # ✅ Fetch correct SQLMAP_PATH dynamically

    if not SQLMAP_PATH or not os.path.exists(SQLMAP_PATH):
        logging.error(f"❌ SQLMAP_PATH is invalid or does not exist: {SQLMAP_PATH}")
        return

    try:
        logging.info(f"🚀 Running SQLMap on: {target}")

        sqlmap_cmd = [
            "python3", SQLMAP_PATH,  # ✅ Use SQLMAP_PATH from config
            "--url", target,
            "--level", "5",
            "--risk", "3",
            "--crawl", "20",
            "--batch",
            "--random-agent",
            "--technique", "BEUST",
            "--dbs",
            "--current-user",
            "--current-db",
            "--hostname"
        ]

        logging.info(f"🛠 SQLMap Command: {' '.join(sqlmap_cmd)}")  # ✅ Log actual command being executed

        # ✅ Run SQLMap with live output (SHOWS OUTPUT IN REAL TIME)
        process = subprocess.Popen(sqlmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for line in process.stdout:
            print(line, end="")  # ✅ Print SQLMap output in real time
            logging.info(line.strip())  # ✅ Log SQLMap output

        process.wait()  # ✅ Wait for SQLMap to finish

        if process.returncode == 0:
            logging.info(f"✅ SQLi scan completed successfully for: {target}")
        else:
            logging.error(f"❌ SQLMap encountered an error on {target}")

    except Exception as e:
        logging.error(f"❌ Unexpected SQLMap error on {target}: {e}")

def run_bulk_sqlmap(targets):
    """Run SQLMap on multiple targets in parallel."""
    if not targets:
        logging.warning("⚠ No targets found. Skipping SQLi scanning.")
        return

    logging.info(f"🔍 Starting SQLi automation for {len(targets)} targets...")

    with ThreadPoolExecutor(max_workers=5) as executor:
        list(tqdm(executor.map(run_sqlmap, targets), total=len(targets), desc="SQLi Scanning", unit="target"))

def sqli_testing_automation(sqlmap_path):
    """Run SQLi spider enumeration using sqlmap on all targets stored in network.enumeration."""
    if not sqlmap_path or not os.path.exists(sqlmap_path):
        logging.error("❌ SQLMAP_PATH is invalid. Ensure sqlmap is installed.")
        return

    if not os.path.exists(ENUMERATION_FILE_PATH):  # ✅ Check correct file path
        logging.error(f"❌ Enumeration file not found at {ENUMERATION_FILE_PATH}. Ensure web application enumeration has been run.")
        return

    with open(ENUMERATION_FILE_PATH, "r") as file:
        targets = [line.strip() for line in file if line.strip()]

    if not targets:
        logging.warning("⚠ No targets found in enumeration file.")
        return

    logging.info(f"🔍 Starting SQLi automation for {len(targets)} targets...")
    run_bulk_sqlmap(targets)  # ✅ Calls parallel SQLi execution
