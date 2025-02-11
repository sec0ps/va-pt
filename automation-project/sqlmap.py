import os
import logging
import subprocess
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import utils  # ✅ Import utils as a module to avoid circular import
from config import NETWORK_ENUMERATION_FILE  # ✅ Import the correct constant

ENUMERATION_FILE_PATH = os.path.abspath(NETWORK_ENUMERATION_FILE)
logging.info(f"🔍 Checking for enumeration file at: {ENUMERATION_FILE_PATH}")

def sqli_automation_enumeration():
    """Run SQLi spider enumeration on all targets stored in network.enumeration using sqlmap in parallel."""

    data = utils.get_encrypted_data()
    SQLMAP_PATH = data.get("SQLMAP_PATH", None)

    if not SQLMAP_PATH or not os.path.exists(SQLMAP_PATH):
        logging.error("❌ SQLMAP_PATH is not set or invalid. Run set_sqlmap_path() first.")
        return

    if not os.path.exists(ENUMERATION_FILE_PATH):  # ✅ Check the correct file path
        logging.error(f"❌ Enumeration file not found at {ENUMERATION_FILE_PATH}. Ensure web application enumeration has been run.")
        return

    with open(ENUMERATION_FILE_PATH, "r") as file:
        targets = file.read().splitlines()

    if not targets:
        logging.warning("⚠ No targets found in enumeration file.")
        return

    logging.info(f"🔍 Starting parallel SQLi automation for {len(targets)} targets...")
    run_bulk_sqlmap(targets)

def run_sqlmap(target):
    """Execute SQLMap for a single target."""
    try:
        logging.info(f"🚀 Running sqlmap on: {target}")

        sqlmap_cmd = [
            "python3", utils.SQLMAP_PATH,
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

        result = subprocess.run(sqlmap_cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            logging.info(f"✅ SQLi scan completed for: {target}")
        else:
            logging.error(f"❌ SQLmap failed on {target}: {result.stderr.strip()}")

    except Exception as e:
        logging.error(f"❌ Unexpected SQLmap error on {target}: {e}")

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
