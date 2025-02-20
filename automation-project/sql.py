import os
import logging
import subprocess
from tqdm import tqdm
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import utils
from config import NETWORK_ENUMERATION_FILE, SQLMAP_PATH

ENUMERATION_FILE_PATH = os.path.abspath(NETWORK_ENUMERATION_FILE)
logging.info(f"🔍 Checking for enumeration file at: {ENUMERATION_FILE_PATH}")

def sqli_automation_enumerations():
    """Run SQLi spider enumeration on all targets stored in network.enumeration using sqlmap in parallel.

    - If `network.enumeration` exists, use it.
    - If it does not exist or is empty, use the stored `target` from config.
    """

    data = utils.get_stored.data()

    # ✅ Ensure SQLMAP_PATH is valid
    sqlmap_path = SQLMAP_PATH or data.get("SQLMAP_PATH", None)
    if not sqlmap_path or not os.path.exists(sqlmap_path):
        logging.error("❌ SQLMAP_PATH is not set or invalid. Run set_sqlmap_path() first.")
        return

    targets = []

    # ✅ Try loading targets from `network.enumeration`
    if os.path.exists(ENUMERATION_FILE_PATH):
        logging.info(f"📄 Using targets from {ENUMERATION_FILE_PATH}.")
        try:
            with open(ENUMERATION_FILE_PATH, "r") as file:
                targets = file.read().splitlines()
        except Exception as e:
            logging.error(f"❌ Failed to read {ENUMERATION_FILE_PATH}: {e}")

    # ✅ If `network.enumeration` is missing or empty, fallback to stored `target`
    if not targets:
        logging.warning(f"⚠ {ENUMERATION_FILE_PATH} not found or empty. Falling back to stored target.")

        target = data.get("target", None)

        if target:
            if isinstance(target, list):
                targets = target  # ✅ Handle HTTP/HTTPS stored as a list
            else:
                targets = [target]  # ✅ Convert single target into a list
        else:
            logging.error("❌ No valid target found. Ensure you set a target before running SQLi testing.")
            return

    logging.info(f"🔍 Starting parallel SQLi automation for {len(targets)} targets...")
    run_bulk_sqlmap(targets, sqlmap_path)

def run_sqlmap(target, sqlmap_path):
    """Execute SQLMap for a single target and save results in XML format."""

    if not sqlmap_path or not os.path.exists(sqlmap_path):
        logging.error(f"❌ SQLMAP_PATH is invalid or does not exist: {sqlmap_path}")
        return

    # ✅ Convert target IP/FQDN to filename-safe format (Replace dots with underscores)
    parsed_url = urlparse(target)
    host = parsed_url.hostname if parsed_url.hostname else target

    # ✅ Convert CIDR to filename-safe format (Replace dots & slashes)
    safe_filename = host.replace(".", "_").replace("/", "_")


    # ✅ Define report paths
    report_dir = "sqlmap_reports"
    os.makedirs(report_dir, exist_ok=True)  # Ensure directory exists
    xml_report = os.path.join(report_dir, f"sqlmap_report_{safe_filename}.xml")

    try:
        logging.info(f"🚀 Running SQLMap on: {target}")

        sqlmap_cmd = [
            "python3", sqlmap_path,
            "--url", target,
            "--crawl", "20",
            "--batch",
            "--random-agent",
            "--technique", "BEUST",
            "--forms",
            "--dbs",
            "--current-user",
            "--current-db",
            "--hostname",
            "--output-dir", report_dir,  # ✅ Store results in reports folder
            "--threads", "10" # ✅ Increases parallel requests (faster results)
            "--disable-coloring"  # ✅ Ensures clean XML output
        ]

        logging.info(f"🛠 SQLMap Command: {' '.join(sqlmap_cmd)}")

        # ✅ Run SQLMap and capture output
        process = subprocess.Popen(sqlmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        with open(xml_report, "w") as file:
            for line in process.stdout:
                print(line, end="")  # ✅ Show real-time output
                file.write(line)  # ✅ Save to XML report file
                logging.info(line.strip())

        process.wait()

        if process.returncode == 0:
            logging.info(f"✅ SQLi scan completed successfully. Report saved: {xml_report}")
        else:
            logging.error(f"❌ SQLMap encountered an error on {target}")

    except Exception as e:
        logging.error(f"❌ Unexpected SQLMap error on {target}: {e}")

def run_bulk_sqlmap(targets, sqlmap_path):
    """Run SQLMap on multiple targets in parallel."""
    if not targets:
        logging.warning("⚠ No targets found. Skipping SQLi scanning.")
        return

    logging.info(f"🔍 Starting SQLi automation for {len(targets)} targets...")

    with ThreadPoolExecutor(max_workers=5) as executor:
        list(tqdm(executor.map(lambda target: run_sqlmap(target, sqlmap_path), targets), total=len(targets), desc="SQLi Scanning", unit="target"))

def sqli_testing_automation(sqlmap_path):
    """Run SQLi spider enumeration using sqlmap on all targets stored in network.enumeration.

    - If `network.enumeration` exists, use it.
    - If it does not exist or is empty, fall back to the stored target.
    """

    if not sqlmap_path or not os.path.exists(sqlmap_path):
        logging.error("❌ SQLMAP_PATH is invalid. Ensure sqlmap is installed.")
        return

    targets = []

    # ✅ Try using `network.enumeration` first
    if os.path.exists(ENUMERATION_FILE_PATH):
        logging.info(f"📄 Using targets from {ENUMERATION_FILE_PATH}.")
        try:
            with open(ENUMERATION_FILE_PATH, "r") as file:
                targets = [line.strip() for line in file if line.strip()]
        except Exception as e:
            logging.error(f"❌ Failed to read {ENUMERATION_FILE_PATH}: {e}")

    # ✅ If `network.enumeration` is missing or empty, fall back to the stored target
    if not targets:
        logging.warning(f"⚠ {ENUMERATION_FILE_PATH} not found or empty. Falling back to stored target.")

        data = utils.get_stored_data()  # ✅ Fetch stored target securely
        target = data.get("target", None)

        if target:
            targets = [target] if isinstance(target, str) else target  # ✅ Convert single string to a list
        else:
            logging.error("❌ No valid target found. Ensure you set a target before running SQLi testing.")
            return

    if not targets:
        logging.warning("⚠ No targets found. Skipping SQLi scanning.")
        return

    logging.info(f"🔍 Starting SQLi automation for {len(targets)} targets...")
    run_bulk_sqlmap(targets, sqlmap_path)
