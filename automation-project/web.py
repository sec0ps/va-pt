import logging
import os
import time
import requests
import socket
import sys
from tqdm import tqdm
from ipaddress import ip_network
from urllib.parse import urlparse, urlunparse
from datetime import datetime
import concurrent.futures
import random
import subprocess
from nmap import *
from sql import *
from config import load_api_key, ZAP_API_URL, ZAP_API_KEY, find_nikto, NETWORK_ENUMERATION_FILE, ZAP_DIR, ZAP_PATH
from utils import store_data, get_stored_data, is_valid_ipv4, is_valid_ipv6, is_valid_fqdn, is_valid_cidr, check_target_defined, stop_zap

def check_zap_running():
    """Check if OWASP ZAP API is accessible with retries.

    If ZAP is not running, it will be started in headless mode.

    Returns:
        bool: True if ZAP is running, False otherwise.
    """
    max_retries = 5
    retry_delay = 3
    api_url = f"{ZAP_API_URL}/JSON/core/view/version/?apikey={ZAP_API_KEY}"

    for attempt in range(1, max_retries + 1):
        try:
            logging.info(f"🔍 Checking OWASP ZAP API availability (Attempt {attempt}/{max_retries})...")
            response = requests.get(api_url, timeout=5)
            response.raise_for_status()
            zap_version = response.json().get('version', 'Unknown')
            logging.info(f"✅ Connected to ZAP Proxy at {ZAP_API_URL}, version: {zap_version}")
            return True
        except requests.exceptions.RequestException:
            logging.warning(f"⚠ ZAP API is not available (Attempt {attempt}/{max_retries})...")
            time.sleep(retry_delay)

    logging.error("❌ ZAP API is not accessible. Attempting to start ZAP in headless mode...")
    start_zap_headless()

    # Retry after attempting to start ZAP
    return check_zap_running()

def start_zap_headless():
    """Start OWASP ZAP in headless mode with session persistence."""
    if not os.path.exists(ZAP_PATH):
        logging.error("❌ ZAP binary not found. Ensure ZAP is installed and ZAP_PATH is correct.")
        return False

    # Ensure zap_exports directory exists
    os.makedirs(ZAP_DIR, exist_ok=True)

    # Generate session file name based on timestamp
    session_filename = f"zap_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    session_path = os.path.join(ZAP_DIR, session_filename)

    logging.info(f"🚀 Starting OWASP ZAP in headless mode with session stored at: {session_path}")

    try:
        # Start ZAP in daemon mode
        zap_command = [
            ZAP_PATH, "-daemon",
            "-host", "127.0.0.1",  # Bind to localhost
            "-port", "8080",  # Explicitly set port to 8080
            "-config", f"api.key={ZAP_API_KEY}",
            "-newsession", session_path  # Store session in ZAP_DIR
        ]

        subprocess.Popen(zap_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for ZAP to initialize
        time.sleep(10)

        # Verify if ZAP is running by checking the API
        zap_api_url = f"http://127.0.0.1:8080/JSON/core/view/version/?apikey={ZAP_API_KEY}"
        response = subprocess.run(["curl", "-s", zap_api_url], capture_output=True, text=True)

        if "version" in response.stdout:
            logging.info("✅ OWASP ZAP is running in headless mode.")
            return True
        else:
            logging.error("❌ OWASP ZAP failed to start.")
            return False

    except Exception as e:
        logging.error(f"❌ Error starting ZAP: {e}")
        return False

def process_network_enumeration():
    """Check if network.enumeration exists and has valid targets; otherwise, use the stored target."""
    data = get_stored_data()
    target = data.get("target")

    if os.path.exists(NETWORK_ENUMERATION_FILE):
        logging.info(f"📄 Found {NETWORK_ENUMERATION_FILE}. Processing targets...")

        with open(NETWORK_ENUMERATION_FILE, "r") as file:
            targets = file.read().splitlines()

        if not targets:
            logging.warning(f"⚠ {NETWORK_ENUMERATION_FILE} is empty. Using stored target instead.")
        else:
            logging.info(f"✅ Found targets in {NETWORK_ENUMERATION_FILE}")
            for t in targets:
                clean_target = t.strip()  # ✅ Remove extra spaces or newlines
                if not clean_target:
                    continue  # Skip empty lines

                parsed_url = urlparse(clean_target)
                if not parsed_url.scheme or not parsed_url.netloc:
                    logging.error(f"❌ Invalid URL format detected in network.enumeration: {clean_target}")
                    continue  # Skip invalid URLs

                logging.info(f"🚀 Valid target found: {clean_target}")
                web_application_enumeration(clean_target)
            return  # ✅ Exit after processing network enumeration targets

    # ✅ If `network.enumeration` is missing or empty, use stored target
    logging.warning(f"⚠ {NETWORK_ENUMERATION_FILE} not found. Using stored target instead.")

    if not target:
        logging.error("❌ No valid target found. Exiting enumeration.")
        return

    clean_target = target.strip().replace("http://", "").replace("https://", "")  # ✅ Strip protocol before use

    if is_valid_fqdn(clean_target):
        logging.info(f"🚀 Starting web application enumeration for FQDN target: {clean_target}")
        web_application_enumeration(f"http://{clean_target}")
        web_application_enumeration(f"https://{clean_target}")

    elif is_valid_ipv4(clean_target) or is_valid_ipv6(clean_target) or is_valid_cidr(clean_target):
        logging.info(f"🚀 Starting web application enumeration for target: {clean_target}")
        web_application_enumeration(clean_target)
    else:
        logging.error(f"❌ Invalid target format: {clean_target}")

def check_web_service(ip):
    """Determine if the given IP has an active web service and return the correct URL."""
    ports = [(443, "https"), (80, "http")]  # Prioritize HTTPS first
    for port, scheme in ports:
        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                detected_url = f"{scheme}://{ip}:{port}"
                logging.info(f"✅ Secure web service detected: {detected_url}")
                return detected_url  # Return a single string
        except (socket.timeout, ConnectionRefusedError):
            continue  # Try the next port

    return None  # No web service found

from urllib.parse import urlparse, urlunparse

def web_application_enumeration(target):
    """Scan web applications found in a CIDR range or a single target."""

    target = target.strip()  # ✅ Remove any leading/trailing spaces

    # ✅ Ensure target is a properly formatted URL
    parsed_url = urlparse(target)

    # ✅ If the scheme is missing, assume HTTP
    if not parsed_url.scheme:
        logging.warning(f"⚠ No scheme found in target: {target}. Assuming 'http://'.")
        target = f"http://{target}"
        parsed_url = urlparse(target)  # Re-parse after adding scheme

    # ✅ Ensure target contains both scheme and netloc (host)
    if not parsed_url.netloc:
        logging.error(f"❌ Invalid URL format: {target}")
        return

    # ✅ Reconstruct the URL to ensure consistency
    formatted_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

    logging.info(f"🚀 Starting web scan on: {formatted_url}")

    try:
        logging.info(f"🚀 Sending target to ZAP: {formatted_url}")
        scan_target_with_zap(formatted_url)
    except Exception as e:
        logging.error(f"❌ Error scanning {formatted_url}: {e}")

def scan_target_with_zap(target_url):
    """Scan a web service using OWASP ZAP."""
    logging.info(f"🚀 Starting ZAP scan on: {target_url}")

    session = requests.Session()
    headers = {"Content-Type": "application/json"}

    try:
        spider_url = f"{ZAP_API_URL}/JSON/spider/action/scan/?apikey={ZAP_API_KEY}&url={requests.utils.quote(target_url)}&recurse=true"
        response = session.get(spider_url, headers=headers, timeout=10)
        response.raise_for_status()
        scan_id = response.json().get("scan", "-1")
        logging.info(f"✅ Spider started for {target_url} with Scan ID: {scan_id}")
    except requests.RequestException as e:
        logging.error(f"❌ Failed to start Spider: {e}")
        return

    spider_status_url = f"{ZAP_API_URL}/JSON/spider/view/status/?apikey={ZAP_API_KEY}&scanId={scan_id}"
    while True:
        try:
            response = session.get(spider_status_url, headers=headers, timeout=10)
            status = response.json().get("status", "0")
            logging.info(f"🕷 Spider Progress: {status}%")
            if status == "100":
                break
        except requests.RequestException as e:
            logging.error(f"❌ Error checking Spider progress: {e}")
            break
        time.sleep(10)

    # Start Active Scan
    try:
        active_scan_url = f"{ZAP_API_URL}/JSON/ascan/action/scan/?apikey={ZAP_API_KEY}&url={requests.utils.quote(target_url)}"
        response = session.get(active_scan_url, headers=headers, timeout=10)
        response.raise_for_status()
        scan_id = response.json().get("scan", "-1")
        logging.info(f"✅ Active scan started for {target_url} with Scan ID: {scan_id}")
    except requests.RequestException as e:
        logging.error(f"❌ Failed to start Active Scan: {e}")
        return

    scan_status_url = f"{ZAP_API_URL}/JSON/ascan/view/status/?apikey={ZAP_API_KEY}&scanId={scan_id}"
    while True:
        try:
            response = session.get(scan_status_url, headers=headers, timeout=10)
            status = response.json().get("status", "0")
            logging.info(f"🔥 Active Scan Progress: {status}%")
            if status == "100":
                break
        except requests.RequestException as e:
            logging.error(f"❌ Error checking Active Scan progress: {e}")
            break
        time.sleep(10)

    export_zap_xml_report(target_url)

def export_zap_xml_report(target_url):
    """Fetch and save the OWASP ZAP scan report in XML format, then launch Nikto in parallel."""
    try:
        REPORT_DIR = "raw_reports"

        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR, exist_ok=True)
            os.chmod(REPORT_DIR, 0o700)

        parsed_url = urlparse(target_url)
        target_name = parsed_url.hostname.replace(".", "_")
        report_file = os.path.join(REPORT_DIR, f"zap_report_{target_name}.xml")

        url = f"{ZAP_API_URL}/OTHER/core/other/xmlreport/?apikey={ZAP_API_KEY}"
        logging.info(f"📄 Fetching XML report for {target_url} from {url}")

        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            with open(report_file, "wb") as file:
                file.write(response.content)
            logging.info(f"✅ XML report saved: {report_file}")

            # ✅ Debug Logging Before Starting Nikto
#            logging.info(f"🔎 Checking if Nikto exists before launching scan for {target_url}...")
            nikto_path = find_nikto()

            if nikto_path:
                logging.info(f"🚀 Found Nikto at {nikto_path}, launching scan for {target_url}")

                # ✅ Execute Nikto in Parallel
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    executor.submit(run_nikto_scan, target_url, nikto_path)
                logging.info(f"🔄 Nikto scan should now be running for {target_url}")
            else:
                logging.error("❌ Nikto not found! Skipping Nikto scan.")

        else:
            logging.error(f"❌ Failed to fetch XML report. Status Code: {response.status_code}")

    except requests.RequestException as e:
        logging.error(f"❌ Error connecting to ZAP API: {e}")

def select_nikto_targets():
    """Determine the correct targets for Nikto scanning and execute scans accordingly."""
#    logging.info("🔍 [DEBUG] Entered select_nikto_targets()...")

    nikto_path = find_nikto()
    if not nikto_path:
        logging.error("❌ Nikto not found! Skipping Nikto scans.")
        return

#    logging.info(f"✅ [DEBUG] Found Nikto at: {nikto_path}")

    if os.path.exists(NETWORK_ENUMERATION_FILE):
        logging.info(f"📄 Found {NETWORK_ENUMERATION_FILE}. Using it for Nikto scans.")

        with open(NETWORK_ENUMERATION_FILE, "r") as file:
            targets = file.read().splitlines()

        for target in targets:
            logging.info(f"✅ Running Nikto scan on: {target}")
            run_nikto_scan(target, nikto_path)  # ✅ Pass nikto_path

        return

    target = get_stored_data("target")

    if not target:
        logging.warning("⚠ No valid target found. Nikto scan skipped.")
        return

 #   logging.info(f"🎯 [DEBUG] Selected target from config: {target}")

    if is_valid_cidr(target):
        logging.info(f"🌍 Expanding CIDR block: {target}")

        for ip in ip_network(target).hosts():
            ip_str = str(ip)
#            logging.info(f"🔎 [DEBUG] Checking web services on {ip_str}...")

            https_target = f"https://{ip_str}:443"
            http_target = f"http://{ip_str}:80"

            if check_web_service(ip_str) == https_target:
                logging.info(f"✅ Found active HTTPS service: {https_target}")
                run_nikto_scan(https_target, nikto_path)  # ✅ Pass nikto_path

            elif check_web_service(ip_str) == http_target:
                logging.info(f"✅ Found active HTTP service: {http_target}")
                run_nikto_scan(http_target, nikto_path)  # ✅ Pass nikto_path

        logging.info("✅ CIDR expansion completed.")
        return

    if is_valid_ipv4(target) or is_valid_ipv6(target) or is_valid_fqdn(target):
        logging.info(f"✅ Running Nikto scan on: {target}")
        run_nikto_scan(target, nikto_path)  # ✅ Pass nikto_path
        return

    logging.warning("⚠ No valid target found for Nikto scan.")

def run_nikto_scan(target, nikto_path):
    """Run a Nikto scan against the target using the dynamically located Nikto."""
#    logging.info(f"🚀 [DEBUG] Preparing Nikto scan for: {target}")

    if not nikto_path:
        logging.error("❌ Nikto not found on the system. Ensure it is installed.")
        return

    logging.info(f"✅ Using Nikto path: {nikto_path}")

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
    ]

    random_user_agent = f'"{random.choice(user_agents)}"'  # ✅ Wrap User-Agent in quotes

    # ✅ Convert IP/FQDN to ZAP-style filename format
    parsed_url = urlparse(target)
    host = parsed_url.hostname if parsed_url.hostname else target
    filename_safe_target = host.replace(".", "_")  # Convert dots to underscores

    # ✅ Define report file paths
    xml_report = f"nikto_report_{filename_safe_target}.xml"
    csv_report = f"nikto_report_{filename_safe_target}.csv"

    # ✅ Remove `-p` flag since we are passing a full URL
    nikto_command = [
        "perl", nikto_path, "-h", target,
        "-Tuning", "x", "-C", "all", "-Plugins", "all",
        "-timeout", "30",
        "-o", xml_report, "-Format", "xml",
        "-o", csv_report, "-Format", "csv",
        "-useragent", random_user_agent  # ✅ Wrapped in quotes
    ]

#    logging.info(f"📢 [DEBUG] Running Nikto command: {' '.join(nikto_command)}")

    try:
        result = subprocess.run(nikto_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        logging.info(f"✅ Nikto scan completed for {target}.\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Nikto scan failed for {target}: {e.stderr}")

def main():
    """Main function to determine whether to use `network.enumeration` or perform web enumeration."""
    logging.info("🔎 Checking for existing network enumeration results...")
    process_network_enumeration()

if __name__ == "__main__":
    main()
