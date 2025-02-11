import logging
import os
import time
import requests
import socket
from tqdm import tqdm
from ipaddress import ip_network
from urllib.parse import urlparse
from datetime import datetime

# Load API Key once at the start
from utils import load_api_key, encrypt_and_store_data, get_encrypted_data  # Ensure utils handles encryption

#ZAP_API_KEY = load_api_key()
#ZAP_API_URL = "http://127.0.0.1:8080"

#REPORT_DIR = "raw_reports"
#ENUMERATION_FILE = ".tmp.enumeration"

def get_api_key():
    """Return the cached API key."""
    return ZAP_API_KEY

def check_zap_running():
    """Check if OWASP ZAP API is accessible with retries."""
    max_retries = 5
    retry_delay = 3
    api_url = f"{ZAP_API_URL}/JSON/core/view/version/?apikey={get_api_key()}"

    for attempt in range(1, max_retries + 1):
        try:
            logging.info(f"🔍 Checking OWASP ZAP API availability (Attempt {attempt}/{max_retries})...")
            response = requests.get(api_url, timeout=5)
            response.raise_for_status()
            zap_version = response.json().get('version', 'Unknown')
            logging.info(f"✅ Connected to ZAP Proxy at {ZAP_API_URL}, version: {zap_version}")
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"⚠ ZAP API connection issue: {e}")

        time.sleep(retry_delay)

    logging.error("❌ Max retries reached. ZAP API is not accessible. Exiting...")
    sys.exit(1)

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

def web_application_enumeration():
    """Scan web applications found in a CIDR range or a single target."""
    target = check_target_defined()

    try:
        ip_network(target)  # If this doesn't raise an error, it's a CIDR block
        is_cidr = True
    except ValueError:
        is_cidr = False

    if not is_cidr:
        if not target.startswith(("http://", "https://")):
            logging.error("❌ Invalid URL format. Please enter a valid URL.")
            return
        try:
            logging.info(f"🚀 Starting active scan on: {target}")
            scan_target_with_zap(target)  # Ensure a string URL is passed
        except Exception as e:
            logging.error(f"❌ Error scanning {target}: {e}")
        return

    # CIDR Handling
    logging.info(f"🌍 Expanding CIDR network: {target}")

    target_ips = list(ip_network(target).hosts())  # Get all hosts in the network
    with tqdm(total=len(target_ips), desc="Scanning Progress", unit="host", dynamic_ncols=True) as pbar:
        for ip in target_ips:
            ip_str = str(ip)
            try:
                target_url = check_web_service(ip_str)
                if target_url:
                    logging.info(f"🚀 Starting active scan on: {target_url}")
                    scan_target_with_zap(target_url)  # Ensure a single string is passed
                time.sleep(2)  # Simulate processing time
            except Exception as e:
                if "No route to host" not in str(e):  # Suppress only connection errors
                    logging.error(f"❌ Error scanning {ip_str}: {e}")
            finally:
                pbar.update(1)

    logging.info("✅ Scanning job completed.")

def export_zap_xml_report(target_url):
    """Fetch and save the OWASP ZAP scan report in XML format."""
    try:
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR, exist_ok=True)
            os.chmod(REPORT_DIR, 0o700)  # Secure directory

        parsed_url = urlparse(target_url)
        target_name = parsed_url.hostname.replace(".", "_")  # Convert dots to underscores
        report_file = os.path.join(REPORT_DIR, f"zap_report_{target_name}.xml")

        url = f"{ZAP_API_URL}/OTHER/core/other/xmlreport/?apikey={ZAP_API_KEY}"
        logging.info(f"📄 Fetching XML report for {target_url} from {url}")

        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            with open(report_file, "wb") as file:
                file.write(response.content)
            logging.info(f"✅ XML report saved: {report_file}")
        else:
            logging.error(f"❌ Failed to fetch XML report. Status Code: {response.status_code}")

    except requests.RequestException as e:
        logging.error(f"❌ Error connecting to ZAP API: {e}")

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
