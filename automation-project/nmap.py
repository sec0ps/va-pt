import os
import subprocess
import xml.etree.ElementTree as ET
import logging
import concurrent.futures
import random
from datetime import datetime
from config import NETWORK_ENUMERATION_FILE, RAW_NMAP_DIR  # ✅ Import constants directly

# Ensure raw_nmap directory exists
os.makedirs(RAW_NMAP_DIR, exist_ok=True)

def run_nmap_scan(target, scan_type):
    """Run an Nmap scan on a single target with selected scan type."""

    # Generate timestamp in "YYYY-MM-DD.HH-MM-SS" format
    timestamp = datetime.now().strftime("%Y-%m-%d.%H-%M-%S")
    output_txt = os.path.join(RAW_NMAP_DIR, f"{timestamp}.txt")
    output_xml = os.path.join(RAW_NMAP_DIR, f"{timestamp}.xml")

    if scan_type == "1":
        command = [
            "nmap", "-p-", "-sV", "-T5", "--min-rate", "1000", "--max-retries", "1",
            "--open", "-oN", output_txt, "-oX", output_xml, "--script=default", target
        ]
    else:
        command = [
            "nmap", "-A", "-T4", "--max-retries", "1", "--open", "--script", "vulners",
            "-oN", output_txt, "-oX", output_xml, target
        ]

    print(f"Running Nmap scan on {target}: {' '.join(command)}")
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    parse_nmap_results(output_xml)

def parse_nmap_results(xml_file):
    """Parse Nmap XML results and extract HTTP/HTTPS services."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        results = []

        for host in root.findall(".//host"):
            ip_addr = host.find("address").get("addr")
            for port in host.findall(".//port"):
                port_id = port.get("portid")
                service = port.find("service")
                if service is not None:
                    service_name = service.get("name", "")
                    if "http" in service_name:
                        protocol = "https" if "ssl" in service_name or port_id in ["443", "8443", "4443"] else "http"
                        results.append(f"{protocol}://{ip_addr}:{port_id}")

        # ✅ Append results to network.enumeration
        with open(NETWORK_ENUMERATION_FILE, "a") as f:
            for result in results:
                f.write(result + "\n")

        print(f"Parsed results from {xml_file}")

    except Exception as e:
        logging.error(f"❌ Error parsing Nmap XML results: {e}")

def deduplicate_network_enumeration():
    """Remove duplicate entries from network.enumeration."""
    if not os.path.exists(NETWORK_ENUMERATION_FILE):
        return

    try:
        with open(NETWORK_ENUMERATION_FILE, "r") as file:
            unique_entries = set(file.read().splitlines())

        with open(NETWORK_ENUMERATION_FILE, "w") as file:
            for entry in sorted(unique_entries):  # Sorted for consistency
                file.write(entry + "\n")

        print(f"✅ Deduplicated {NETWORK_ENUMERATION_FILE}")

    except Exception as e:
        logging.error(f"❌ Failed to deduplicate {NETWORK_ENUMERATION_FILE}: {e}")

def main():
    """Main function to handle parallel scanning and randomization."""
    targets = [
        "192.168.1.1", "192.168.1.2", "192.168.1.3",  # Add your target IPs here
        "192.168.1.4", "192.168.1.5", "192.168.1.6"
    ]

    random.shuffle(targets)  # Randomize the scan order

    print("\n[🔍 Network Enumeration Options]")
    print("1️⃣ Fast Scan: Quick service discovery and fingerprinting")
    print("2️⃣ Thorough Scan: In-depth analysis including vulnerability detection")

    scan_type = input("\nSelect an option (1 or 2): ").strip()
    if scan_type not in ["1", "2"]:
        print("Invalid selection. Exiting.")
        return

    max_threads = 5  # Adjust the level of parallelism as needed

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(lambda target: run_nmap_scan(target, scan_type), targets)

    # Deduplicate network.enumeration file after scan completion
    deduplicate_network_enumeration()

if __name__ == "__main__":
    main()
