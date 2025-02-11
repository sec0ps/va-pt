import subprocess
import xml.etree.ElementTree as ET
import logging
import concurrent.futures
import random
from datetime import datetime
from web import *
from utils import *
from sqlmap import *

def run_nmap_scan(target, scan_type):
    """Run an Nmap scan on a single target with selected scan type."""

    # Generate timestamp for the filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output = f"nmap_scan_results_{timestamp}"

    if scan_type == "1":
        command = [
            "nmap", "-p-", "-sV", "-T5", "--min-rate", "1000", "--max-retries", "1",
            "--open", "-oN", f"{output}.txt", "-oX", f"{output}.xml", "--script=default", target
        ]
    else:
        command = [
            "nmap", "-A", "-T4", "--max-retries", "1", "--open", "--script", "vulners",
            "-oN", f"{output}.txt", "-oX", f"{output}.xml", target
        ]

    print(f"Running Nmap scan on {target}: {' '.join(command)}")
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    parse_nmap_results(f"{output}.xml")


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

        with open("network.enumeration", "a") as f:
            for result in results:
                f.write(result + "\n")

        print(f"Parsed results from {xml_file}")

    except Exception as e:
        logging.error(f"❌ Error parsing Nmap XML results: {e}")


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

if __name__ == "__main__":
    main()
