import os
import subprocess
import xml.etree.ElementTree as ET
import logging
import concurrent.futures
from datetime import datetime
from config import NETWORK_ENUMERATION_FILE, RAW_NMAP_DIR
from utils import is_valid_ipv4, is_valid_ipv6, is_valid_fqdn, is_valid_cidr

# Ensure raw_nmap directory exists
os.makedirs(RAW_NMAP_DIR, exist_ok=True)

def format_target_name(target):
    """Format target name for logging (IP, CIDR, FQDN)."""
    if is_valid_ipv4(target) or is_valid_ipv6(target):
        return target.replace(".", "_")  # Convert dots to underscores for IPs
    elif is_valid_cidr(target):
        return target.replace(".", "_").replace("/", "_")  # Handle CIDR format
    elif is_valid_fqdn(target):
        return target.replace(".", "_")  # Convert dots to underscores for FQDNs
    else:
        logging.error(f"❌ Invalid target format: {target}")
        return None

def run_nmap_scan(target, scan_type):
    """Run an Nmap scan on a single target with optimized parameters and real-time output."""

    if isinstance(target, list):
        target = target[0]  # Ensure target is a string

    formatted_target = format_target_name(target)
    if not formatted_target:
        return

    # Generate timestamp in "YYYY-MM-DD.HH-MM-SS" format
    timestamp = datetime.now().strftime("%Y-%m-%d.%H-%M-%S")

    output_txt = os.path.join(RAW_NMAP_DIR, f"{formatted_target}_{timestamp}.txt")
    output_xml = os.path.join(RAW_NMAP_DIR, f"{formatted_target}_{timestamp}.xml")

    # ✅ Choose scan type with optimized flags
    if scan_type == "1":
        command = [
            "nmap", "-p-", "-sV", "-T5", "--min-rate", "1000", "--max-retries", "1",
            "--open", "--min-hostgroup", "64",
            "-oN", output_txt, "-oX", output_xml, "--script=default", target
        ]
    else:
        command = [
            "nmap", "-A", "-T4", "--max-retries", "1", "--open", "--script", "vulners",
            "--min-hostgroup", "64",
            "-oN", output_txt, "-oX", output_xml, target
        ]

    logging.info(f"🚀 Running Nmap scan on {target}: {' '.join(command)}")

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line.strip())
            logging.info(line.strip())

        process.wait()

        if process.returncode == 0:
            logging.info(f"✅ Nmap scan completed successfully for {target}")
        else:
            logging.error(f"❌ Nmap scan failed on {target} with return code {process.returncode}")

        # ✅ Pass the original target to `parse_nmap_results()` to ensure the correct FQDN is used
        parse_nmap_results(output_xml, target)

    except Exception as e:
        logging.error(f"❌ Unexpected error running Nmap scan on {target}: {e}")

def run_bulk_nmap_scan(targets, scan_type):
    """Run multiple Nmap scans in parallel using ThreadPoolExecutor."""
    if not isinstance(targets, list):
        targets = [targets]  # ✅ Convert a single target into a list

    if not targets:
        logging.error("❌ No valid targets provided. Skipping Nmap scanning.")
        return

    # ✅ Ensure all targets are valid strings (not single characters)
    valid_targets = [t for t in targets if isinstance(t, str) and len(t) > 3]  # Filter out incorrect targets

    if not valid_targets:
        logging.error("❌ No valid targets after filtering. Exiting Nmap scanning.")
        return

    logging.info(f"🔍 Starting parallel Nmap scans for {len(valid_targets)} targets...")

    # ✅ Run scans in parallel with a max of 5 concurrent scans
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(lambda target: run_nmap_scan(target, scan_type), valid_targets)

    logging.info("✅ All parallel Nmap scans completed.")

def parse_nmap_results(xml_file, original_target):
    """Parse Nmap XML results and extract all detected HTTP/HTTPS services, preserving the original FQDN."""

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        results = []

        for host in root.findall(".//host"):
            ip_addr = host.find("address").get("addr")  # Extract resolved IP from scan
            fqdn_used = original_target if is_valid_fqdn(original_target) else ip_addr  # Use FQDN if target was an FQDN

            for port in host.findall(".//port"):
                port_id = port.get("portid")  # Extract the actual port number dynamically
                service = port.find("service")

                if service is not None:
                    service_name = service.get("name", "").lower()

                    # ✅ Determine protocol dynamically based on service name
                    if "ssl" in service_name or "https" in service_name:
                        protocol = "https"
                    else:
                        protocol = "http"

                    results.append(f"{protocol}://{fqdn_used}:{port_id}")

        # ✅ Write results to network.enumeration file
        with open(NETWORK_ENUMERATION_FILE, "a") as f:
            for result in results:
                f.write(result + "\n")

        logging.info(f"✅ Parsed results from {xml_file} and saved to {NETWORK_ENUMERATION_FILE}")

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
