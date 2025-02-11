import subprocess
import xml.etree.ElementTree as ET
import logging

def run_nmap_scan(target):
    """Run an Nmap scan based on user selection."""
    print("\n[🔍 Network Enumeration Options]")
    print("1️⃣ Fast Scan: Quick service discovery and fingerprinting")
    print("2️⃣ Thorough Scan: In-depth analysis including vulnerability detection")

    scan_type = input("\nSelect an option (1 or 2): ").strip()

    output = "nmap_scan_results"

    if scan_type == "1":
        command = [
            "nmap", "-p-", "-sV", "-T5", "--open", "-oN", f"{output}.txt", "-oX", f"{output}.xml", "--script=default", target
        ]
    elif scan_type == "2":
        command = [
            "nmap", "-A", "-T4", "--open", "--script", "vulners", "-oN", f"{output}.txt", "-oX", f"{output}.xml", target
        ]
    else:
        print("Invalid selection. Please choose either '1' or '2'.")
        return

    print(f"Running Nmap scan: {' '.join(command)}")
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

        with open("network.enumeration", "w") as f:
            for result in results:
                f.write(result + "\n")

        print("HTTP/HTTPS services have been written to network.enumeration")

    except Exception as e:
        logging.error(f"❌ Error parsing Nmap XML results: {e}")
