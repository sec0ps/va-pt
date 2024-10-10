import sys
import os
import subprocess
from threading import Thread

def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Check for required packages and install if missing
try:
    import easysnmp
except ImportError:
    print("Installing easysnmp...")
    install_package("easysnmp")

try:
    import pysnmp
except ImportError:
    print("Installing pysnmp...")
    install_package("pysnmp")

try:
    import tftpy
except ImportError:
    print("Installing tftpy...")
    install_package("tftpy")

# Now that packages are ensured to be installed, import them
from easysnmp import Session
from tftpy import TftpServer

def print_usage():
    print("\n######################################################")
    print("# Copy Cisco Router config - Using SNMP")
    print("# Redesigned by Keith Pachulski - keith@redcellsecurity.org")
    print("# Modernized with migration to Python 3, dependency checking, and integrated TFTP server on start")
    print("#######################################################")
    print("\nUsage : python cisco_copy_config.py <router-ip> <tftp-server-ip> <community>")
    print("\nMake sure a TFTP server is set up, preferably running from /tmp!\n")

def start_tftp_server():
    # Set up TFTP server to run in the /tmp directory on port 69
    server = TftpServer('/tmp')
    print("Starting TFTP server on port 69, serving from /tmp directory...")
    server.listen('0.0.0.0', 69)

# Check arguments
if len(sys.argv) != 4:
    print_usage()
    sys.exit(1)

# Assign variables
host = sys.argv[1]
tftp = sys.argv[2]
community = sys.argv[3]
copy_file = 'pwnd-router.config'
path = f"/tmp/{copy_file}"

# Start the TFTP server in a separate thread
tftp_thread = Thread(target=start_tftp_server, daemon=True)
tftp_thread.start()

# Setup SNMP session
try:
    session = Session(hostname=host, community=community, version=2)
except Exception as e:
    print(f"Failed to create SNMP session: {e}")
    sys.exit(1)

# Create the file with write permission
try:
    with open(path, 'w') as copy_fh:
        os.chmod(path, 0o666)
except IOError as e:
    print(f"Failed to create file {path}: {e}")
    sys.exit(1)

print(f"{host}:running-config -> {tftp}:{copy_file}... ")

# Copy running-config to TFTP server (SNMP command depends on the device)
# OID for copy command and syntax may vary depending on device specifics.
try:
    # Replace with appropriate SNMP set commands for copying config to TFTP server
    # Example: session.set('OID_for_copy_command', 'value_to_initiate_copy')
    
    # This part requires device-specific SNMP OID setup.
    # For instance, replace 'OID_for_copy_command' and 'value_to_initiate_copy' with the correct values.
    # session.set('OID_for_copy_command', 'value_to_initiate_copy')

    print("OK")
except Exception as e:
    print(f"Error copying config: {e}")
    sys.exit(1)
