#!/usr/bin/env python3
# =============================================================================
# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit
# =============================================================================
#
# Location: reporting/zap_cleanup.py
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: Selective deletion of alerts from an OWASP ZAP HSQLDB session
#          database. Connects to a ZAP session via the HSQLDB JDBC driver,
#          lists unique alerts grouped by plugin/risk, and allows removal by
#          index range, risk level, or plugin ID. Self-bootstraps a local
#          virtual environment and installs its Python dependencies on first
#          run, then re-executes inside that environment.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# NOTICE: This toolkit is intended for authorized security testing only.
#         Users are responsible for ensuring compliance with all applicable laws
#         and regulations. Unauthorized use of these tools may violate local,
#         state, federal, and international laws.
#
# =============================================================================

import os
import sys
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.absolute()
VENV_DIR = SCRIPT_DIR / ".venv"
HSQLDB_JAR = SCRIPT_DIR / "hsqldb.jar"
REQUIRED_PACKAGES = ["jaydebeapi"]

# HSQLDB is pulled from Maven Central (hsqldb.org's TLS cert is unreliable).
# The 2.7.x main jar targets Java 11+.
HSQLDB_VERSION = "2.7.4"
HSQLDB_URL = (f"https://repo1.maven.org/maven2/org/hsqldb/hsqldb/"
              f"{HSQLDB_VERSION}/hsqldb-{HSQLDB_VERSION}.jar")

# =============================================================================
# Virtual environment bootstrap
# Creates a local venv, installs missing dependencies, then re-execs this
# script using the venv interpreter. Runs before any third-party imports.
# =============================================================================

def _venv_python():
    """Return the path to the venv Python interpreter for the current OS"""
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"

def _ensure_venv():
    """Ensure a venv exists with required deps, then re-exec inside it"""
    # Already running inside our venv, nothing to do
    if Path(sys.prefix).resolve() == VENV_DIR.resolve():
        return

    venv_python = _venv_python()

    # Create the venv if it does not exist yet
    if not venv_python.exists():
        print(f"[*] Creating virtual environment: {VENV_DIR}")
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])

    # Verify dependencies inside the venv, install if any are missing
    check = subprocess.run(
        [str(venv_python), "-c", "import jaydebeapi"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if check.returncode != 0:
        print(f"[*] Installing dependencies: {', '.join(REQUIRED_PACKAGES)}")
        subprocess.check_call([str(venv_python), "-m", "pip", "install", *REQUIRED_PACKAGES])

    # Re-exec this script using the venv interpreter, passing through args
    print("[*] Relaunching inside virtual environment")
    result = subprocess.run([str(venv_python), str(Path(__file__).absolute()), *sys.argv[1:]])
    sys.exit(result.returncode)

_ensure_venv()

# Third-party and venv-dependent imports live below the bootstrap
import shutil
import hashlib
import urllib.request
import jaydebeapi
from datetime import datetime

RISK_NAMES_SHORT = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High'}
RISK_NAMES_LONG = {0: 'Informational', 1: 'Low', 2: 'Medium', 3: 'High'}
GROUP_KEY_COLS = ('PLUGINID', 'ALERT', 'RISK')

def check_and_download_hsqldb():
    """Check for HSQLDB JAR, download from Maven Central with SHA-1 verification if missing"""
    if HSQLDB_JAR.exists():
        return True

    print(f"[!] hsqldb.jar not found in {SCRIPT_DIR}")
    response = input("Download hsqldb.jar automatically? (yes/no): ").strip().lower()
    if response != 'yes':
        print(f"[!] Cannot proceed without hsqldb.jar - download manually from: {HSQLDB_URL}")
        return False

    tmp_path = HSQLDB_JAR.with_suffix(".jar.part")
    try:
        print(f"[*] Downloading {HSQLDB_URL}")
        with urllib.request.urlopen(HSQLDB_URL, timeout=60) as r:
            data = r.read()
        with urllib.request.urlopen(HSQLDB_URL + ".sha1", timeout=30) as r:
            expected = r.read().decode().split()[0].strip().lower()

        actual = hashlib.sha1(data).hexdigest()
        if actual != expected:
            print(f"[!] SHA-1 mismatch: expected {expected}, got {actual} - discarding")
            return False

        # Write to a temp file then rename, so a failed run never leaves a half-written jar
        tmp_path.write_bytes(data)
        tmp_path.replace(HSQLDB_JAR)
        print(f"[+] Downloaded and verified (SHA-1 {actual}): {HSQLDB_JAR}")
        return True
    except Exception as e:
        tmp_path.unlink(missing_ok=True)
        print(f"[!] Download failed: {e}")
        print(f"[!] Manually download from: {HSQLDB_URL}")
        return False

def check_java():
    """Warn if no JVM is on PATH, jaydebeapi needs one to connect"""
    if shutil.which("java") is None:
        print("[!] Warning: 'java' not found on PATH")
        print("[!] jaydebeapi requires a JRE/JDK (11+) to connect to HSQLDB")
        response = input("Continue anyway? (yes/no): ").strip().lower()
        return response == 'yes'
    return True

def _find_sessions(directory):
    """Return ZAP session files in a directory (files with a sibling .properties file)"""
    return sorted(f for f in directory.iterdir()
                  if f.is_file() and (directory / f"{f.name}.properties").exists())

def get_session_file():
    """Find or prompt for session file - returns full path"""
    # Check current directory first
    sessions = _find_sessions(Path.cwd())

    if sessions:
        print("[*] Available sessions in current directory:")
        for i, s in enumerate(sessions, 1):
            print(f"  {i}. {s.name}")

        choice = input(f"\nSelect (1-{len(sessions)}) or enter path to session file/directory: ").strip()

        try:
            session_idx = int(choice) - 1
            if 0 <= session_idx < len(sessions):
                return sessions[session_idx]
        except ValueError:
            pass

        # User entered a path
        session_path = Path(choice).expanduser()
    else:
        print("[!] No ZAP session files found in current directory")
        session_path = Path(input("Enter full path to ZAP session file or directory: ").strip()).expanduser()

    # Check if it's a directory
    if session_path.is_dir():
        dir_sessions = _find_sessions(session_path)

        if not dir_sessions:
            print(f"[!] No ZAP session files found in {session_path}")
            return None

        print(f"[*] Found {len(dir_sessions)} session(s) in directory:")
        for i, s in enumerate(dir_sessions, 1):
            print(f"  {i}. {s.name}")

        choice = input(f"\nSelect (1-{len(dir_sessions)}): ").strip()
        try:
            session_idx = int(choice) - 1
            if 0 <= session_idx < len(dir_sessions):
                session_path = dir_sessions[session_idx]
            else:
                print("[!] Invalid selection")
                return None
        except ValueError:
            print("[!] Invalid selection")
            return None

    if not session_path.exists():
        print(f"[!] Session file not found: {session_path}")
        return None

    if not (session_path.parent / f"{session_path.name}.properties").exists():
        print("[!] Not a valid ZAP session (missing .properties file)")
        return None

    return session_path.resolve()

def check_session_lock(session_path):
    """Warn if the HSQLDB lock file exists - usually means ZAP still has the session open"""
    lck = session_path.parent / f"{session_path.name}.lck"
    if lck.exists():
        print(f"[!] Lock file present: {lck.name}")
        print("[!] ZAP may still have this session open - close ZAP first or changes may be lost")
        response = input("Continue anyway? (yes/no): ").strip().lower()
        return response == 'yes'
    return True

def backup_session(session_path):
    """Create timestamped backup if user confirms - takes full Path object"""
    response = input("\nCreate backup before making changes? (yes/no): ").strip().lower()

    if response != 'yes':
        print("[!] Proceeding without backup")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = session_path.parent / f"{session_path.name}_backup_{timestamp}"
    backup_dir.mkdir(exist_ok=True)

    session_files = [
        session_path.name,
        f"{session_path.name}.properties",
        f"{session_path.name}.script",
        f"{session_path.name}.data",
        f"{session_path.name}.backup",
        f"{session_path.name}.log"
    ]

    for fname in session_files:
        src = session_path.parent / fname
        if src.exists():
            shutil.copy2(src, backup_dir / fname)

    # HSQLDB keeps LOB data in a separate directory
    lobs = session_path.parent / f"{session_path.name}.lobs"
    if lobs.exists():
        shutil.copy2(lobs, backup_dir / lobs.name)

    print(f"[+] Backup: {backup_dir}")
    return backup_dir

def connect_db(session_path):
    """Connect to HSQLDB - takes full Path object"""
    jdbc_url = f"jdbc:hsqldb:file:{session_path};shutdown=true"

    conn = jaydebeapi.connect(
        "org.hsqldb.jdbc.JDBCDriver",
        jdbc_url,
        ["SA", ""],
        str(HSQLDB_JAR)
    )
    print(f"[+] Connected to database: {session_path.name}")
    return conn

def get_table_columns(conn):
    """Find out what columns exist in ALERT table"""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = 'ALERT'
    """)
    columns = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return columns

def get_all_alerts(conn, columns):
    """Fetch unique alert groups (PLUGINID, ALERT, RISK) with instance count"""
    cursor = conn.cursor()

    available = [col for col in GROUP_KEY_COLS if col in columns]
    if not available:
        raise RuntimeError("ALERT table has none of the expected columns (PLUGINID, ALERT, RISK)")

    order = []
    if 'RISK' in available:
        order.append('RISK DESC')
    if 'PLUGINID' in available:
        order.append('PLUGINID')
    order_clause = f"ORDER BY {', '.join(order)}" if order else ""

    query = f"""
        SELECT {', '.join(available)}, COUNT(*) AS CNT
        FROM ALERT
        GROUP BY {', '.join(available)}
        {order_clause}
    """

    cursor.execute(query)
    results = cursor.fetchall()
    cursor.close()

    return results, available + ['COUNT']

def get_risk_summary(conn):
    """Get count of alerts by risk level"""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT RISK, COUNT(*)
        FROM ALERT
        GROUP BY RISK
        ORDER BY RISK DESC
    """)
    results = cursor.fetchall()
    cursor.close()
    return results

def delete_by_risk(conn, risk_level):
    """Delete all alerts of a specific risk level"""
    risk_map = {'info': 0, 'informational': 0, 'low': 1, 'medium': 2, 'med': 2, 'high': 3}
    risk_value = risk_map.get(risk_level.strip().lower())

    if risk_value is None:
        print("[!] Invalid risk level (use info, low, medium, high)")
        return

    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM ALERT WHERE RISK = ?", [risk_value])
    count = cursor.fetchone()[0]

    if count == 0:
        print(f"[*] No alerts with risk level {risk_level}")
        cursor.close()
        return

    print(f"[*] Found {count} alerts with risk level {risk_level}")
    confirm = input(f"Delete ALL {count} alerts? (Y/n): ").strip().lower()

    if confirm in ('', 'y', 'yes'):
        cursor.execute("DELETE FROM ALERT WHERE RISK = ?", [risk_value])
        conn.commit()
        print(f"[+] Deleted {count} alerts")
    else:
        print("[*] Cancelled")
    cursor.close()

def delete_by_plugin(conn, plugin_id):
    """Delete all alerts from a specific plugin"""
    try:
        plugin_id = int(plugin_id)
    except ValueError:
        print("[!] Plugin ID must be a number")
        return

    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM ALERT WHERE PLUGINID = ?", [plugin_id])
    count = cursor.fetchone()[0]

    if count == 0:
        print(f"[*] No alerts with plugin ID {plugin_id}")
        cursor.close()
        return

    # Show what plugin this is
    cursor.execute("SELECT ALERT FROM ALERT WHERE PLUGINID = ? LIMIT 1", [plugin_id])
    plugin_name = cursor.fetchone()[0]

    print(f"[*] Found {count} alerts from plugin {plugin_id}: {plugin_name}")
    confirm = input(f"Delete ALL {count} alerts? (Y/n): ").strip().lower()

    if confirm in ('', 'y', 'yes'):
        cursor.execute("DELETE FROM ALERT WHERE PLUGINID = ?", [plugin_id])
        conn.commit()
        print(f"[+] Deleted {count} alerts")
    else:
        print("[*] Cancelled")
    cursor.close()

def delete_selected_groups(conn, groups, column_names):
    """Delete every alert instance matching each selected (PLUGINID, ALERT, RISK) group"""
    key_cols = [c for c in GROUP_KEY_COLS if c in column_names]
    cursor = conn.cursor()
    total = 0

    for g in groups:
        values = [g[column_names.index(c)] for c in key_cols]
        # NULL-safe match: '=' never matches NULL, so handle it explicitly
        clauses, params = [], []
        for col, val in zip(key_cols, values):
            if val is None:
                clauses.append(f"{col} IS NULL")
            else:
                clauses.append(f"{col} = ?")
                params.append(val)
        where = ' AND '.join(clauses)

        cursor.execute(f"SELECT COUNT(*) FROM ALERT WHERE {where}", params)
        total += cursor.fetchone()[0]
        cursor.execute(f"DELETE FROM ALERT WHERE {where}", params)

    conn.commit()
    cursor.close()
    print(f"[+] Deleted {total} alert instances across {len(groups)} group(s)")

def display_alerts(alerts, column_names):
    """Display alert groups with selection numbers"""
    plugin_idx = column_names.index('PLUGINID') if 'PLUGINID' in column_names else None
    alert_idx = column_names.index('ALERT') if 'ALERT' in column_names else None
    risk_idx = column_names.index('RISK') if 'RISK' in column_names else None
    count_idx = column_names.index('COUNT')

    print(f"\n{'='*100}")
    header = f"{'#':<5}"
    if plugin_idx is not None:
        header += f" {'Plugin':<7}"
    if risk_idx is not None:
        header += f" {'Risk':<7}"
    header += f" {'Count':<6}"
    if alert_idx is not None:
        header += f" {'Alert':<60}"
    print(header)
    print(f"{'='*100}")

    for idx, alert in enumerate(alerts, 1):
        line = f"{idx:<5}"

        if plugin_idx is not None:
            line += f" {str(alert[plugin_idx]):<7}"

        if risk_idx is not None:
            risk_str = RISK_NAMES_SHORT.get(alert[risk_idx], str(alert[risk_idx]))
            line += f" {risk_str:<7}"

        line += f" {str(alert[count_idx]):<6}"

        if alert_idx is not None:
            alert_name = alert[alert_idx] or ''
            alert_display = alert_name[:58] + '..' if len(alert_name) > 60 else alert_name
            line += f" {alert_display:<60}"

        print(line)

    print(f"{'='*100}")
    print(f"Total unique alerts: {len(alerts)}\n")

def parse_selection(selection_str, max_num):
    """
    Parse selection string into list of indices
    Examples: '1,2,3' or '1-5' or '1-5,10,15-20'
    """
    selected = set()

    for part in selection_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start, end = int(start), int(end)
                if 1 <= start <= max_num and 1 <= end <= max_num and start <= end:
                    selected.update(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                num = int(part)
                if 1 <= num <= max_num:
                    selected.add(num)
            except ValueError:
                pass

    return sorted(selected)

def checkpoint_database(conn):
    """Checkpoint database to ensure changes are written to disk"""
    try:
        cursor = conn.cursor()
        cursor.execute("CHECKPOINT")
        cursor.close()
        print("[*] Database checkpointed - changes saved to disk")
    except Exception as e:
        print(f"[!] Warning: Could not checkpoint database: {e}")

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        ZAP Alert Selective Deletion                          ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # Check for HSQLDB JAR
    if not check_and_download_hsqldb():
        return

    # Check for a JVM, jaydebeapi cannot connect without one
    if not check_java():
        return

    # Get session file (returns full Path object)
    session_path = get_session_file()
    if not session_path:
        return

    # Refuse to silently fight ZAP for the session
    if not check_session_lock(session_path):
        return

    # Backup and connect
    backup_session(session_path)
    conn = connect_db(session_path)

    try:
        columns = get_table_columns(conn)
        print(f"[*] Available columns: {', '.join(columns)}")

        while True:
            # Show risk summary
            risk_summary = get_risk_summary(conn)
            print("\n[*] Alerts by Risk Level:")
            for risk, count in risk_summary:
                print(f"    {RISK_NAMES_LONG.get(risk, f'Unknown({risk})')}: {count}")

            # Get and display alert groups
            alerts, column_names = get_all_alerts(conn, columns)

            if not alerts:
                print("[*] No alerts in database")
                break

            display_alerts(alerts, column_names)

            print("Commands:")
            print("  - Enter numbers to delete (e.g., '1,2,3' or '1-10' or '1-5,8,10-15')")
            print("  - 'risk <level>' to delete all of a risk level (e.g., 'risk info' or 'risk low')")
            print("  - 'plugin <id>' to delete all from a plugin (e.g., 'plugin 10054')")
            print("  - 'r' to refresh list")
            print("  - 'q' to quit")

            selection = input("\nYour selection: ").strip().lower()

            if selection == 'q':
                break
            elif selection == 'r':
                continue
            elif selection.startswith('risk '):
                delete_by_risk(conn, selection.split(' ', 1)[1])
                continue
            elif selection.startswith('plugin '):
                delete_by_plugin(conn, selection.split(' ', 1)[1].strip())
                continue

            indices = parse_selection(selection, len(alerts))
            if not indices:
                print("[!] No valid selections")
                continue

            # Show what will be deleted
            alert_idx = column_names.index('ALERT') if 'ALERT' in column_names else None
            plugin_idx = column_names.index('PLUGINID') if 'PLUGINID' in column_names else None
            count_idx = column_names.index('COUNT')
            groups = [alerts[i - 1] for i in indices]
            instance_total = sum(g[count_idx] for g in groups)

            print(f"\n[*] Selected {len(groups)} alert group(s) ({instance_total} instances) for deletion:")
            for i, g in zip(indices[:10], groups[:10]):
                info = f"  #{i}:"
                if plugin_idx is not None:
                    info += f" Plugin={g[plugin_idx]}"
                info += f" Count={g[count_idx]}"
                if alert_idx is not None:
                    info += f" {g[alert_idx]}"
                print(info)
            if len(groups) > 10:
                print(f"  ... and {len(groups) - 10} more")

            confirm = input("\nDelete these? (Y/n): ").strip().lower()
            if confirm in ('', 'y', 'yes'):
                delete_selected_groups(conn, groups, column_names)
            else:
                print("[*] Cancelled")
    finally:
        # Always flush and release the session, even on error or Ctrl+C
        checkpoint_database(conn)
        conn.close()

    print("\n[+] Done")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
