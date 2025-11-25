#!/usr/bin/env python3
# =============================================================================
# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This script provides an automated installation and management system
#          for a vulnerability assessment and penetration testing
#          toolkit. It installs and configures security tools across multiple
#          categories including exploitation, web testing, network scanning,
#          mobile security, cloud security, and Active Directory testing.
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

import jaydebeapi
import shutil
from pathlib import Path
from datetime import datetime

SCRIPT_DIR = Path(__file__).parent.absolute()
HSQLDB_JAR = SCRIPT_DIR / "hsqldb.jar"

def check_and_download_hsqldb():
    """Check for HSQLDB JAR, download if missing"""
    if HSQLDB_JAR.exists():
        return True

    print(f"[!] hsqldb.jar not found in {SCRIPT_DIR}")
    response = input("Download hsqldb.jar automatically? (yes/no): ").strip().lower()

    if response != 'yes':
        print("[!] Cannot proceed without hsqldb.jar")
        return False

    try:
        import urllib.request
        url = "https://hsqldb.org/download/hsqldb_274/hsqldb.jar"
        print(f"[*] Downloading from {url}...")
        urllib.request.urlretrieve(url, HSQLDB_JAR)
        print(f"[+] Downloaded to {HSQLDB_JAR}")
        return True
    except Exception as e:
        print(f"[!] Download failed: {e}")
        print(f"[!] Manually download from: https://hsqldb.org/download/hsqldb_274/hsqldb.jar")
        return False

def get_session_file():
    """Find or prompt for session file"""
    # Check current directory first
    sessions = [f.name for f in SCRIPT_DIR.iterdir()
                if f.is_file() and (SCRIPT_DIR / f"{f.name}.properties").exists()]

    if sessions:
        print("[*] Available sessions in current directory:")
        for i, s in enumerate(sessions, 1):
            print(f"  {i}. {s}")

        choice = input(f"\nSelect (1-{len(sessions)}) or enter path to different session file: ").strip()

        try:
            session_idx = int(choice) - 1
            if 0 <= session_idx < len(sessions):
                return sessions[session_idx]
        except ValueError:
            pass

        # User entered a path
        session_path = Path(choice)
    else:
        print("[!] No ZAP session files found in current directory")
        session_path = Path(input("Enter full path to ZAP session file: ").strip())

    # Validate the provided path
    if not session_path.exists():
        print(f"[!] Session file not found: {session_path}")
        return None

    if not (session_path.parent / f"{session_path.name}.properties").exists():
        print(f"[!] Not a valid ZAP session (missing .properties file)")
        return None

    # Copy to working directory
    print(f"[*] Copying session files to working directory...")
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
        dst = SCRIPT_DIR / fname
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)

    return session_path.name

def backup_session(session_name):
    """Create timestamped backup if user confirms"""
    response = input("\nCreate backup before making changes? (yes/no): ").strip().lower()

    if response != 'yes':
        print("[!] Proceeding without backup")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = SCRIPT_DIR / f"{session_name}_backup_{timestamp}"
    backup_dir.mkdir(exist_ok=True)

    session_files = [
        session_name,
        f"{session_name}.properties",
        f"{session_name}.script",
        f"{session_name}.data",
        f"{session_name}.backup",
        f"{session_name}.log"
    ]

    for fname in session_files:
        src = SCRIPT_DIR / fname
        if src.exists():
            shutil.copy2(src, backup_dir / fname)

    print(f"[+] Backup: {backup_dir}")
    return backup_dir

def connect_db(session_name):
    """Connect to HSQLDB"""
    session_path = SCRIPT_DIR / session_name
    jdbc_url = f"jdbc:hsqldb:file:{session_path};shutdown=true"

    conn = jaydebeapi.connect(
        "org.hsqldb.jdbc.JDBCDriver",
        jdbc_url,
        ["SA", ""],
        str(HSQLDB_JAR)
    )
    print(f"[+] Connected to database: {session_name}")
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
    return columns

def get_all_alerts(conn, columns):
    """Fetch unique alerts with count"""
    cursor = conn.cursor()

    # Build query with only available columns, group by plugin and alert name
    base_cols = ['PLUGINID', 'ALERT', 'RISK']
    available = [col for col in base_cols if col in columns]

    query = f"""
        SELECT {', '.join(available)}, COUNT(*) as COUNT, MIN(ALERTID) as FIRST_ID
        FROM ALERT
        GROUP BY {', '.join(available)}
        ORDER BY RISK DESC, PLUGINID
    """

    cursor.execute(query)
    results = cursor.fetchall()

    # Add COUNT to column names for display
    return results, available + ['COUNT', 'FIRST_ID']

def get_risk_summary(conn):
    """Get count of alerts by risk level"""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT RISK, COUNT(*)
        FROM ALERT
        GROUP BY RISK
        ORDER BY RISK DESC
    """)
    return cursor.fetchall()

def delete_by_risk(conn, risk_level):
    """Delete all alerts of a specific risk level"""
    risk_map = {'info': 0, 'informational': 0, 'low': 1, 'medium': 2, 'med': 2, 'high': 3}
    risk_value = risk_map.get(risk_level.lower(), None)

    if risk_value is None:
        print("[!] Invalid risk level")
        return

    cursor = conn.cursor()

    # Count first
    cursor.execute("SELECT COUNT(*) FROM ALERT WHERE RISK = ?", [risk_value])
    count = cursor.fetchone()[0]

    if count == 0:
        print(f"[*] No alerts with risk level {risk_level}")
        return

    print(f"[*] Found {count} alerts with risk level {risk_level}")
    confirm = input(f"Delete ALL {count} alerts? (yes/no): ").strip().lower()

    if confirm == 'yes':
        cursor.execute("DELETE FROM ALERT WHERE RISK = ?", [risk_value])
        conn.commit()
        print(f"[+] Deleted {count} alerts")
    else:
        print("[*] Cancelled")

def display_alerts(alerts, column_names):
    """Display alerts with selection numbers"""
    risk_names = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High'}

    # Find column indices
    plugin_idx = column_names.index('PLUGINID') if 'PLUGINID' in column_names else None
    alert_idx = column_names.index('ALERT') if 'ALERT' in column_names else None
    risk_idx = column_names.index('RISK') if 'RISK' in column_names else None
    count_idx = column_names.index('COUNT') if 'COUNT' in column_names else None

    print(f"\n{'='*100}")
    header = f"{'#':<5}"
    if plugin_idx is not None:
        header += f" {'Plugin':<7}"
    if risk_idx is not None:
        header += f" {'Risk':<7}"
    if count_idx is not None:
        header += f" {'Count':<6}"
    if alert_idx is not None:
        header += f" {'Alert':<60}"
    print(header)
    print(f"{'='*100}")

    for idx, alert in enumerate(alerts, 1):
        line = f"{idx:<5}"

        if plugin_idx is not None:
            line += f" {alert[plugin_idx]:<7}"

        if risk_idx is not None:
            risk_str = risk_names.get(alert[risk_idx], str(alert[risk_idx]))
            line += f" {risk_str:<7}"

        if count_idx is not None:
            line += f" {alert[count_idx]:<6}"

        if alert_idx is not None:
            alert_name = alert[alert_idx] if alert[alert_idx] else ''
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
        if '-' in part:
            try:
                start, end = part.split('-')
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

def delete_by_plugin(conn, plugin_id):
    """Delete all alerts from a specific plugin"""
    try:
        plugin_id = int(plugin_id)
    except ValueError:
        print("[!] Plugin ID must be a number")
        return

    cursor = conn.cursor()

    # Count first
    cursor.execute("SELECT COUNT(*) FROM ALERT WHERE PLUGINID = ?", [plugin_id])
    count = cursor.fetchone()[0]

    if count == 0:
        print(f"[*] No alerts with plugin ID {plugin_id}")
        return

    # Show what plugin this is
    cursor.execute("SELECT ALERT FROM ALERT WHERE PLUGINID = ? LIMIT 1", [plugin_id])
    plugin_name = cursor.fetchone()[0]

    print(f"[*] Found {count} alerts from plugin {plugin_id}: {plugin_name}")
    confirm = input(f"Delete ALL {count} alerts? (yes/no): ").strip().lower()

    if confirm == 'yes':
        cursor.execute("DELETE FROM ALERT WHERE PLUGINID = ?", [plugin_id])
        conn.commit()
        print(f"[+] Deleted {count} alerts")
    else:
        print("[*] Cancelled")

def delete_selected_alerts(conn, alert_ids):
    """Delete alerts by ID"""
    cursor = conn.cursor()
    placeholders = ','.join(['?' for _ in alert_ids])
    cursor.execute(f"DELETE FROM ALERT WHERE ALERTID IN ({placeholders})", alert_ids)
    conn.commit()
    print(f"[+] Deleted {len(alert_ids)} alerts")

def check_and_download_hsqldb():
    """Check for HSQLDB JAR, download if missing"""
    if HSQLDB_JAR.exists():
        return True

    print(f"[!] hsqldb.jar not found in {SCRIPT_DIR}")
    response = input("Download hsqldb.jar automatically? (yes/no): ").strip().lower()

    if response != 'yes':
        print("[!] Cannot proceed without hsqldb.jar")
        print("[!] Download manually from: https://hsqldb.org/download/hsqldb_274/hsqldb.jar")
        return False

    try:
        import urllib.request
        url = "https://hsqldb.org/download/hsqldb_274/hsqldb.jar"
        print(f"[*] Downloading from {url}...")
        urllib.request.urlretrieve(url, HSQLDB_JAR)
        print(f"[+] Downloaded to {HSQLDB_JAR}")
        return True
    except Exception as e:
        print(f"[!] Download failed: {e}")
        print(f"[!] Manually download from: https://hsqldb.org/download/hsqldb_274/hsqldb.jar")
        return False

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        ZAP Alert Selective Deletion                          ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # Check for HSQLDB JAR
    if not check_and_download_hsqldb():
        return

    # Get session file
    session_name = get_session_file()
    if not session_name:
        return

    # Backup and connect
    backup_session(session_name)
    conn = connect_db(session_name)

    # Check table structure
    columns = get_table_columns(conn)
    print(f"[*] Available columns: {', '.join(columns)}")

    while True:
        # Show risk summary
        risk_summary = get_risk_summary(conn)
        risk_names = {0: 'Informational', 1: 'Low', 2: 'Medium', 3: 'High'}

        print(f"\n[*] Alerts by Risk Level:")
        for risk, count in risk_summary:
            print(f"    {risk_names.get(risk, f'Unknown({risk})')}: {count}")

        # Get and display alerts
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
            risk_level = selection.split(' ', 1)[1]
            delete_by_risk(conn, risk_level)
            continue
        elif selection.startswith('plugin '):
            plugin_id = selection.split(' ', 1)[1]
            delete_by_plugin(conn, plugin_id)
            continue

        # Parse selection
        indices = parse_selection(selection, len(alerts))

        if not indices:
            print("[!] No valid selections")
            continue

        # Show what will be deleted
        id_idx = column_names.index('ALERTID')
        alert_idx = column_names.index('ALERT') if 'ALERT' in column_names else None
        url_idx = column_names.index('URL') if 'URL' in column_names else None
        plugin_idx = column_names.index('PLUGINID') if 'PLUGINID' in column_names else None

        print(f"\n[*] Selected {len(indices)} alerts for deletion:")
        for idx in indices[:10]:
            alert = alerts[idx - 1]
            info = f"  #{idx}: ID={alert[id_idx]}"
            if plugin_idx is not None:
                info += f" Plugin={alert[plugin_idx]}"
            if alert_idx is not None:
                info += f" {alert[alert_idx]}"
            if url_idx is not None:
                info += f" - {alert[url_idx][:60]}"
            print(info)

        if len(indices) > 10:
            print(f"  ... and {len(indices) - 10} more")

        confirm = input("\nDelete these? (yes/no): ").strip().lower()
        if confirm == 'yes':
            alert_ids = [alerts[idx - 1][id_idx] for idx in indices]
            delete_selected_alerts(conn, alert_ids)
        else:
            print("[*] Cancelled")

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
