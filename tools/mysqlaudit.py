#!/usr/bin/env python3
# =========================================================================
#
# NAME: mysqlaudit.py
# VERSION: 1
# AUTHOR: Keith Pachulski - based on the mysqlaudit.py originally written by Carlos Perez.
# DATE  : 10/10/2024  - Updated for modernization and feature addition
# EMAIL: keith@redcellsecurity.org
#
# Will be adding in more checks to this script over the next few weeks
#
# Modern Library: Switched to mysql.connector, which is better maintained.
# Error Handling: Used try-except to handle potential connection errors.
# Command-Line Arguments: Used argparse for improved argument handling.
# Formatted Strings: Made the output more readable and concise.
# Functions for Reusability: Created a security_check function to streamline the process of running and reporting each security check.
# File Handling: Used with open(...) as file syntax for better resource management.
#
# =========================================================================

import subprocess
import sys
import argparse
from datetime import datetime

# Check if mysql-connector-python is installed, if not, install it
try:
    import mysql.connector
    from mysql.connector import Error
except ImportError:
    print("mysql-connector-python not found. Attempting to install it...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "mysql-connector-python"])
    import mysql.connector
    from mysql.connector import Error

# Initialize risk counters
high, medium, low = 0, 0, 0

# Setup command-line argument parsing
parser = argparse.ArgumentParser(description="MySQL Security Assessment Script")
parser.add_argument("target_ip", help="Target IP for the MySQL database")
parser.add_argument("user", help="User account with DBA privileges for assessment")
parser.add_argument("password", help="Password for the user account")
parser.add_argument("report", help="Filename to save the assessment report")
args = parser.parse_args()

# Connect to the MySQL database
try:
    conn = mysql.connector.connect(
        host=args.target_ip,
        user=args.user,
        password=args.password,
        database="mysql"
    )
    cursor = conn.cursor()
except Error as e:
    print(f"Error connecting to MySQL: {e}")
    sys.exit(1)

# Start report
date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
report_content = [
    f"MySQL Security Assessment Report - {date}\n",
    "========================================\n\n"
]

# Define security checks
def security_check(query, severity, description, solution, detail):
    global high, medium, low
    cursor.execute(query)
    result = cursor.fetchall()
    if result:
        report_content.append(f"Severity: {severity}\n")
        report_content.append(f"Description:\n{description}\n")
        report_content.append(f"Solution:\n{solution}\n")
        report_content.append(f"{detail}\n")
        if severity == "High":
            high += 1
        elif severity == "Medium":
            medium += 1
        elif severity == "Low":
            low += 1
    return result

# Security assessment checks
security_check(
    "SELECT User, Host FROM user WHERE User = ''",
    "High",
    "MySQL allows anonymous user access.",
    "DELETE FROM mysql.user WHERE User = '';",
    "Anonymous users found:\n" + "\n".join([f"User: anonymous, Host: {row[1]}" for row in cursor.fetchall()])
)

security_check(
    "SELECT User, Host FROM user WHERE Password = ''",
    "High",
    "MySQL user accounts have empty passwords.",
    "Use 'ALTER USER' to set strong passwords.",
    "Users with empty passwords:\n" + "\n".join([f"User: {row[0]}, Host: {row[1]}" for row in cursor.fetchall()])
)

# Example of Medium severity check
security_check(
    "SELECT User, Host FROM user WHERE FILE_priv = 'Y' AND User != 'root'",
    "Medium",
    "Users have FILE privileges that allow file manipulation.",
    "REVOKE FILE ON *.* FROM '[username]';",
    "Users with FILE privilege:\n" + "\n".join([f"User: {row[0]}, Host: {row[1]}" for row in cursor.fetchall()])
)

# Additional security checks can be added here in a similar manner

# Footer summary
report_content.append("\n========================================\n")
report_content.append(f"High Risk Issues: {high}\n")
report_content.append(f"Medium Risk Issues: {medium}\n")
report_content.append(f"Low Risk Issues: {low}\n")
report_content.append("========================================\n")

# Write report
with open(args.report, "w") as report_file:
    report_file.writelines(report_content)

# Cleanup
cursor.close()
conn.close()

print(f"Report written to {args.report}")
