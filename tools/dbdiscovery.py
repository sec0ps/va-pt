#!/usr/bin/env python3
# =============================================================================
# DBDiscovery Tool - Database Discovery and Enumeration Tool
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
# Purpose: This script is part of the DBDiscovery Tool, which provides enterprise-grade
#          database discovery and classification capabilities with automated security
#          assessment. It discovers database services, tests authentication mechanisms,
#          enumerates databases, and integrates with DarkShield for data classification
#          and PII detection across enterprise networks.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================

import nmap
import requests
import json
import socket
import logging
import argparse
import sys
import time
import ipaddress
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import subprocess
import shutil
import os
from pathlib import Path
warnings.filterwarnings("ignore")

# Configure logging for DBDiscovery Tool
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dbdiscovery_security_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class DatabaseTarget:
    """Data class for discovered database targets"""
    host: str
    port: int
    service: str
    version: str = ""
    database_type: str = ""
    credentials: Optional[Dict[str, str]] = None
    databases: List[str] = None
    schema_info: Optional[Dict] = None

class DatabaseSecurityScanner:

    def __init__(self):
        self.discovered_databases = []
        self.use_darkshield = False
        self.darkshield_url = ""
        self.msfconsole_path = ""
        self.target_db_type = "all"  # ADD THIS LINE

        # Metasploit module mappings
        self.msf_login_modules = {
            'mysql': 'auxiliary/scanner/mysql/mysql_login',
            'postgresql': 'auxiliary/scanner/postgres/postgres_login',
            'mssql': 'auxiliary/scanner/mssql/mssql_login',
            'mongodb': 'auxiliary/scanner/mongodb/mongodb_login',
            'oracle': 'auxiliary/scanner/oracle/oracle_login',
            'redis': 'auxiliary/scanner/redis/redis_login'
        }

        self.msf_schema_modules = {
            'mysql': 'auxiliary/scanner/mysql/mysql_schemadump',
            'mssql': 'auxiliary/scanner/mssql/mssql_schemadump',
            'postgresql': 'auxiliary/scanner/postgres/postgres_schemadump',
            'oracle': 'auxiliary/scanner/oracle/oracle_schemadump'
        }

        # Default credentials for Metasploit
        self.default_credentials = {
            'mysql': [
                ('root', ''), ('root', 'root'), ('root', 'password'), ('root', 'admin'),
                ('root', 'mysql'), ('root', 'toor'), ('admin', 'admin'), ('admin', 'password'),
                ('mysql', 'mysql'), ('user', 'user'), ('test', 'test'), ('guest', 'guest')
            ],
            'postgresql': [
                ('postgres', ''), ('postgres', 'postgres'), ('postgres', 'password'),
                ('postgres', 'admin'), ('admin', 'admin'), ('user', 'user'),
                ('root', 'root'), ('test', 'test')
            ],
            'mssql': [
                ('sa', ''), ('sa', 'sa'), ('sa', 'password'), ('sa', 'admin'),
                ('admin', 'admin'), ('administrator', 'administrator'),
                ('root', 'root'), ('test', 'test'), ('user', 'user')
            ],
            'mongodb': [
                ('admin', ''), ('admin', 'admin'), ('admin', 'password'),
                ('root', 'root'), ('user', 'user'), ('test', 'test'),
                ('mongodb', 'mongodb')
            ],
            'oracle': [
                ('system', 'oracle'), ('sys', 'sys'), ('scott', 'tiger'),
                ('admin', 'admin'), ('oracle', 'oracle'), ('test', 'test'),
                ('hr', 'hr'), ('scott', 'scott')
            ],
            'redis': [
                ('', ''), ('admin', ''), ('root', ''), ('redis', 'redis')
            ]
        }

    def banner(self):
        """Display tool banner"""
        print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          DBDiscovery Security Tool                           ║
║                     Database Discovery & Enumeration                         ║
║                                                                              ║
║                        Author: Keith Pachulski                               ║
║                      Company: Red Cell Security, LLC                         ║
║                      Email: keith@redcellsecurity.org                        ║
║                      Website: www.redcellsecurity.org                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """)

    def get_user_input(self) -> Tuple[str, bool, str, str, str]:
        """Get target IP/CIDR, scan preferences, and DarkShield settings from user"""
        print("\n[*] Database Security Assessment Configuration")
        print("=" * 50)

        # Get target network
        while True:
            target = input("\n[?] Enter target IP address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24): ").strip()
            if self.validate_target(target):
                break
            print("[!] Invalid IP address or CIDR range. Please try again.")

        # Database type selection
        print("\n[*] Database Type Filter:")
        print("    1. All databases")
        print("    2. MySQL/MariaDB only")
        print("    3. PostgreSQL only")
        print("    4. Microsoft SQL Server only")
        print("    5. MongoDB only")
        print("    6. Oracle only")
        print("    7. Redis only")

        while True:
            db_choice = input("[?] Select database type to target (1-7): ").strip()
            if db_choice in ['1', '2', '3', '4', '5', '6', '7']:
                break
            print("[!] Please enter a number between 1-7")

        db_type_map = {
            '1': 'all',
            '2': 'mysql',
            '3': 'postgresql',
            '4': 'mssql',
            '5': 'mongodb',
            '6': 'oracle',
            '7': 'redis'
        }
        target_db_type = db_type_map[db_choice]

        # Get scan intensity preference
        print("\n[*] Scan Options:")
        print("    1. Fast scan (common database ports)")
        print("    2. Comprehensive scan (all 65535 ports)")

        while True:
            scan_choice = input("[?] Select scan type (1-2): ").strip()
            if scan_choice in ['1', '2']:
                break
            print("[!] Please enter 1 or 2")

        scan_intensity = {'1': 'fast', '2': 'comprehensive'}[scan_choice]

        # Get DarkShield preference
        while True:
            darkshield_choice = input("\n[?] Use DarkShield API for data classification if databases are discovered? (y/n): ").strip().lower()
            if darkshield_choice in ['y', 'yes', 'n', 'no']:
                use_darkshield = darkshield_choice in ['y', 'yes']
                break
            print("[!] Please enter 'y' or 'n'")

        darkshield_url = ""
        if use_darkshield:
            darkshield_url = input("[?] Enter DarkShield server URL (e.g., http://localhost:8080): ").strip()
            if not darkshield_url.startswith(('http://', 'https://')):
                darkshield_url = 'http://' + darkshield_url

        return target, use_darkshield, darkshield_url, scan_intensity, target_db_type

    def validate_target(self, target: str) -> bool:
        """Validate IP address or CIDR range"""
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            try:
                ipaddress.ip_address(target)
                return True
            except ValueError:
                return False

    def find_msfconsole(self) -> bool:
        """Locate msfconsole binary using locate as primary method"""
        # Try using 'which' command first (fastest)
        try:
            result = subprocess.run(['which', 'msfconsole'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                self.msfconsole_path = result.stdout.strip()
                logger.info(f"[+] Found msfconsole via 'which': {self.msfconsole_path}")
                return True
        except:
            pass

        # Try shutil.which
        msfconsole_path = shutil.which('msfconsole')
        if msfconsole_path:
            self.msfconsole_path = msfconsole_path
            logger.info(f"[+] Found msfconsole via shutil.which: {self.msfconsole_path}")
            return True

        # Primary method: locate command
        try:
            logger.info("[*] Searching for msfconsole using locate...")
            result = subprocess.run(['locate', '-i', 'msfconsole'], capture_output=True, text=True, timeout=30)

            if result.returncode == 0 and result.stdout.strip():
                locate_results = result.stdout.strip().split('\n')

                valid_paths = []
                for path in locate_results:
                    path = path.strip()
                    if (path.endswith('msfconsole') or path.endswith('msfconsole.rb')) and os.path.exists(path) and os.access(path, os.X_OK):
                        valid_paths.append(path)

                if valid_paths:
                    preferred_paths = [p for p in valid_paths if any(kw in p.lower() for kw in ['metasploit', '/usr/bin', '/usr/local/bin', '/opt'])]
                    chosen_path = preferred_paths[0] if preferred_paths else valid_paths[0]
                    self.msfconsole_path = chosen_path
                    logger.info(f"[+] Found msfconsole via locate: {self.msfconsole_path}")
                    return True
                else:
                    logger.info("[*] locate found references but no executable files")

        except FileNotFoundError:
            logger.info("[*] locate command not available on this system")
        except subprocess.TimeoutExpired:
            logger.warning("[*] locate command timeout - database may be updating")
        except Exception as e:
            logger.warning(f"[*] locate command failed: {str(e)}")

        # Manual input fallback
        print("[!] Could not locate msfconsole automatically.")
        print("[*] Tried: which, shutil.which, locate")

        while True:
            user_path = input("[?] Enter full path to msfconsole (or 'exit' to quit): ").strip()

            if user_path.lower() == 'exit':
                return False

            expanded_path = os.path.expanduser(user_path)

            if os.path.exists(expanded_path) and os.access(expanded_path, os.X_OK):
                self.msfconsole_path = expanded_path
                logger.info(f"[+] Using user-provided msfconsole path: {self.msfconsole_path}")
                return True
            else:
                print(f"[!] Path not found or not executable: {expanded_path}")
                print("[*] Please verify the path and try again.")

    def test_metasploit_login(self, target: DatabaseTarget) -> bool:
        """Use Metasploit to test database authentication"""
        if target.database_type not in self.msf_login_modules:
            logger.warning(f"[!] No Metasploit login module for {target.database_type}")
            return False

        module = self.msf_login_modules[target.database_type]
        credentials = self.default_credentials.get(target.database_type, [])

        print(f"[*] Testing authentication on {target.host}:{target.port} using Metasploit...")

        for username, password in credentials:
            try:
                # Create Metasploit command
                msf_commands = [
                    f"use {module}",
                    f"set RHOSTS {target.host}",
                    f"set RPORT {target.port}",
                    f"set USERNAME {username}",
                    f"set PASSWORD {password}",
                    "set VERBOSE false",
                    "run",
                    "exit"
                ]

                command_string = "; ".join(msf_commands)

                # Execute Metasploit
                result = subprocess.run(
                    [self.msfconsole_path, '-q', '-x', command_string],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                # Check for successful login indicators
                output = result.stdout.lower()
                if any(indicator in output for indicator in ['success', 'login successful', 'authenticated', 'valid credentials']):
                    logger.info(f"[+] Successful login: {username}:{password}")
                    print(f"[+] ✓ Authentication successful: {username}:{'*' * len(password) if password else '(blank)'}")
                    target.credentials = {'username': username, 'password': password}
                    return True

            except subprocess.TimeoutExpired:
                logger.warning(f"[!] Metasploit timeout for {username}:{password}")
            except Exception as e:
                logger.error(f"[!] Metasploit error: {str(e)}")

        print(f"[!] ✗ All authentication attempts failed")
        return False

    def dump_schema(self, target: DatabaseTarget) -> bool:
        """Use Metasploit to dump database schema with fallback methods"""
        if target.database_type not in self.msf_schema_modules:
            logger.info(f"[*] No schema dump module available for {target.database_type}")
            return False

        if not target.credentials:
            logger.warning(f"[!] No credentials available for schema dump")
            return False

        module = self.msf_schema_modules[target.database_type]

        print(f"[*] Dumping schema from {target.host}:{target.port}...")

        try:
            username = target.credentials['username']
            password = target.credentials['password']

            # Try the standard schema dump module first
            msf_commands = [
                f"use {module}",
                f"set RHOSTS {target.host}",
                f"set RPORT {target.port}",
                f"set USERNAME {username}",
                f"set PASSWORD '{password}'",
                "run",
                "exit"
            ]

            command_string = "; ".join(msf_commands)

            result = subprocess.run(
                [self.msfconsole_path, '-q', '-x', command_string],
                capture_output=True,
                text=True,
                timeout=120
            )

            # Check if the module executed successfully
            output_lower = result.stdout.lower()

            # If we get the NoMethodError or similar issues, try alternative approach
            if any(error in output_lower for error in ['nomethoderror', 'undefined method', 'auxiliary failed']):
                logger.warning(f"[!] Standard schema dump failed due to module bug, trying alternative approach")
                print(f"[!] Schema dump module failed (likely honeypot/compatibility issue), trying SQL queries...")

                # Fallback: Use mysql_sql module to run manual schema queries
                return self._manual_schema_dump(target)

            elif any(error in output_lower for error in ['password must be specified', 'failed to validate', 'authentication failed', 'connection failed']):
                logger.warning(f"[!] Schema dump failed due to authentication")
                print(f"[!] Schema dump failed - authentication error")
                return False

            elif result.returncode == 0 and result.stdout and len(result.stdout.strip()) > 100:
                # Save schema output if it looks substantial
                schema_filename = f'schema_dump_{target.host}_{target.port}_{target.database_type}.txt'
                with open(schema_filename, 'w') as f:
                    f.write(result.stdout)

                target.schema_info = {'schema_file': schema_filename}
                print(f"[+] Schema dump saved to: {schema_filename}")
                return True
            else:
                logger.warning(f"[!] Schema dump produced minimal output")
                print(f"[!] Schema dump completed but produced minimal results")
                return False

        except subprocess.TimeoutExpired:
            logger.warning(f"[!] Schema dump timeout for {target.host}:{target.port}")
        except Exception as e:
            logger.error(f"[!] Schema dump error: {str(e)}")

        return False

    def _manual_schema_dump(self, target: DatabaseTarget) -> bool:
        """Fallback method to manually dump schema using SQL queries"""
        if target.database_type != 'mysql':
            logger.info(f"[*] Manual schema dump only supports MySQL currently")
            return False

        try:
            username = target.credentials['username']
            password = target.credentials['password']

            print(f"[*] Attempting manual schema enumeration...")

            # List of SQL queries to gather schema information
            schema_queries = [
                "SHOW DATABASES;",
                "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema','performance_schema','mysql','sys');",
                "SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys');",
                "SELECT table_schema, table_name, column_name, data_type FROM information_schema.columns WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys');"
            ]

            schema_output = []
            schema_output.append("=== MANUAL SCHEMA DUMP ===\n")
            schema_output.append(f"Target: {target.host}:{target.port}\n")
            schema_output.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            for query in schema_queries:
                try:
                    # Use auxiliary/admin/mysql/mysql_sql to run queries
                    msf_commands = [
                        "use auxiliary/admin/mysql/mysql_sql",
                        f"set RHOSTS {target.host}",
                        f"set RPORT {target.port}",
                        f"set USERNAME {username}",
                        f"set PASSWORD '{password}'",
                        f"set SQL '{query}'",
                        "run",
                        "exit"
                    ]

                    command_string = "; ".join(msf_commands)

                    result = subprocess.run(
                        [self.msfconsole_path, '-q', '-x', command_string],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )

                    if result.returncode == 0 and result.stdout:
                        schema_output.append(f"Query: {query}\n")
                        schema_output.append(result.stdout)
                        schema_output.append("\n" + "="*50 + "\n")

                except Exception as e:
                    schema_output.append(f"Query failed: {query} - Error: {str(e)}\n")

            # Save manual schema output
            schema_filename = f'manual_schema_dump_{target.host}_{target.port}_{target.database_type}.txt'
            with open(schema_filename, 'w') as f:
                f.writelines(schema_output)

            target.schema_info = {'schema_file': schema_filename}
            print(f"[+] Manual schema dump saved to: {schema_filename}")
            return True

        except Exception as e:
            logger.error(f"[!] Manual schema dump error: {str(e)}")
            return False

    def discover_databases(self, target: str, scan_intensity: str) -> List[DatabaseTarget]:
        """Use Nmap to discover database services"""
        logger.info(f"[*] Starting database discovery scan on {target} (intensity: {scan_intensity})")

        nm = nmap.PortScanner()
        discovered = []

        # Common database ports
        common_db_ports = "3306,5432,1433,1521,27017,6379,5984,9042,7000,8086,3050,50000,5000"

        try:
            if scan_intensity == 'fast':
                print(f"[*] Fast scan - checking common database ports...")
                nm.scan(target, common_db_ports, arguments='-sV')
            else:  # comprehensive
                print(f"[*] Comprehensive scan - checking all 65535 ports...")
                nm.scan(target, arguments='-sV -p-')

            for host in nm.all_hosts():
                print(f"[*] Analyzing {host}...")

                if 'tcp' in nm[host]:
                    for port in nm[host]['tcp']:
                        port_info = nm[host]['tcp'][port]

                        if port_info['state'] == 'open':
                            db_target = self._identify_database(host, port, port_info)
                            if db_target:
                                discovered.append(db_target)
                                print(f"[+] Database found: {host}:{port} ({db_target.database_type})")

            logger.info(f"[+] Discovery complete. Found {len(discovered)} databases")
            return discovered

        except Exception as e:
            logger.error(f"[!] Nmap scan failed: {str(e)}")
            return []

    def _identify_database(self, host: str, port: int, port_info: dict) -> Optional[DatabaseTarget]:
        """Simple database identification based on port and service info"""
        service = port_info.get('name', '').lower()
        product = port_info.get('product', '').lower()
        version = port_info.get('version', '')

        db_type = None

        # Port-based identification with service confirmation
        if port == 3306 or 'mysql' in service or 'mysql' in product or 'mariadb' in product:
            db_type = 'mysql'
        elif port == 5432 or 'postgresql' in service or 'postgres' in product:
            db_type = 'postgresql'
        elif port == 1433 or 'ms-sql' in service or 'microsoft' in product or 'mssql' in service:
            db_type = 'mssql'
        elif port == 1521 or 'oracle' in service or 'oracle' in product or 'tns' in service:
            db_type = 'oracle'
        elif port == 27017 or 'mongodb' in service or 'mongo' in product:
            db_type = 'mongodb'
        elif port == 6379 or 'redis' in service or 'redis' in product:
            db_type = 'redis'

        if db_type:
            # Filter based on target database type
            if self.target_db_type != "all" and db_type != self.target_db_type:
                return None  # Skip this database type

            return DatabaseTarget(
                host=host,
                port=port,
                service=service,
                version=f"{product} {version}".strip(),
                database_type=db_type
            )

        return None

    def create_darkshield_payload(self, target: DatabaseTarget, database_name: str) -> Dict:
        """Create DarkShield API payload for database scanning"""

        # Determine JDBC URL and driver based on database type
        if target.database_type == 'mysql':
            jdbc_url = f"jdbc:mysql://{target.host}:{target.port}/{database_name}"
            driver_class = "com.mysql.cj.jdbc.Driver"
        elif target.database_type == 'postgresql':
            jdbc_url = f"jdbc:postgresql://{target.host}:{target.port}/{database_name}"
            driver_class = "org.postgresql.Driver"
        elif target.database_type == 'mssql':
            jdbc_url = f"jdbc:sqlserver://{target.host}:{target.port};databaseName={database_name};encrypt=false;"
            driver_class = "com.microsoft.sqlserver.jdbc.SQLServerDriver"
        elif target.database_type == 'oracle':
            jdbc_url = f"jdbc:oracle:thin:@{target.host}:{target.port}:{database_name}"
            driver_class = "oracle.jdbc.driver.OracleDriver"
        else:
            logger.warning(f"[!] Unsupported database type for DarkShield: {target.database_type}")
            return None

        payload = {
            "searchContext": {
                "name": "SearchContext",
                "matchers": []
            },
            "maskContext": {
                "name": "MaskContext",
                "rules": [
                    {
                        "name": "SSNMaskRule",
                        "type": "cosort",
                        "expression": "deterministic_pseudo_replace(\"SSN\", ${PersonID}, \"pswd\")"
                    },
                    {
                        "name": "EmailMaskRule",
                        "type": "cosort",
                        "expression": "deterministic_pseudo_replace(\"EMAIL\", ${PersonID}, \"pswd\")"
                    }
                ],
                "ruleMatchers": [
                    {
                        "name": "SSNMatcher",
                        "type": "name",
                        "rule": "SSNMaskRule",
                        "pattern": "SSN_Pattern"
                    },
                    {
                        "name": "EmailMatcher",
                        "type": "name",
                        "rule": "EmailMaskRule",
                        "pattern": "Email_Pattern"
                    }
                ]
            },
            "fileSearchContext": {
                "name": "FileSearchContext",
                "matchers": [
                    {
                        "name": "SearchContext",
                        "type": "searchContext"
                    },
                    {
                        "name": "SSN_Pattern",
                        "dataClass": "SSN",
                        "searchMatcherPriority": 1,
                        "type": "column",
                        "pattern": "(?i)\\b.*(SSN|SOCIAL|SECURITY).*\\b"
                    },
                    {
                        "name": "Email_Pattern",
                        "dataClass": "Email",
                        "searchMatcherPriority": 2,
                        "type": "column",
                        "pattern": "(?i)\\b.*EMAIL.*\\b"
                    },
                    {
                        "name": "CreditCard_Pattern",
                        "dataClass": "CreditCard",
                        "searchMatcherPriority": 3,
                        "type": "column",
                        "pattern": "(?i)\\b.*(CARD|CC|CREDIT).*\\b"
                    }
                ],
                "configs": {}
            },
            "fileMaskContext": {
                "name": "FileMaskContext",
                "rules": [
                    {
                        "name": "MaskContext",
                        "type": "maskContext"
                    }
                ],
                "configs": {}
            },
            "rdbSearchContext": {
                "name": "RdbSearchContext",
                "fileSearchContextName": "FileSearchContext",
                "configs": {
                    "url": jdbc_url,
                    "username": target.credentials['username'],
                    "password": target.credentials['password'],
                    "driverClassName": driver_class,
                    "includePattern": ".*",
                    "driverConfigs": {
                        "encrypt": "false" if target.database_type == 'mssql' else None
                    }
                }
            },
            "rdbMaskContext": {
                "name": "RdbMaskContext",
                "fileMaskContextName": "FileMaskContext",
                "configs": {
                    "url": jdbc_url,
                    "username": target.credentials['username'],
                    "password": target.credentials['password'],
                    "driverClassName": driver_class,
                    "disableForeignKeys": True,
                    "disableTriggers": False,
                    "driverConfigs": {
                        "encrypt": "false" if target.database_type == 'mssql' else None
                    }
                }
            },
            "sourceType": "rdb"
        }

        # Clean up None values
        def clean_dict(d):
            if isinstance(d, dict):
                return {k: clean_dict(v) for k, v in d.items() if v is not None}
            return d

        return clean_dict(payload)

    def call_darkshield_api(self, target: DatabaseTarget, database_name: str) -> Dict:
        """Call DarkShield API for data classification"""
        logger.info(f"[*] Calling DarkShield API for {target.host}:{database_name}")

        payload = self.create_darkshield_payload(target, database_name)
        if not payload:
            return {"error": "Could not create payload for database type"}

        try:
            endpoint = f"{self.darkshield_url.rstrip('/')}/api/darkshield/all/allContext.searchAndMask"

            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            logger.info(f"[*] Sending request to: {endpoint}")
            response = requests.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=300  # 5 minute timeout for large databases
            )

            if response.status_code == 200:
                logger.info(f"[+] DarkShield API call successful for {database_name}")
                return response.json()
            else:
                logger.error(f"[!] DarkShield API error: {response.status_code} - {response.text}")
                return {"error": f"API call failed: {response.status_code}", "details": response.text}

        except requests.exceptions.RequestException as e:
            logger.error(f"[!] DarkShield API request failed: {str(e)}")
            return {"error": "API request failed", "details": str(e)}

    def generate_report(self):
        """Generate security assessment report"""
        print("\n" + "="*80)
        print("DBDISCOVERY SECURITY ASSESSMENT REPORT")
        print("Generated by: DBDiscovery Tool v1.0")
        print("Author: Keith Pachulski - Red Cell Security, LLC")
        print("="*80)

        if not self.discovered_databases:
            print("[!] No databases discovered in target network")
            return

        for idx, db in enumerate(self.discovered_databases, 1):
            print(f"\n[{idx}] Database Target: {db.host}:{db.port}")
            print(f"    Service: {db.service}")
            print(f"    Type: {db.database_type}")
            print(f"    Version: {db.version}")

            if db.credentials:
                print(f"    ✓ Authentication: SUCCESSFUL (Metasploit)")
                print(f"      Username: {db.credentials['username']}")
                print(f"      Password: {'*' * len(db.credentials['password']) if db.credentials['password'] else '(blank)'}")

                if db.schema_info:
                    print(f"    ✓ Schema Dump: {db.schema_info['schema_file']}")
            else:
                print(f"    ✗ Authentication: FAILED")

        # Save detailed report
        report_data = {
            'tool_info': {
                'name': 'DBDiscovery Security Tool',
                'version': '1.0',
                'author': 'Keith Pachulski',
                'company': 'Red Cell Security, LLC',
                'website': 'www.redcellsecurity.org',
                'scan_method': 'Nmap + Metasploit integration'
            },
            'scan_metadata': {
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'targets_discovered': len(self.discovered_databases),
                'successful_auths': len([db for db in self.discovered_databases if db.credentials]),
                'schema_dumps': len([db for db in self.discovered_databases if db.schema_info]),
                'darkshield_enabled': self.use_darkshield
            },
            'databases': []
        }

        for db in self.discovered_databases:
            db_info = {
                'host': db.host,
                'port': db.port,
                'service': db.service,
                'type': db.database_type,
                'version': db.version,
                'authentication_successful': bool(db.credentials),
                'schema_dumped': bool(db.schema_info)
            }

            if db.credentials:
                db_info['credentials'] = {
                    'username': db.credentials['username'],
                    'password_length': len(db.credentials['password'])
                }

            if db.schema_info:
                db_info['schema_info'] = db.schema_info

            report_data['databases'].append(db_info)

        with open('dbdiscovery_security_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"\n[+] Detailed report saved to: dbdiscovery_security_report.json")
        print(f"[+] Scan logs saved to: dbdiscovery_security_scan.log")

    def run(self):
        """Main execution flow"""
        self.banner()

        # Check for Metasploit
        print("[*] Checking for Metasploit Framework...")
        if not self.find_msfconsole():
            print("[!] Metasploit Framework not found!")
            print("")

            # Ask user if they want to install Metasploit
            while True:
                install_choice = input("[?] Would you like to install Metasploit Framework now? [Y/n]: ").strip().lower()

                # Default to 'yes' if user just presses enter
                if install_choice == '' or install_choice in ['y', 'yes']:
                    print("\n[*] Installing Metasploit Framework...")
                    print("[*] This may take several minutes depending on your system and internet connection.")

                    try:
                        # Check if git is available
                        subprocess.run(['git', '--version'], capture_output=True, check=True)

                        # Clone Metasploit repository
                        print("[*] Cloning Metasploit Framework repository...")
                        clone_result = subprocess.run(
                            ['git', 'clone', 'https://github.com/rapid7/metasploit-framework.git'],
                            capture_output=True,
                            text=True,
                            timeout=300  # 5 minute timeout for cloning
                        )

                        if clone_result.returncode != 0:
                            print(f"[!] Git clone failed: {clone_result.stderr}")
                            print("[!] Installation aborted. Please install Metasploit manually.")
                            return

                        print("[*] Repository cloned successfully.")

                        # Change to metasploit directory and run bundle install
                        print("[*] Installing dependencies with bundle install...")
                        print("[*] This step may take 10-20 minutes...")

                        bundle_result = subprocess.run(
                            ['bundle', 'install'],
                            cwd='metasploit-framework',
                            capture_output=True,
                            text=True,
                            timeout=1200  # 20 minute timeout for bundle install
                        )

                        if bundle_result.returncode != 0:
                            print(f"[!] Bundle install failed: {bundle_result.stderr}")
                            print("[!] You may need to install Ruby and Bundler first.")
                            print("[!] Please check Metasploit installation requirements.")
                            return

                        print("[+] Metasploit Framework installation completed!")

                        # Update msfconsole path to local installation
                        local_msfconsole = os.path.join(os.getcwd(), 'metasploit-framework', 'msfconsole')
                        if os.path.exists(local_msfconsole):
                            self.msfconsole_path = local_msfconsole
                            print(f"[+] Using local Metasploit installation: {self.msfconsole_path}")
                            break
                        else:
                            print("[!] Installation completed but msfconsole not found.")
                            print("[!] Please check the installation and try again.")
                            return

                    except subprocess.TimeoutExpired:
                        print("[!] Installation timeout. The process is taking too long.")
                        print("[!] Please install Metasploit manually or try again with a better internet connection.")
                        return

                    except FileNotFoundError:
                        print("[!] Git not found. Please install git first:")
                        print("    Ubuntu/Debian: sudo apt-get install git")
                        print("    CentOS/RHEL: sudo yum install git")
                        print("    macOS: brew install git")
                        return

                    except Exception as e:
                        print(f"[!] Installation error: {str(e)}")
                        print("[!] Please install Metasploit manually.")
                        print("[!] Manual installation: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html")
                        return

                elif install_choice in ['n', 'no']:
                    print("[!] Metasploit Framework is required for database authentication testing.")
                    print("[!] Exiting program.")
                    return
                else:
                    print("[!] Please enter 'y' for yes or 'n' for no (default is yes)")

        else:
            print(f"[+] Metasploit found at: {self.msfconsole_path}")

        # Get user input
        target, self.use_darkshield, self.darkshield_url, scan_intensity, self.target_db_type = self.get_user_input()

        # Configuration display with database filter
        db_type_display = {
            'all': 'All database types',
            'mysql': 'MySQL/MariaDB only',
            'postgresql': 'PostgreSQL only',
            'mssql': 'Microsoft SQL Server only',
            'mongodb': 'MongoDB only',
            'oracle': 'Oracle only',
            'redis': 'Redis only'
        }

        print(f"\n[*] Configuration:")
        print(f"    Target: {target}")
        print(f"    Database Filter: {db_type_display[self.target_db_type]}")
        print(f"    Scan Type: {'Fast (common ports)' if scan_intensity == 'fast' else 'Comprehensive (all ports)'}")
        print(f"    DarkShield Integration: {'Enabled' if self.use_darkshield else 'Disabled'}")
        if self.use_darkshield:
            print(f"    DarkShield URL: {self.darkshield_url}")

        # Phase 1: Database Discovery
        print(f"\n[*] Phase 1: Database Discovery")
        print("-" * 40)
        self.discovered_databases = self.discover_databases(target, scan_intensity)

        if not self.discovered_databases:
            print(f"[!] No database services discovered")
            return

        print(f"\n[+] Found {len(self.discovered_databases)} database services")

        # Phase 2: Authentication Testing with Metasploit
        print(f"\n[*] Phase 2: Database Authentication (Metasploit)")
        print("-" * 40)

        authenticated_databases = []
        for db in self.discovered_databases:
            print(f"\n[*] Testing: {db.host}:{db.port} ({db.database_type})")
            if self.test_metasploit_login(db):
                authenticated_databases.append(db)

        # Phase 3: Schema Enumeration
        if authenticated_databases:
            print(f"\n[*] Phase 3: Schema Enumeration")
            print("-" * 40)

            for db in authenticated_databases:
                self.dump_schema(db)

        # Phase 4: DarkShield Integration (if enabled)
        if self.use_darkshield and authenticated_databases:
            print(f"\n[*] Phase 4: Data Classification with DarkShield")
            print("-" * 40)

            for db in authenticated_databases:
                if db.databases:
                    for database in db.databases:
                        print(f"[*] Analyzing database: {database}")
                        result = self.call_darkshield_api(db, database)

                        if 'error' not in result:
                            result_filename = f'dbdiscovery_darkshield_{db.host}_{db.port}_{database}.json'
                            with open(result_filename, 'w') as f:
                                json.dump(result, f, indent=2)
                            print(f"[+] Results saved to: {result_filename}")

        # Final Report
        print(f"\n[*] Final Phase: Report Generation")
        print("-" * 40)
        self.generate_report()

        print(f"\n[+] DBDiscovery assessment completed!")

def main():
    """
    Main entry point for DBDiscovery Tool

    Initializes the database security scanner and handles command-line arguments.
    Provides comprehensive error handling and user feedback.
    """
    parser = argparse.ArgumentParser(
        description='DBDiscovery Tool - Dynamic Database Discovery and Security Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python dbdiscovery.py                   # Interactive mode with scan options
        """
    )

    args = parser.parse_args()

    try:
        scanner = DatabaseSecurityScanner()
        scanner.run()

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
