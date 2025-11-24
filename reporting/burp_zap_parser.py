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

import xml.etree.ElementTree as ET
import argparse
import sys
from pathlib import Path
from datetime import datetime
from html.parser import HTMLParser
from collections import defaultdict
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH

class ZAPHTMLParser(HTMLParser):
    """Parse ZAP HTML report format"""

    def __init__(self):
        super().__init__()
        self.alerts = []
        self.current_alert = {}
        self.current_tag = None
        self.current_data = []
        self.in_alert = False
        self.in_instance = False
        self.current_instances = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == 'div' and attrs_dict.get('class') in ['alert-item', 'site']:
            self.in_alert = True
            self.current_alert = {'instances': []}
        elif tag == 'span' and 'risk-' in attrs_dict.get('class', ''):
            self.current_tag = 'risk'
        elif tag == 'h3' and self.in_alert:
            self.current_tag = 'name'
        elif tag == 'h4' and self.in_alert:
            self.current_tag = 'section'
        elif tag == 'p' and self.in_alert:
            self.current_tag = 'content'
        elif tag == 'li' and self.in_alert:
            if self.current_tag == 'urls':
                self.in_instance = True
            self.current_tag = 'list_item'
        elif tag == 'td' and self.in_alert:
            self.current_tag = 'table_cell'

    def handle_data(self, data):
        data = data.strip()
        if not data or not self.in_alert:
            return

        if self.current_tag == 'risk':
            self.current_alert['risk'] = data
        elif self.current_tag == 'name' and 'name' not in self.current_alert:
            self.current_alert['name'] = data
        elif self.current_tag == 'content':
            self.current_data.append(data)
        elif self.current_tag == 'list_item' and self.in_instance:
            self.current_instances.append(data)
        elif self.current_tag == 'table_cell':
            self.current_data.append(data)

    def handle_endtag(self, tag):
        if tag == 'div' and self.in_alert:
            if 'name' in self.current_alert and 'risk' in self.current_alert:
                content = ' '.join(self.current_data)

                if 'Description' in content:
                    parts = content.split('Description', 1)
                    if len(parts) > 1:
                        desc_part = parts[1].split('Solution', 1)[0] if 'Solution' in parts[1] else parts[1]
                        self.current_alert['description'] = desc_part.strip()

                if 'Solution' in content:
                    parts = content.split('Solution', 1)
                    if len(parts) > 1:
                        sol_part = parts[1].split('Reference', 1)[0] if 'Reference' in parts[1] else parts[1]
                        self.current_alert['solution'] = sol_part.strip()

                if 'Reference' in content:
                    parts = content.split('Reference', 1)
                    if len(parts) > 1:
                        self.current_alert['reference'] = parts[1].strip()

                if self.current_instances:
                    self.current_alert['instances'] = self.current_instances.copy()

                self.alerts.append(self.current_alert)

            self.in_alert = False
            self.current_alert = {}
            self.current_data = []
            self.current_instances = []
        elif tag in ['p', 'h3', 'h4', 'span', 'li', 'td']:
            self.current_tag = None

        if tag == 'ul':
            self.in_instance = False

def detect_format(file_path):
    """Auto-detect report type: zap_xml, zap_html, burp_xml"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read(2000)

        if '<?xml' in content:
            if '<OWASPZAPReport' in content or 'programName="ZAP"' in content:
                return 'zap_xml'
            elif '<issues' in content and 'burpVersion' in content:
                return 'burp_xml'
            else:
                return 'unknown'
        elif '<html' in content.lower() or '<!doctype' in content.lower():
            return 'zap_html'

    return 'unknown'

def find_reports_in_directory():
    """Find all supported report files in current directory"""
    current_dir = Path('.')
    supported_files = []

    for file in current_dir.iterdir():
        if file.is_file() and file.suffix.lower() in ['.xml', '.html', '.htm']:
            try:
                report_type = detect_format(file)
                if report_type in ['zap_xml', 'zap_html', 'burp_xml']:
                    supported_files.append((file, report_type))
            except:
                continue

    return supported_files

def parse_xml_report(file_path):
    """Parse ZAP XML report"""
    tree = ET.parse(file_path)
    root = tree.getroot()

    metadata = {
        'program': root.get('programName', 'OWASP ZAP'),
        'version': root.get('version', 'Unknown'),
        'generated': root.get('generated', 'Unknown')
    }

    alerts_by_severity = defaultdict(list)
    all_alerts = []

    for site in root.findall('.//site'):
        site_name = site.get('name', 'Unknown')
        site_host = site.get('host', '')
        site_port = site.get('port', '')

        for alert in site.findall('.//alertitem'):
            alert_data = {
                'name': alert.findtext('name', 'Unknown'),
                'risk': alert.findtext('riskdesc', 'Unknown'),
                'confidence': alert.findtext('confidence', 'Unknown'),
                'description': alert.findtext('desc', ''),
                'solution': alert.findtext('solution', ''),
                'reference': alert.findtext('reference', ''),
                'cweid': alert.findtext('cweid', ''),
                'wascid': alert.findtext('wascid', ''),
                'site': site_name,
                'host': site_host,
                'port': site_port,
                'instances': []
            }

            for instance in alert.findall('.//instance'):
                instance_data = {
                    'uri': instance.findtext('uri', ''),
                    'method': instance.findtext('method', ''),
                    'param': instance.findtext('param', ''),
                    'attack': instance.findtext('attack', ''),
                    'evidence': instance.findtext('evidence', ''),
                    'request_header': instance.findtext('requestheader', ''),
                    'request_body': instance.findtext('requestbody', ''),
                    'response_header': instance.findtext('responseheader', ''),
                    'response_body': instance.findtext('responsebody', '')
                }
                alert_data['instances'].append(instance_data)

            risk_level = alert_data['risk'].split()[0] if alert_data['risk'] else 'Informational'
            alerts_by_severity[risk_level].append(alert_data)
            all_alerts.append(alert_data)

    return metadata, alerts_by_severity, all_alerts

def parse_html_report(file_path):
    """Parse ZAP HTML report"""
    with open(file_path, 'r', encoding='utf-8') as f:
        html_content = f.read()

    parser = ZAPHTMLParser()
    parser.feed(html_content)

    metadata = {
        'program': 'OWASP ZAP',
        'version': 'Unknown',
        'generated': 'Unknown'
    }

    if 'ZAP Version' in html_content:
        import re
        version_match = re.search(r'ZAP Version[:\s]+([0-9.]+)', html_content)
        if version_match:
            metadata['version'] = version_match.group(1)

    if 'Report Generated' in html_content:
        import re
        date_match = re.search(r'Report Generated[:\s]+([^<]+)', html_content)
        if date_match:
            metadata['generated'] = date_match.group(1).strip()

    alerts_by_severity = defaultdict(list)
    all_alerts = []

    for alert in parser.alerts:
        risk = alert.get('risk', 'Informational')
        if 'High' in risk:
            risk_level = 'High'
        elif 'Medium' in risk:
            risk_level = 'Medium'
        elif 'Low' in risk:
            risk_level = 'Low'
        else:
            risk_level = 'Informational'

        alert['risk'] = risk_level
        alerts_by_severity[risk_level].append(alert)
        all_alerts.append(alert)

    return metadata, alerts_by_severity, all_alerts

def parse_burp_report(file_path):
    """Parse Burp Suite XML report"""
    tree = ET.parse(file_path)
    root = tree.getroot()

    metadata = {
        'program': 'Burp Suite',
        'version': root.get('burpVersion', 'Unknown'),
        'generated': root.get('exportTime', 'Unknown')
    }

    alerts_by_severity = defaultdict(list)
    all_alerts = []

    severity_map = {
        'High': 'High',
        'Medium': 'Medium',
        'Low': 'Low',
        'Information': 'Informational',
        'Informational': 'Informational'
    }

    for issue in root.findall('.//issue'):
        alert_data = {
            'name': issue.findtext('name', 'Unknown'),
            'risk': severity_map.get(issue.findtext('severity', 'Informational'), 'Informational'),
            'confidence': issue.findtext('confidence', 'Certain'),
            'description': issue.findtext('issueBackground', '') or issue.findtext('issueDetail', ''),
            'solution': issue.findtext('remediationBackground', '') or issue.findtext('remediationDetail', ''),
            'reference': '\n'.join([ref.text for ref in issue.findall('.//reference') if ref.text]),
            'cweid': '',
            'wascid': '',
            'instances': []
        }

        host = issue.findtext('host', '')
        path = issue.findtext('path', '')

        # Extract request/response data
        request_data = issue.find('.//requestresponse/request')
        response_data = issue.find('.//requestresponse/response')

        if host and path:
            instance = {
                'uri': f"{host}{path}",
                'method': issue.findtext('method', ''),
                'param': '',
                'request_header': request_data.text if request_data is not None else '',
                'request_body': '',
                'response_header': response_data.text if response_data is not None else '',
                'response_body': '',
                'evidence': ''
            }
            alert_data['instances'].append(instance)

        risk_level = alert_data['risk']
        alerts_by_severity[risk_level].append(alert_data)
        all_alerts.append(alert_data)

    return metadata, alerts_by_severity, all_alerts

def extract_base_url(uri):
    """Extract base URL with non-standard ports"""
    from urllib.parse import urlparse

    parsed = urlparse(uri)

    # Build base URL
    base = f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else uri

    # Add port if non-standard
    if parsed.port:
        if (parsed.scheme == 'https' and parsed.port != 443) or \
           (parsed.scheme == 'http' and parsed.port != 80):
            base += f":{parsed.port}"

    return base

def add_heading(doc, text, level=1):
    """Add a heading with consistent formatting"""
    heading = doc.add_heading(text, level=level)
    return heading

def add_paragraph(doc, text, bold=False, italic=False):
    """Add a paragraph with optional formatting"""
    para = doc.add_paragraph()
    run = para.add_run(text)
    if bold:
        run.bold = True
    if italic:
        run.italic = True
    return para

def add_bullet(doc, text, level=0):
    """Add a bulleted item"""
    para = doc.add_paragraph(text, style='List Bullet')
    if level > 0:
        para.paragraph_format.left_indent = Inches(0.5 * level)
    return para

def generate_docx_report(metadata, alerts_by_severity, all_alerts, target_name="Target"):
    """Generate DOCX report matching nessus_parser style"""

    doc = Document()

    # Detailed Findings by Severity (no top-level headers)
    severity_order = ['High', 'Medium', 'Low', 'Informational']

    for severity in severity_order:
        alerts = alerts_by_severity.get(severity, [])
        if not alerts:
            continue

        # Level 2: Severity heading
        add_heading(doc, f'{severity} Severity Findings', level=2)

        # Group by alert name to avoid duplicates
        alerts_by_name = defaultdict(list)
        for alert in alerts:
            alerts_by_name[alert['name']].append(alert)

        for alert_name, alert_group in alerts_by_name.items():
            # Level 3: Finding name
            add_heading(doc, alert_name, level=3)

            alert = alert_group[0]

            add_bullet(doc, f"Severity: {severity}")

            if 'confidence' in alert and alert['confidence']:
                add_bullet(doc, f"Confidence: {alert['confidence']}")

            if 'cweid' in alert and alert['cweid']:
                add_bullet(doc, f"CWE ID: {alert['cweid']}")

            if 'wascid' in alert and alert['wascid']:
                add_bullet(doc, f"WASC ID: {alert['wascid']}")

            doc.add_paragraph()

            # Description
            if alert.get('description'):
                para = add_paragraph(doc, 'Description:', bold=True)
                add_paragraph(doc, alert['description'].strip())
                doc.add_paragraph()

            # Solution
            if alert.get('solution'):
                para = add_paragraph(doc, 'Solution:', bold=True)
                add_paragraph(doc, alert['solution'].strip())
                doc.add_paragraph()

            # Supporting Evidence (first instance only)
            all_instances = []
            for a in alert_group:
                all_instances.extend(a.get('instances', []))

            if all_instances:
                first_instance = all_instances[0]

                para = add_paragraph(doc, 'Supporting Evidence:', bold=True)

                # Request Header
                if first_instance.get('request_header'):
                    add_paragraph(doc, 'Request Header:', bold=True)
                    para = doc.add_paragraph(first_instance['request_header'], style='Normal')
                    para.style.font.name = 'Courier New'
                    para.style.font.size = Pt(9)
                    doc.add_paragraph()

                # Request Body
                if first_instance.get('request_body'):
                    add_paragraph(doc, 'Request Body:', bold=True)
                    para = doc.add_paragraph(first_instance['request_body'], style='Normal')
                    para.style.font.name = 'Courier New'
                    para.style.font.size = Pt(9)
                    doc.add_paragraph()

                # Response Header
                if first_instance.get('response_header'):
                    add_paragraph(doc, 'Response Header:', bold=True)
                    para = doc.add_paragraph(first_instance['response_header'], style='Normal')
                    para.style.font.name = 'Courier New'
                    para.style.font.size = Pt(9)
                    doc.add_paragraph()

                # Response Body
                if first_instance.get('response_body'):
                    add_paragraph(doc, 'Response Body:', bold=True)
                    para = doc.add_paragraph(first_instance['response_body'][:500], style='Normal')  # Truncate if too long
                    para.style.font.name = 'Courier New'
                    para.style.font.size = Pt(9)
                    if len(first_instance['response_body']) > 500:
                        add_paragraph(doc, '... (truncated)')
                    doc.add_paragraph()

            # Reference
            if alert.get('reference'):
                para = add_paragraph(doc, 'References:', bold=True)
                for ref in alert['reference'].split('\n'):
                    ref = ref.strip()
                    if ref:
                        add_bullet(doc, ref)
                doc.add_paragraph()

            # Affected Systems (deduplicated)
            if all_instances:
                # Extract unique base URLs
                systems = set()
                for instance in all_instances:
                    if isinstance(instance, dict) and instance.get('uri'):
                        base_url = extract_base_url(instance['uri'])
                        systems.add(base_url)

                if systems:
                    para = add_paragraph(doc, f"Affected Systems ({len(systems)} system{'s' if len(systems) != 1 else ''}):", bold=True)
                    for system in sorted(systems):
                        add_bullet(doc, system)
                    doc.add_paragraph()

            doc.add_paragraph('_' * 80)
            doc.add_paragraph()

    return doc

def print_test_output(metadata, alerts_by_severity, all_alerts, target_name):
    """Print test output showing document structure"""
    print("\n" + "="*60)
    print("TEST MODE - Document Structure Preview")
    print("="*60 + "\n")

    print(f"TITLE: {metadata['program']} Security Assessment Report")
    print(f"SUBTITLE: {target_name}\n")

    print("SECTION: Executive Summary")
    total_findings = len(all_alerts)
    unique_findings = len(set(alert['name'] for alert in all_alerts))
    print(f"  {total_findings} total findings, {unique_findings} unique\n")

    print("SECTION: Scan Information")
    print(f"  - Scanner: {metadata['program']} {metadata['version']}")
    print(f"  - Scan Date: {metadata['generated']}")
    print(f"  - Total: {total_findings}, Unique: {unique_findings}\n")

    print("SECTION: Findings Summary")
    severity_order = ['High', 'Medium', 'Low', 'Informational']
    for severity in severity_order:
        count = len(alerts_by_severity.get(severity, []))
        if count > 0:
            print(f"  {severity}: {count} finding(s)")
    print()

    line_count = 0
    max_lines = 30

    for severity in severity_order:
        alerts = alerts_by_severity.get(severity, [])
        if not alerts or line_count >= max_lines:
            continue

        print(f"SECTION: {severity} Severity Findings")
        line_count += 1

        alerts_by_name = defaultdict(list)
        for alert in alerts:
            alerts_by_name[alert['name']].append(alert)

        shown = 0
        for alert_name, alert_group in alerts_by_name.items():
            if shown >= 2 or line_count >= max_lines:
                remaining = len(alerts_by_name) - shown
                if remaining > 0:
                    print(f"  ... and {remaining} more {severity} findings")
                break

            print(f"  FINDING: {alert_name}")
            alert = alert_group[0]

            print(f"    - Severity: {severity}")
            if 'confidence' in alert and alert['confidence']:
                print(f"    - Confidence: {alert['confidence']}")

            instance_count = sum(len(a.get('instances', [])) for a in alert_group)
            if instance_count > 0:
                print(f"    - Affected Locations: {instance_count}")

            print()
            shown += 1
            line_count += 4

    print("="*60)
    print(f"Full report would contain all {unique_findings} unique findings")
    print("="*60)

def process_report(input_path, report_type, args):
    """Process a single report file"""
    try:
        if report_type == 'zap_xml':
            metadata, alerts_by_severity, all_alerts = parse_xml_report(input_path)
        elif report_type == 'zap_html':
            metadata, alerts_by_severity, all_alerts = parse_html_report(input_path)
        elif report_type == 'burp_xml':
            metadata, alerts_by_severity, all_alerts = parse_burp_report(input_path)

        print(f"[+] Parsed {len(all_alerts)} total findings from {input_path.name}")

    except Exception as e:
        print(f"[!] Error parsing report: {e}")
        import traceback
        traceback.print_exc()
        return

    if args.test:
        print_test_output(metadata, alerts_by_severity, all_alerts, args.target)
        return

    try:
        doc = generate_docx_report(metadata, alerts_by_severity, all_alerts, args.target)
    except Exception as e:
        print(f"[!] Error generating DOCX: {e}")
        import traceback
        traceback.print_exc()
        return

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_name(f"{input_path.stem}_report.docx")

    try:
        doc.save(str(output_path))
        print(f"[+] Report written to: {output_path}")
    except Exception as e:
        print(f"[!] Error writing report: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Parse OWASP ZAP and Burp Suite reports into DOCX format'
    )
    parser.add_argument(
        'input_file',
        nargs='?',
        help='Report file (ZAP XML/HTML or Burp XML). If omitted, scans current directory.'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output DOCX file (default: <input>_report.docx)'
    )
    parser.add_argument(
        '-t', '--target',
        default='Target',
        help='Target name for report header (default: Target)'
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help='Test mode: print document structure to console instead of writing file'
    )

    args = parser.parse_args()

    # Auto-detect files if no input specified
    if not args.input_file:
        print("[*] No input file specified, scanning current directory...")
        reports = find_reports_in_directory()

        if not reports:
            print("[!] No supported report files found in current directory")
            sys.exit(1)

        print(f"[*] Found {len(reports)} supported report(s):")
        for i, (file, report_type) in enumerate(reports, 1):
            print(f"  {i}. {file.name} ({report_type.replace('_', ' ').upper()})")

        choice = input(f"\nSelect file (1-{len(reports)}) or 'all': ").strip().lower()

        if choice == 'all':
            files_to_process = reports
        else:
            try:
                idx = int(choice) - 1
                files_to_process = [reports[idx]]
            except (ValueError, IndexError):
                print("[!] Invalid selection")
                sys.exit(1)

        for input_path, report_type in files_to_process:
            process_report(input_path, report_type, args)

        return

    # Single file processing
    input_path = Path(args.input_file)

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    report_type = detect_format(input_path)
    print(f"[*] Detected: {report_type.replace('_', ' ').upper()}")

    if report_type not in ['zap_xml', 'zap_html', 'burp_xml']:
        print(f"[!] Unsupported report type: {report_type}")
        sys.exit(1)

    process_report(input_path, report_type, args)

if __name__ == '__main__':
    main()
