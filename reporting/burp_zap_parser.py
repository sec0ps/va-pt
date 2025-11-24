#!/usr/bin/env python3
"""
OWASP ZAP and Burp Suite Report Parser
Parses ZAP XML/HTML and Burp Suite XML reports into DOCX format
"""

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
                uri = instance.findtext('uri', '')
                method = instance.findtext('method', '')
                param = instance.findtext('param', '')

                instance_data = {
                    'uri': uri,
                    'method': method,
                    'param': param
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
        if host and path:
            instance = {
                'uri': f"{host}{path}",
                'method': issue.findtext('method', ''),
                'param': ''
            }
            alert_data['instances'].append(instance)

        risk_level = alert_data['risk']
        alerts_by_severity[risk_level].append(alert_data)
        all_alerts.append(alert_data)

    return metadata, alerts_by_severity, all_alerts

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

    # Title
    title = doc.add_heading(f'{metadata["program"]} Security Assessment Report', level=1)
    subtitle = doc.add_heading(target_name, level=2)
    doc.add_paragraph()

    # Executive Summary
    add_heading(doc, 'Executive Summary', level=1)

    total_findings = len(all_alerts)
    unique_findings = len(set(alert['name'] for alert in all_alerts))

    summary_text = (f"This report presents the findings from an automated security assessment using {metadata['program']}. "
                   f"The scan identified {total_findings} total security findings across {unique_findings} unique vulnerability types.")
    add_paragraph(doc, summary_text)
    doc.add_paragraph()

    # Scan Information
    add_heading(doc, 'Scan Information', level=1)
    add_bullet(doc, f"Scanner: {metadata['program']} {metadata['version']}")
    add_bullet(doc, f"Scan Date: {metadata['generated']}")
    add_bullet(doc, f"Total Findings: {total_findings}")
    add_bullet(doc, f"Unique Vulnerabilities: {unique_findings}")
    doc.add_paragraph()

    # Findings Summary
    add_heading(doc, 'Findings Summary', level=1)

    severity_order = ['High', 'Medium', 'Low', 'Informational']
    for severity in severity_order:
        count = len(alerts_by_severity.get(severity, []))
        if count > 0:
            para = add_paragraph(doc, f"{severity}: ", bold=True)
            para.add_run(f"{count} finding{'s' if count != 1 else ''}")
    doc.add_paragraph()

    # Detailed Findings by Severity
    for severity in severity_order:
        alerts = alerts_by_severity.get(severity, [])
        if not alerts:
            continue

        add_heading(doc, f'{severity} Severity Findings', level=1)

        # Group by alert name to avoid duplicates
        alerts_by_name = defaultdict(list)
        for alert in alerts:
            alerts_by_name[alert['name']].append(alert)

        for alert_name, alert_group in alerts_by_name.items():
            add_heading(doc, alert_name, level=2)

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

            # Reference
            if alert.get('reference'):
                para = add_paragraph(doc, 'References:', bold=True)
                for ref in alert['reference'].split('\n'):
                    ref = ref.strip()
                    if ref:
                        add_bullet(doc, ref)
                doc.add_paragraph()

            # Affected URLs/Instances
            all_instances = []
            for a in alert_group:
                all_instances.extend(a.get('instances', []))

            if all_instances:
                para = add_paragraph(doc, f"Affected Locations ({len(all_instances)} instance{'s' if len(all_instances) != 1 else ''}):", bold=True)

                for instance in all_instances[:10]:
                    if isinstance(instance, dict):
                        uri = instance.get('uri', '')
                        method = instance.get('method', '')
                        param = instance.get('param', '')

                        if uri:
                            loc = uri
                            if method:
                                loc += f" ({method})"
                            if param:
                                loc += f" [Parameter: {param}]"
                            add_bullet(doc, loc)
                    else:
                        add_bullet(doc, str(instance))

                if len(all_instances) > 10:
                    add_bullet(doc, f"... and {len(all_instances) - 10} more locations")

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
