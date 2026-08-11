#!/usr/bin/env python3
# =============================================================================
# Location: tools/nuclei_katana.py
#
# Author: Keith Pachulski
# Company: Red Cell Security LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# License: MIT License
#
# Purpose:
#   Spider a CLI-supplied target list with katana headless, then run nuclei
#   templated and -dast passes over the crawl, rendering one consolidated
#   markdown report per host filtered to critical, high, and medium severity.
#   The crawl drives both passes. The templated pass runs over the union of the
#   original targets and every crawled URL so discovered endpoints get
#   templated, and the -dast pass runs over the parameterized subset. Both sets
#   of findings merge into the per-host report under separate headings. This
#   crawl plus dast flow is the default. --no-dast runs a fast roots-only
#   templated scan instead. Targets with no findings still receive a clean
#   report so every system scanned has an artifact. An existing nuclei JSONL
#   file can be ingested directly with -j to regenerate reports without
#   rescanning.
#
# SECURITY NOTICE:
#   This tool is intended solely for authorized security assessment and
#   penetration testing engagements conducted within a defined scope. Use
#   against systems without explicit written authorization is prohibited.
#
# DISCLAIMER:
#   This software is provided as is without warranty of any kind. The author
#   and Red Cell Security LLC assume no liability for misuse or for any damage
#   resulting from use of this tool.
# =============================================================================

"""Spider targets with katana headless then run nuclei templated and -dast passes over the crawl, rendering one markdown report per host for critical, high, and medium findings. Crawl plus dast is the default."""

import argparse
import json
import os
import re
import subprocess

SEVERITY = "critical,high,medium"
REPORT_DIR = "reports"
CRAWL_DIR = "crawl"
JSONL_FILE = "nuclei_results.jsonl"
SCAN_URLS_FILE = "scan_urls.txt"
DAST_URLS_FILE = "dast_urls.txt"
DAST_JSONL_FILE = "nuclei_dast_results.jsonl"
KATANA_DEPTH = "3"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2}


def normalize_host(value):
    value = value.strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    return value


def is_ipv4(host):
    part = host.split(":", 1)[0]
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", part) is not None


def safe_name(host):
    if is_ipv4(host):
        host = host.replace(".", "_")
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)


def read_targets(path):
    targets = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def run_katana(target, out_path):
    cmd = [
        "katana",
        "-u", target,
        "-headless",
        "-jc",
        "-d", KATANA_DEPTH,
        "-fs", "fqdn",
        "-f", "url",
        "-silent",
        "-o", out_path,
    ]
    subprocess.run(cmd, check=False)


def crawl_targets(targets):
    os.makedirs(CRAWL_DIR, exist_ok=True)
    all_urls = set()
    for target in targets:
        host = normalize_host(target)
        out_path = os.path.join(CRAWL_DIR, f"{safe_name(host)}.txt")
        print(f"[*] crawling {target}")
        run_katana(target, out_path)
        if os.path.exists(out_path):
            with open(out_path) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        all_urls.add(line)
    print(f"[*] {len(all_urls)} URLs discovered by katana")
    return all_urls


def run_nuclei(targets_path, jsonl_path):
    if os.path.exists(jsonl_path):
        os.remove(jsonl_path)
    cmd = [
        "nuclei",
        "-l", targets_path,
        "-severity", SEVERITY,
        "-jsonl-export", jsonl_path,
        "-rate-limit", "150",
        "-concurrency", "25",
        "-timeout", "10",
        "-retries", "2",
        "-max-host-error", "30",
        "-follow-redirects",
        "-stats", "-stats-interval", "30",
    ]
    subprocess.run(cmd, check=False)


def run_nuclei_dast(url_list_path, jsonl_path):
    if os.path.exists(jsonl_path):
        os.remove(jsonl_path)
    cmd = [
        "nuclei",
        "-l", url_list_path,
        "-dast",
        "-severity", SEVERITY,
        "-jsonl-export", jsonl_path,
        "-rate-limit", "150",
        "-concurrency", "25",
        "-timeout", "10",
        "-retries", "2",
        "-max-host-error", "30",
        "-follow-redirects",
        "-stats", "-stats-interval", "30",
    ]
    subprocess.run(cmd, check=False)


def load_findings(jsonl_path):
    findings = {}
    if not os.path.exists(jsonl_path):
        return findings
    with open(jsonl_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                print(f"[!] {jsonl_path} is not nuclei JSONL. Pass a target list as the positional argument to scan.")
                return {}
            host = normalize_host(item.get("host") or item.get("matched-at") or "unknown")
            findings.setdefault(host, []).append(item)
    return findings


def render_findings_section(items):
    items.sort(key=lambda x: SEV_ORDER.get(x.get("info", {}).get("severity", "medium"), 9))
    lines = []
    for item in items:
        info = item.get("info", {})
        sev = info.get("severity", "unknown").upper()
        name = info.get("name") or item.get("template-id", "unnamed")
        lines.append(f"### [{sev}] {name}")
        lines.append("")
        lines.append(f"- Template: {item.get('template-id', 'n/a')}")
        lines.append(f"- Matched: {item.get('matched-at') or item.get('host', 'n/a')}")
        desc = info.get("description")
        if desc:
            lines.append(f"- Description: {desc.strip()}")
        refs = info.get("reference")
        if refs:
            if isinstance(refs, list):
                refs = ", ".join(refs)
            lines.append(f"- Reference: {refs}")
        extracted = item.get("extracted-results")
        if extracted:
            lines.append(f"- Extracted: {', '.join(extracted)}")
        curl = item.get("curl-command")
        if curl:
            lines.append("")
            lines.append("```")
            lines.append(curl)
            lines.append("```")
        lines.append("")
    return lines


def render_host_report(host, baseline_items, dast_items):
    total = len(baseline_items) + (len(dast_items) if dast_items else 0)
    lines = [f"# Nuclei Findings - {host}", "", f"Total findings: {total}", ""]

    lines.append("## Template Scan")
    lines.append("")
    if baseline_items:
        lines.extend(render_findings_section(baseline_items))
    else:
        lines.append("No critical, high, or medium findings.")
        lines.append("")

    if dast_items is not None:
        lines.append("## DAST Scan")
        lines.append("")
        if dast_items:
            lines.extend(render_findings_section(dast_items))
        else:
            lines.append("No critical, high, or medium findings.")
            lines.append("")

    return "\n".join(lines)


def write_reports(hosts, baseline, dast):
    for host in sorted(hosts):
        baseline_items = baseline.get(host, [])
        dast_items = None if dast is None else dast.get(host, [])
        path = os.path.join(REPORT_DIR, f"{safe_name(host)}.md")
        with open(path, "w") as fh:
            fh.write(render_host_report(host, baseline_items, dast_items))
        count = len(baseline_items) + (len(dast_items) if dast_items else 0)
        marker = "+" if count else "-"
        print(f"[{marker}] {path} ({count} findings)")


def main():
    parser = argparse.ArgumentParser(description="Spider targets with katana headless then run nuclei templated and -dast passes, rendering one markdown report per host for critical, high, and medium findings.")
    parser.add_argument("targets", nargs="?", help="target list to scan")
    parser.add_argument("-j", "--jsonl", help="ingest an existing nuclei JSONL results file and skip the scan")
    parser.add_argument("--no-dast", action="store_true", help="skip the katana crawl and dast pass, run a fast roots-only templated scan")
    args = parser.parse_args()

    os.makedirs(REPORT_DIR, exist_ok=True)

    if args.jsonl:
        if not os.path.exists(args.jsonl):
            print(f"JSONL file not found: {args.jsonl}")
            return
        baseline = load_findings(args.jsonl)
        if not baseline:
            print(f"No findings loaded from {args.jsonl}")
            return
        write_reports(set(baseline), baseline, None)
        return

    if not args.targets:
        parser.error("a target list is required, or use -j to ingest an existing JSONL")

    if not os.path.exists(args.targets):
        print(f"Target list not found: {args.targets}")
        return

    targets = read_targets(args.targets)
    if not targets:
        print(f"No targets in {args.targets}")
        return

    dast = None

    if args.no_dast:
        run_nuclei(args.targets, JSONL_FILE)
        baseline = load_findings(JSONL_FILE)
    else:
        all_urls = crawl_targets(targets)
        scan_targets = sorted(set(targets) | all_urls)
        with open(SCAN_URLS_FILE, "w") as fh:
            fh.write("\n".join(scan_targets) + "\n")
        print(f"[*] templated pass over {len(scan_targets)} URLs (targets plus crawl)")
        run_nuclei(SCAN_URLS_FILE, JSONL_FILE)
        baseline = load_findings(JSONL_FILE)

        qurls = sorted(u for u in all_urls if "?" in u)
        if qurls:
            with open(DAST_URLS_FILE, "w") as fh:
                fh.write("\n".join(qurls) + "\n")
            print(f"[*] dast pass over {len(qurls)} parameterized URLs")
            run_nuclei_dast(DAST_URLS_FILE, DAST_JSONL_FILE)
            dast = load_findings(DAST_JSONL_FILE)
        else:
            print("[!] no parameterized URLs from crawl, skipping DAST pass")
            dast = {}

    target_hosts = {normalize_host(t) for t in targets}
    hosts = set(baseline) | target_hosts
    if dast is not None:
        hosts |= set(dast)

    write_reports(hosts, baseline, dast)


if __name__ == "__main__":
    main()
