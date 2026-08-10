#!/usr/bin/env python3
# =============================================================================
# Location    tools/nmap_url_extractor.py
# Author      Keith Pachulski
# Company     Red Cell Security LLC
# Email       keith@redcellsecurity.org
# Website     www.redcellsecurity.org
# License     MIT License
#
# Purpose
#   Parse an nmap XML scan and emit a deduplicated list of http/https URLs
#   with correct scheme and port, suitable for feeding into OWASP ZAP for
#   manual testing. Scheme is resolved solely from parsed service name and
#   tunnel state. Ports nmap did not identify as web services are not emitted.
#
# SECURITY NOTICE
#   This tool is intended for authorized security assessment and penetration
#   testing activities only. Use exclusively against systems for which explicit
#   written permission has been granted.
#
# DISCLAIMER
#   This software is provided "as is" without warranty of any kind. The author
#   and Red Cell Security LLC assume no liability for misuse or for any damages
#   resulting from the use of this software.
# =============================================================================
"""Extract http/https URLs from nmap XML output for ZAP ingestion."""

import argparse
import sys
import xml.etree.ElementTree as ET


def classify_scheme(service_name, tunnel):
    """Return 'https', 'http', or None based solely on parsed service data."""
    name = (service_name or "").lower()
    tun = (tunnel or "").lower()

    # Only ports nmap identified as an http-bearing service are web targets.
    if "http" not in name:
        return None

    # https when the service name says so or the port is wrapped in an ssl tunnel.
    if "https" in name or tun == "ssl":
        return "https"
    return "http"


def build_url(scheme, host, portid):
    """Build a clean URL, omitting the port when it is the scheme default."""
    default = 443 if scheme == "https" else 80
    if portid == default:
        return "{0}://{1}".format(scheme, host)
    return "{0}://{1}:{2}".format(scheme, host, portid)


def pick_host(host_elem, prefer_hostname):
    """Return the target host string, preferring a hostname when requested."""
    if prefer_hostname:
        hn = host_elem.find("./hostnames/hostname")
        if hn is not None and hn.get("name"):
            return hn.get("name")
    for addr in host_elem.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            return addr.get("addr")
    addr = host_elem.find("address")
    return addr.get("addr") if addr is not None else None


def parse(xml_path, prefer_hostname, include_filtered):
    """Parse the nmap XML file and return a sorted list of unique URLs."""
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        sys.stderr.write("error parsing XML, {0}\n".format(exc))
        sys.exit(2)
    except (OSError, IOError) as exc:
        sys.stderr.write("error reading file, {0}\n".format(exc))
        sys.exit(2)

    root = tree.getroot()
    urls = set()
    allowed_states = {"open"}
    if include_filtered:
        allowed_states.add("open|filtered")

    for host_elem in root.findall("host"):
        host = pick_host(host_elem, prefer_hostname)
        if not host:
            continue

        for port in host_elem.findall("./ports/port"):
            if port.get("protocol", "tcp").lower() != "tcp":
                continue

            state_elem = port.find("state")
            state = state_elem.get("state") if state_elem is not None else ""
            if state not in allowed_states:
                continue

            try:
                portid = int(port.get("portid"))
            except (TypeError, ValueError):
                continue

            service = port.find("service")
            svc_name = service.get("name") if service is not None else ""
            tunnel = service.get("tunnel") if service is not None else ""

            scheme = classify_scheme(svc_name, tunnel)
            if scheme is None:
                continue

            urls.add(build_url(scheme, host, portid))

    return sorted(urls)


def main():
    parser = argparse.ArgumentParser(
        description="Extract http/https URLs from nmap XML for ZAP ingestion"
    )
    parser.add_argument("xml", help="path to nmap XML output file")
    parser.add_argument(
        "-o", "--output", help="write URLs to file instead of stdout"
    )
    parser.add_argument(
        "--ip-only",
        action="store_true",
        help="use IP addresses even when a hostname is available",
    )
    parser.add_argument(
        "--include-filtered",
        action="store_true",
        help="also emit ports in the open|filtered state",
    )
    args = parser.parse_args()

    urls = parse(args.xml, not args.ip_only, args.include_filtered)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write("\n".join(urls) + ("\n" if urls else ""))
        except (OSError, IOError) as exc:
            sys.stderr.write("error writing output, {0}\n".format(exc))
            sys.exit(2)
        sys.stderr.write("wrote {0} URLs to {1}\n".format(len(urls), args.output))
    else:
        for url in urls:
            print(url)


if __name__ == "__main__":
    main()
