#!/usr/bin/env python3
"""
wsdl_recon.py

Usage:
  python wsdl_recon.py --wsdl https://example.com/service?wsdl             # dry-run (no SOAP calls)
  python wsdl_recon.py --wsdl /path/to/local.wsdl --send                 # actively POST SOAP calls (explicit opt-in)
  python wsdl_recon.py --wsdl https://... --send --op getTimerDetails    # send only that operation
"""

import argparse
import json
import re
import sys
import time
from collections import defaultdict

import requests
from zeep import Client, Settings
from zeep.exceptions import XMLSyntaxError, Fault
from zeep.transports import Transport
from zeep.plugins import HistoryPlugin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

SUSPICIOUS_KEYWORDS = [
    "password", "passwd", "credential", "secret", "token", "key", "username", "user", "admin",
    "provider_url", "providerurl", "initial_context_factory", "security_credentials",
    "security_principal", "PROVIDER_URL", "SECURITY_CREDENTIALS", "SECURITY_PRINCIPAL",
    "connectionFactory", "connection_factory", "destinationName", "destinationType",
    "customProcessor", "customReader", "customWriter", "customPropertyFile", "msgSource",
]

def requests_session_with_retries(timeout=10, retries=2, backoff=0.5):
    """
    Create a requests.Session with retry logic and default timeout handling.
    This version fixes the previous 'multiple values for timeout' error by
    not forcing timeout twice (zeep handles it internally).
    """
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import requests

    s = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": "wsdl-recon/1.0"})

    # ✅ FIX: patched request wrapper to prevent duplicate timeout kwarg
    original_request = s.request

    def patched_request(*args, **kwargs):
        # only add timeout if caller did not already include one
        if "timeout" not in kwargs:
            kwargs["timeout"] = timeout
        return original_request(*args, **kwargs)

    s.request = patched_request
    return s


def load_client(wsdl_url_or_path, verify=True, timeout=15):
    """
    Initialize Zeep SOAP client with fixed transport, session and timeouts.
    """
    from zeep import Client, Settings
    from zeep.transports import Transport
    from zeep.plugins import HistoryPlugin

    session = requests_session_with_retries(timeout=timeout)
    # Respect SSL verification
    session.verify = verify

    transport = Transport(session=session, timeout=timeout, operation_timeout=timeout)
    settings = Settings(strict=False, xml_huge_tree=True)
    history = HistoryPlugin()

    try:
        client = Client(wsdl=wsdl_url_or_path, transport=transport,
                        settings=settings, plugins=[history])
    except Exception as e:
        raise RuntimeError(f"Failed to parse WSDL: {e}")

    return client, history

def detect_axis_version_from_comments(wsdl_text):
    # naive: look for "Apache Axis"
    if wsdl_text is None:
        return None
    m = re.search(r"Apache Axis version[:\s]*([0-9\.]+)", wsdl_text, re.I)
    if m:
        return m.group(1)
    if "Apache Axis" in wsdl_text:
        return "axis (unknown version)"
    return None

def find_suspicious_elements(client):
    findings = []
    schema = client.wsdl.types

    # Safely iterate over types (dict or generator)
    try:
        type_items = schema.types.items() if hasattr(schema.types, 'items') else list(schema.types)
    except Exception:
        type_items = []

    for entry in type_items:
        if isinstance(entry, tuple):
            qname, type_obj = entry
            type_name = str(qname.localname)
        else:
            type_obj = entry
            qname = getattr(type_obj, 'qname', None)
            type_name = str(qname.localname) if qname else str(type_obj)

        if hasattr(type_obj, 'elements'):
            for element in type_obj.elements:
                ename = getattr(element, 'name', '').lower()
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in ename:
                        findings.append({
                            "complexType": type_name,
                            "field": ename,
                            "matched": kw
                        })

    # Top-level elements
    try:
        elem_items = schema.elements.items() if hasattr(schema.elements, 'items') else list(schema.elements)
    except Exception:
        elem_items = []

    for entry in elem_items:
        if isinstance(entry, tuple):
            qname, element = entry
            ename = str(qname.localname).lower()
        else:
            element = entry
            ename = getattr(element, 'name', '').lower()

        for kw in SUSPICIOUS_KEYWORDS:
            if kw in ename:
                findings.append({
                    "element": ename,
                    "matched": kw
                })

    return findings


def list_operations(client):
    services = {}
    for service_name, service in client.wsdl.services.items():
        services[service_name] = {}
        for port_name, port in service.ports.items():
            binding = port.binding
            ops = {}
            for op_name, op in binding._operations.items():
                ops[op_name] = {
                    "input": str(op.input.signature()) if op.input is not None else None,
                    "output": str(op.output.signature()) if op.output is not None else None,
                    "soapaction": op.soapaction if hasattr(op, "soapaction") else None,
                    "style": getattr(binding, 'style', None),
                    "operation": op,
                }
            services[service_name][port_name] = {
                "address": port.binding_options.get('address'),
                "binding_name": str(binding.name),
                "operations": ops,
            }
    return services

def build_example_request(client, history, service_name, port_name, operation_name, timeout=10):
    """
    Create example message by invoking create_message on client.
    We will not actually send the request here; instead we create a message object and return the xml.
    If create_message fails, return None.
    """
    try:
        service = client.wsdl.services.get(service_name)
        if not service:
            return None
        port = service.ports.get(port_name)
        # zeep Client has a method create_message which expects a proxy. Use client.create_message with the binding proxy.
        # If it fails we fall back to attempting a call with HistoryPlugin and then aborting gracefully.
        # The following is a best-effort approach:
        # Attempt to call create_message using the "client.create_message" helper:
        xml = client.create_message(client.service, operation_name)
        # create_message returns an lxml Element; convert to string
        from lxml import etree
        xml_str = etree.tostring(xml, pretty_print=True, encoding='utf-8').decode('utf-8')
        return xml_str
    except Exception:
        # Fallback: attempt to call operation with no args to produce payload captured by history (non-destructive)
        try:
            # call with _soapheaders=None but we want to avoid side effects. So don't perform this fallback without user consent.
            return None
        except Exception:
            return None

def do_active_call(client, history, service_name, port_name, operation_name, timeout=15):
    """
    Actively call operation with dummy inputs (best-effort) capturing request/response via HistoryPlugin.
    WARNING: this will actually send SOAP requests. Only call when authorized and user set --send.
    """
    # Create simple dummy kwargs by inspecting the operation signature
    op = None
    try:
        service = client.wsdl.services[service_name]
        port = service.ports[port_name]
        binding = port.binding
        op = binding._operations[operation_name]
    except Exception:
        pass

    # build minimal kwargs: for each parameter in input message, set dummy values
    kwargs = {}
    try:
        if op and op.input and op.input.body:
            # get element children
            # Zeep provides op.input.signature() but parsing it is messy; do best-effort no args
            pass
    except Exception:
        pass

    # Try calling; allow exceptions to be returned in results
    result = {"sent": None, "response": None, "error": None, "http_status": None, "response_headers": None}
    try:
        # call via getattr(client.service, operation_name)(**kwargs)
        func = getattr(client.service, operation_name)
        # attempt call with empty args (many RPC encoded ops accept empty)
        res = func(_timeout=timeout)
        # HistoryPlugin recorded last sent and received
        last_sent = None
        last_received = None
        try:
            last_sent = history.last_sent["envelope"].decode('utf-8') if history.last_sent and "envelope" in history.last_sent else None
        except Exception:
            last_sent = None
        try:
            last_received = history.last_received["envelope"].decode('utf-8') if history.last_received and "envelope" in history.last_received else None
        except Exception:
            last_received = None
        result.update({"sent": last_sent, "response": last_received, "result_object": res})
    except Fault as f:
        # SOAP Fault returned
        result["error"] = f.message
        try:
            last_sent = history.last_sent["envelope"].decode('utf-8')
            last_received = history.last_received["envelope"].decode('utf-8')
            result.update({"sent": last_sent, "response": last_received})
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)
    return result

def scan_wsdl(wsdl_url_or_path, do_send=False, target_ops=None, timeout=15, verify_tls=True):
    report = {
        "wsdl": wsdl_url_or_path,
        "timestamp": time.time(),
        "axis_version": None,
        "services": {},
        "suspicious_elements": [],
        "warnings": [],
        "active_results": {},
    }
    # try to fetch raw WSDL text for simple checks (comments, imports pointing to external)
    raw_wsdl = None
    try:
        if wsdl_url_or_path.startswith("http"):
            resp = requests.get(wsdl_url_or_path, timeout=timeout, verify=verify_tls, headers={"User-Agent":"wsdl-recon/1.0"})
            raw_wsdl = resp.text
        else:
            with open(wsdl_url_or_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_wsdl = f.read()
    except Exception:
        raw_wsdl = None

    if raw_wsdl:
        av = detect_axis_version_from_comments(raw_wsdl)
        if av:
            report["axis_version"] = av
        # detect schema imports referencing file:// or suspicious endpoints
        imports = re.findall(r'<import[^>]*schemaLocation=["\']([^"\']+)["\']', raw_wsdl, flags=re.I)
        for imp in imports:
            if imp.startswith("file:") or imp.lower().startswith("http://") and not wsdl_url_or_path.lower().startswith("http://"):
                report["warnings"].append({"import": imp})
            if imp.startswith("http://"):
                report["warnings"].append({"import_http": imp})

    # create zeep client
    try:
        client, history = load_client(wsdl_url_or_path, verify=verify_tls, timeout=timeout)
    except Exception as e:
        report["warnings"].append({"load_wsdl_failed": str(e)})
        return report

    # list operations & endpoints
    services = list_operations(client)
    report["services"] = {}
    for service_name, ports in services.items():
        report["services"][service_name] = {}
        for port_name, port_info in ports.items():
            address = port_info.get("address")
            report["services"][service_name][port_name] = {
                "address": address,
                "binding": port_info.get("binding_name"),
                "operations": list(port_info.get("operations", {}).keys()),
            }
            # weak indicator: HTTP endpoint or mismatched scheme
            if address:
                if address.lower().startswith("http://"):
                    report["warnings"].append({"http_endpoint": address})
                if address.lower().startswith("https://") is False and wsdl_url_or_path.startswith("https://"):
                    # endpoint insecure relative to WSDL
                    report["warnings"].append({"insecure_endpoint_mismatch": address})

            # detect RPC/encoded style
            for op_name, op_meta in port_info.get("operations", {}).items():
                style = op_meta.get("style")
                soapaction = op_meta.get("soapaction")
                if style and "rpc" in str(style).lower():
                    report["warnings"].append({"rpc_style": f"{service_name}/{port_name}/{op_name}"})
                # use="encoded" detection: check op input/output use attribute if possible
                # To avoid deep internal parse, look for 'encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"' in raw WSDL as indicator:
                if raw_wsdl and re.search(r'encodingStyle=["\']http://schemas.xmlsoap.org/soap/encoding/["\']', raw_wsdl):
                    report["warnings"].append({"encoded_style_detected": True})

    # find suspicious elements/fields in types
    report["suspicious_elements"] = find_suspicious_elements(client)

    # build example requests (non-destructive)
    report["examples"] = {}
    for service_name, ports in client.wsdl.services.items():
        report["examples"][service_name] = {}
        for port_name, port in ports.ports.items():
            report["examples"][service_name][port_name] = {}
            for op_name in port.binding._operations.keys():
                if target_ops and op_name not in target_ops:
                    continue
                xml = build_example_request(client, history, service_name, port_name, op_name)
                report["examples"][service_name][port_name][op_name] = {"example_xml": xml}

    # active testing (explicit opt-in)
    if do_send:
        for sname, ports in client.wsdl.services.items():
            for pname, port in ports.ports.items():
                addr = port.binding_options.get("address")
                for op_name in port.binding._operations.keys():
                    if target_ops and op_name not in target_ops:
                        continue
                    key = f"{sname}/{pname}/{op_name}"
                    try:
                        act = do_active_call(client, history, sname, pname, op_name, timeout=timeout)
                        report["active_results"][key] = act
                        # quick check for common leakage patterns in response
                        resp = act.get("response") or ""
                        if resp and re.search(r"(Exception|StackTrace|java\.lang|org\.apache\.axis|at\s+org\.)", resp, re.I):
                            report["warnings"].append({"server_stacktrace_exposed": key})
                    except Exception as e:
                        report["active_results"][key] = {"error": str(e)}
    else:
        report["notes"] = "dry-run: run with --send to actively POST SOAP requests (only do if authorized)."

    return report

def main():
    ap = argparse.ArgumentParser(description="WSDL reconnaissance and safe testing tool")
    ap.add_argument("--wsdl", required=True, help="WSDL URL or local path")
    ap.add_argument("--send", action="store_true", help="Actively send test SOAP requests (explicit opt-in).")
    ap.add_argument("--op", action="append", help="Operation(s) to target (repeatable). If omitted, all operations enumerated.")
    ap.add_argument("--timeout", type=int, default=15, help="Network timeout seconds")
    ap.add_argument("--no-verify-tls", action="store_true", help="Do not verify TLS (useful for self-signed test systems).")
    ap.add_argument("--out", help="Write JSON report to file")
    args = ap.parse_args()

    verify_tls = not args.no_verify_tls

    print(f"[+] Loading WSDL: {args.wsdl}")
    try:
        report = scan_wsdl(args.wsdl, do_send=args.send, target_ops=args.op, timeout=args.timeout, verify_tls=verify_tls)
    except Exception as e:
        print(f"[!] Failed: {e}")
        sys.exit(2)

    # print summary
    print(json.dumps({
        "wsdl": report["wsdl"],
        "timestamp": report["timestamp"],
        "axis_version": report.get("axis_version"),
        "num_services": len(report.get("services", {})),
        "suspicious_count": len(report.get("suspicious_elements", [])),
        "warnings_count": len(report.get("warnings", [])),
        "active_results_count": len(report.get("active_results", {})),
    }, indent=2))

    # if out specified or always, dump full report
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Full report written to {args.out}")
    else:
        # print readable summary and key findings
        print("\n=== Key findings ===")
        if report.get("axis_version"):
            print(f" - Axis/version info found: {report['axis_version']}")
        if report.get("warnings"):
            print(" - Warnings:")
            for w in report["warnings"]:
                print("    *", w)
        if report.get("suspicious_elements"):
            print(" - Suspicious elements/fields:")
            for se in report["suspicious_elements"][:20]:
                print("    *", se)
        print("\nDetailed examples and active results available in JSON report (use --out to save full report).")

if __name__ == "__main__":
    main()
