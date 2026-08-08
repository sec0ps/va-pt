#!/usr/bin/env python3
# =============================================================================
# Location: tools/cloud_bucket_browser.py
#
# Author: Keith Pachulski
# Company: Red Cell Security LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the MIT License.
#
# Purpose: Enumerate a publicly listable cloud storage bucket from a single
#          URL. Detects S3-compatible XML listings (AWS S3, Google Cloud
#          Storage, DigitalOcean Spaces, other S3-clones) and Azure Blob
#          container listings, walks all pagination, and applies client-side
#          filters by file extension and keyword. Supports optional threaded
#          retrieval of matched objects with path-traversal protection.
#
# SECURITY NOTICE: This tool is intended solely for authorized security
#          assessments and penetration testing engagements where the operator
#          has explicit written permission to enumerate the target storage.
#          It only reads listings and objects that the target has exposed to
#          anonymous access. Use against systems without authorization is
#          prohibited.
#
# DISCLAIMER: This software is provided as is, without warranty of any kind.
#          The author and Red Cell Security LLC assume no liability for misuse
#          or for any damage resulting from the use of this software.
# =============================================================================

import argparse
import concurrent.futures
import json
import os
import sys
from urllib.parse import quote, urlparse, urlunparse
from xml.etree import ElementTree as ET

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class BucketError(Exception):
    pass


def strip_ns(tag):
    # Providers wrap element tags in an XML namespace. Match on local name.
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_xml(content):
    try:
        return ET.fromstring(content)
    except ET.ParseError as exc:
        raise BucketError("XML parse error, response was not a bucket listing (%s)" % exc)


def normalize_base(url):
    # Reduce any supplied URL to scheme://host/path/ with no query or fragment.
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise BucketError("could not parse a host from the supplied URL")
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = path + "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def object_url(base, key):
    return base + quote(key, safe="/")


def detect_provider(base, override):
    if override != "auto":
        return override
    host = urlparse(base).netloc.lower()
    if host.endswith("blob.core.windows.net"):
        return "azure"
    return "s3"


def build_session(args):
    session = requests.Session()
    retry = Retry(
        total=args.retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=max(args.threads, 4),
        pool_maxsize=max(args.threads, 4),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": args.user_agent})
    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})
    session.verify = not args.insecure
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


def check_status(resp):
    if resp.status_code == 403:
        raise BucketError("access denied (HTTP 403), anonymous listing not permitted")
    if resp.status_code == 404:
        raise BucketError("bucket or container not found (HTTP 404)")
    if resp.status_code >= 400:
        raise BucketError("unexpected HTTP status %d" % resp.status_code)


def raise_if_error_doc(root):
    if strip_ns(root.tag) != "Error":
        return
    code = ""
    message = ""
    for child in root:
        name = strip_ns(child.tag)
        if name == "Code":
            code = child.text or ""
        elif name == "Message":
            message = child.text or ""
    raise BucketError("bucket returned an error document (%s: %s)" % (code, message))


def list_s3(session, base, timeout, max_pages):
    marker = ""
    pages = 0
    while True:
        params = {}
        if marker:
            params["marker"] = marker
        resp = session.get(base, params=params, timeout=timeout)
        check_status(resp)
        root = parse_xml(resp.content)
        raise_if_error_doc(root)
        if strip_ns(root.tag) != "ListBucketResult":
            raise BucketError("root element was <%s>, not an S3 listing" % strip_ns(root.tag))

        last_key = None
        truncated = False
        next_marker = None
        for elem in root:
            name = strip_ns(elem.tag)
            if name == "Contents":
                key = size = lastmod = None
                for child in elem:
                    cname = strip_ns(child.tag)
                    if cname == "Key":
                        key = child.text
                    elif cname == "Size":
                        size = child.text
                    elif cname == "LastModified":
                        lastmod = child.text
                if key is not None:
                    last_key = key
                    yield {
                        "key": key,
                        "size": int(size) if size and size.isdigit() else 0,
                        "last_modified": lastmod or "",
                    }
            elif name == "IsTruncated":
                truncated = (elem.text or "").strip().lower() == "true"
            elif name == "NextMarker":
                next_marker = elem.text

        pages += 1
        if not truncated or (max_pages and pages >= max_pages):
            break
        marker = next_marker or last_key
        if not marker:
            break


def list_azure(session, base, timeout, max_pages):
    marker = ""
    pages = 0
    while True:
        params = {"restype": "container", "comp": "list"}
        if marker:
            params["marker"] = marker
        resp = session.get(base, params=params, timeout=timeout)
        check_status(resp)
        root = parse_xml(resp.content)
        if strip_ns(root.tag) != "EnumerationResults":
            raise BucketError("root element was <%s>, not an Azure listing" % strip_ns(root.tag))

        next_marker = None
        for elem in root:
            name = strip_ns(elem.tag)
            if name == "Blobs":
                for blob in elem:
                    if strip_ns(blob.tag) != "Blob":
                        continue
                    bname = ""
                    size = 0
                    lastmod = ""
                    for child in blob:
                        cname = strip_ns(child.tag)
                        if cname == "Name":
                            bname = child.text or ""
                        elif cname == "Properties":
                            for prop in child:
                                pname = strip_ns(prop.tag)
                                if pname == "Content-Length":
                                    text = prop.text or "0"
                                    size = int(text) if text.isdigit() else 0
                                elif pname == "Last-Modified":
                                    lastmod = prop.text or ""
                    if bname:
                        yield {"key": bname, "size": size, "last_modified": lastmod}
            elif name == "NextMarker":
                next_marker = (elem.text or "").strip()

        pages += 1
        if not next_marker or (max_pages and pages >= max_pages):
            break
        marker = next_marker


def key_extension(key):
    tail = key.rsplit("/", 1)[-1]
    if "." not in tail:
        return ""
    return tail.rsplit(".", 1)[-1].lower()


def apply_filters(entries, ignore_exts, match_words, exclude_words, match_all, min_size, max_size):
    ignore_exts = {e.lower().lstrip(".") for e in ignore_exts if e}
    match_words = [w.lower() for w in match_words if w]
    exclude_words = [w.lower() for w in exclude_words if w]
    for entry in entries:
        low = entry["key"].lower()
        if ignore_exts and key_extension(entry["key"]) in ignore_exts:
            continue
        if exclude_words and any(w in low for w in exclude_words):
            continue
        if match_words:
            if match_all and not all(w in low for w in match_words):
                continue
            if not match_all and not any(w in low for w in match_words):
                continue
        if min_size and entry["size"] < min_size:
            continue
        if max_size and entry["size"] > max_size:
            continue
        yield entry


def human_size(num):
    size = float(num)
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if size < 1024 or unit == "PB":
            if unit == "B":
                return "%dB" % int(size)
            return "%.1f%s" % (size, unit)
        size /= 1024
    return "%dB" % int(num)


def safe_dest(dest_root, key):
    root_abs = os.path.abspath(dest_root)
    dest = os.path.normpath(os.path.join(root_abs, key))
    if dest != root_abs and not dest.startswith(root_abs + os.sep):
        return None
    return dest


def download_one(session, base, entry, dest_root, timeout):
    key = entry["key"]
    if key.endswith("/"):
        return (key, "skip-dir", 0)
    dest = safe_dest(dest_root, key)
    if dest is None:
        return (key, "unsafe-path", 0)
    url = object_url(base, key)
    try:
        with session.get(url, timeout=timeout, stream=True) as resp:
            if resp.status_code != 200:
                return (key, "http-%d" % resp.status_code, 0)
            parent = os.path.dirname(dest)
            if parent:
                os.makedirs(parent, exist_ok=True)
            total = 0
            with open(dest, "wb") as handle:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        handle.write(chunk)
                        total += len(chunk)
            return (key, "ok", total)
    except Exception as exc:
        return (key, "error:%s" % exc, 0)


def print_table(entries, base, show_urls):
    if not entries:
        print("[-] no objects matched the current filters")
        return
    width = len(str(len(entries)))
    for idx, entry in enumerate(entries, 1):
        size = human_size(entry["size"]).rjust(9)
        stamp = (entry["last_modified"] or "")[:19].ljust(19)
        line = "[%s] %s  %s  %s" % (str(idx).rjust(width), size, stamp, entry["key"])
        print(line)
        if show_urls:
            print(" " * (width + 4) + object_url(base, entry["key"]))


def run_download(session, base, entries, dest_root, threads, timeout):
    os.makedirs(dest_root, exist_ok=True)
    ok = 0
    total_bytes = 0
    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [
            pool.submit(download_one, session, base, entry, dest_root, timeout)
            for entry in entries
        ]
        for future in concurrent.futures.as_completed(futures):
            key, status, size = future.result()
            if status == "ok":
                ok += 1
                total_bytes += size
                print("[+] %s (%s)" % (key, human_size(size)))
            elif status == "skip-dir":
                continue
            else:
                failed += 1
                print("[!] %s (%s)" % (key, status))
    print("[*] downloaded %d objects (%s), %d failed" % (ok, human_size(total_bytes), failed))


def csv_arg(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser():
    parser = argparse.ArgumentParser(
        description="Enumerate and filter a public cloud storage bucket from a URL.",
    )
    parser.add_argument("url", help="bucket or container URL (S3, GCS, Spaces, Azure Blob)")
    parser.add_argument("-i", "--ignore-ext", type=csv_arg, default=[],
                        help="comma list of extensions to drop (e.g. jpg,png,css)")
    parser.add_argument("-m", "--match", type=csv_arg, default=[],
                        help="comma list of keywords, keys matching are kept")
    parser.add_argument("-x", "--exclude", type=csv_arg, default=[],
                        help="comma list of keywords, keys matching are dropped")
    parser.add_argument("--match-all", action="store_true",
                        help="require every --match word instead of any")
    parser.add_argument("--provider", choices=["auto", "s3", "azure"], default="auto",
                        help="listing format, auto-detected by default")
    parser.add_argument("--min-size", type=int, default=0, help="minimum object size in bytes")
    parser.add_argument("--max-size", type=int, default=0, help="maximum object size in bytes")
    parser.add_argument("--max-pages", type=int, default=0,
                        help="cap listing pages, 0 means unlimited")
    parser.add_argument("-d", "--download", metavar="DIR",
                        help="download matched objects into DIR")
    parser.add_argument("-t", "--threads", type=int, default=8, help="download worker count")
    parser.add_argument("--timeout", type=int, default=20, help="per-request timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="HTTP retry count")
    parser.add_argument("--urls", action="store_true", help="print full object URLs")
    parser.add_argument("--json", action="store_true", help="emit results as JSON")
    parser.add_argument("-o", "--output", metavar="FILE", help="write matched keys to FILE")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (compatible; RCS-BucketBrowser/1.0)")
    parser.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--insecure", action="store_true", help="disable TLS verification")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress status output")
    return parser


def main():
    args = build_parser().parse_args()
    try:
        base = normalize_base(args.url)
    except BucketError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 2

    provider = detect_provider(base, args.provider)
    session = build_session(args)

    if not args.quiet:
        print("[*] target  %s" % base, file=sys.stderr)
        print("[*] format  %s" % provider, file=sys.stderr)

    lister = list_azure if provider == "azure" else list_s3
    try:
        raw = lister(session, base, args.timeout, args.max_pages)
        entries = list(apply_filters(
            raw, args.ignore_ext, args.match, args.exclude,
            args.match_all, args.min_size, args.max_size,
        ))
    except BucketError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        print("[!] request failed (%s)" % exc, file=sys.stderr)
        return 1

    entries.sort(key=lambda item: item["key"])

    if args.json:
        payload = [
            {"key": e["key"], "size": e["size"], "last_modified": e["last_modified"],
             "url": object_url(base, e["key"])}
            for e in entries
        ]
        print(json.dumps(payload, indent=2))
    else:
        print_table(entries, base, args.urls)
        if not args.quiet:
            total = sum(e["size"] for e in entries)
            print("[*] %d objects, %s total" % (len(entries), human_size(total)), file=sys.stderr)

    if args.output:
        with open(args.output, "w") as handle:
            for entry in entries:
                handle.write(entry["key"] + "\n")
        if not args.quiet:
            print("[*] wrote %d keys to %s" % (len(entries), args.output), file=sys.stderr)

    if args.download and entries:
        run_download(session, base, entries, args.download, args.threads, args.timeout)

    return 0


if __name__ == "__main__":
    sys.exit(main())
