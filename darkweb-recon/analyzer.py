# =============================================================================
# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit
# =============================================================================
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
# Purpose: Bounded same-onion crawler and page text extractor for the darkweb recon subsystem. Fetches pages over Tor, strips scripts/styles, extracts visible text and onion links into an inert report, and exposes single-page text extraction used for matching watch terms against result page bodies.
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
# Location: darkweb-recon/analyzer.py

"""Bounded same-onion crawler that extracts visible text and links for inert review."""

import logging
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from fetch import FetchError

log = logging.getLogger("recon.analyzer")

STRIP_TAGS = ("script", "style", "noscript", "iframe", "svg", "head")
ASSET_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico", ".svg",
    ".css", ".js", ".mp4", ".webm", ".avi", ".mov", ".mp3", ".wav",
    ".zip", ".gz", ".tar", ".7z", ".rar", ".pdf", ".woff", ".woff2", ".ttf",
)

# Tags removed entirely when producing an inert snapshot: anything that can
# execute, submit, embed, or load an external resource. Inline <style> is kept
# (see inert_snapshot) so layout survives; CSP blocks any external css/@import.
SNAPSHOT_DROP_TAGS = (
    "script", "noscript", "iframe", "object", "embed", "applet", "form", "input",
    "button", "textarea", "select", "option", "link", "base", "meta", "svg",
    "canvas", "audio", "video", "source", "track", "frame", "frameset", "map",
    "area", "img", "picture", "portal",
)
# Attributes stripped from every surviving tag: event handlers and anything that
# navigates or loads a resource. CSP is the backstop; this removes the temptation.
SNAPSHOT_DROP_ATTRS = (
    "src", "srcset", "href", "action", "formaction", "background", "data",
    "poster", "ping", "xlink:href", "codebase", "cite", "usemap", "longdesc",
)


def inert_snapshot(raw_html):
    """Return a sanitized, non-executing HTML snapshot of raw_html.

    Removes scripts, frames, forms, media, and every external-resource or
    navigation reference, and strips event-handler and url()-bearing style
    attributes. Keeps text and inline layout styling. This is defense in depth:
    the snapshot is always served under a CSP sandbox with default-src 'none',
    so nothing executes or loads even if a reference survived here.
    """
    soup = BeautifulSoup(raw_html or "", "lxml")
    for tag in soup(list(SNAPSHOT_DROP_TAGS)):
        tag.decompose()
    for tag in soup.find_all(True):
        for attr in list(tag.attrs):
            low = attr.lower()
            if low.startswith("on") or low in SNAPSHOT_DROP_ATTRS:
                del tag[attr]
            elif low == "style" and "url(" in (tag[attr] or "").lower():
                del tag[attr]  # inline style pulling an external resource
    banner = soup.new_tag("div")
    banner["style"] = ("background:#15191f;color:#8a94a0;border-bottom:2px solid #e02435;"
                       "padding:8px 12px;font:12px sans-serif")
    banner.string = "inert snapshot \u2014 fetched over Tor, sanitized, nothing executes or loads"
    body = soup.body or soup
    body.insert(0, banner)
    return str(soup)


class Analyzer:
    def __init__(self, config):
        self.config = config

    def crawl(self, root_url, fetcher, isolation="default"):
        root_url = self._normalize(root_url)
        root_host = self._onion_host(root_url)
        if not root_host:
            raise FetchError("finding url is not an onion, cannot analyze")

        pages = []
        visited = set()
        queue = [(root_url, 0)]
        index = 0
        max_pages = self.config.analyze_max_pages

        while index < len(queue) and len(pages) < max_pages:
            url, depth = queue[index]
            index += 1
            if url in visited:
                continue
            visited.add(url)
            page = self._fetch_page(url, fetcher, isolation, root_host)
            if page is None:
                continue
            pages.append(page)
            if depth == 0:
                for link in page["links"]:
                    if not link["is_internal"]:
                        continue
                    if link["url"] in visited:
                        continue
                    if self._is_asset(link["url"]):
                        continue
                    queue.append((link["url"], 1))

        return pages

    def page_text(self, url, fetcher, isolation="default"):
        """Fetch a single page over Tor and return its extracted visible text.

        Reuses the crawl's fetch/strip/collapse path but does not follow links,
        so the worker can match watch terms against a result page's body without
        running a full analysis. Returns "" on any fetch failure (fail-soft).
        """
        target = self._normalize(url)
        root_host = self._onion_host(target) or ""
        page = self._fetch_page(target, fetcher, isolation, root_host)
        return page["text"] if page else ""

    def _fetch_page(self, url, fetcher, isolation, root_host):
        try:
            result = fetcher.get_with_retry(url, isolation=isolation)
        except FetchError as exc:
            log.warning("analyze fetch failed for %s: %s", url, exc)
            return None

        soup = BeautifulSoup(result["text"], "lxml")
        title_el = soup.find("title")
        title = title_el.get_text(strip=True) if title_el else ""
        links = self._links(soup, url, root_host)

        for tag in soup(list(STRIP_TAGS)):
            tag.decompose()
        text = soup.get_text("\n", strip=True)
        text = self._collapse(text)[: self.config.analyze_page_text_cap]

        return {"url": url, "title": title, "text": text, "links": links}

    def _links(self, soup, page_url, root_host):
        out = []
        seen = set()
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "data:")):
                continue
            full = urljoin(page_url, href)
            if full in seen:
                continue
            seen.add(full)
            host = self._onion_host(full)
            out.append({
                "url": full,
                "anchor": anchor.get_text(" ", strip=True)[:200],
                "is_onion": host is not None,
                "is_internal": host is not None and host == root_host,
            })
            if len(out) >= self.config.analyze_max_links_per_page:
                break
        return out

    def _onion_host(self, url):
        host = (urlparse(url).hostname or "").lower()
        if host.endswith(".onion"):
            return host
        return None

    def _is_asset(self, url):
        path = urlparse(url).path.lower()
        return path.endswith(ASSET_EXT)

    def _normalize(self, url):
        url = (url or "").strip()
        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url
        return url

    def _collapse(self, text):
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()
