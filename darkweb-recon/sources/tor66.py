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
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: Tor66 onion search-engine source, queried over Tor. Submits the term
#          as a direct GET to the engine's /search?q= endpoint -- no form
#          discovery, ajax handshake, or session seeding is required -- and parses
#          the server-rendered results. Each result is a div.result-block holding
#          the target onion in its anchor href (deep links preserved so distinct
#          paths remain distinct findings), a title, a breadcrumb, and a
#          description in p#desc. Parsing is defensive: it prefers the result-block
#          container and degrades to scanning onion-bearing anchors if that markup
#          changes, so an upstream change lowers recall rather than raising.
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
# Location: darkweb-recon/sources/tor66.py

"""Tor66 onion search-engine source queried over Tor.

Tor66 serves results server-side from a plain GET on ``/search?q=<term>`` -- no
landing-page form to discover, no ajax nonce, and no session cookie to seed, so
search() issues the query directly. Each result is a ``div.result-block``: the
target onion is the anchor ``href`` (a full deep link, kept as-is so the same
onion under different paths stays a distinct finding), the display title is the
``div.title`` anchor text, and the snippet is ``p#desc`` -- whose repeated,
invalid ``id`` is read per block, with advertisement image-markdown stripped so
it neither pollutes the snippet nor gets scanned as page content. If the
result-block markup ever changes, parsing degrades to scanning onion-bearing
anchors, lowering recall instead of raising. Hits are deduplicated by url.
"""

from __future__ import annotations

import re
import logging
from urllib.parse import urlencode, urlparse, parse_qs, unquote

from bs4 import BeautifulSoup

from sources.base import SearchSource, Hit

log = logging.getLogger("recon.tor66")

ONION_HOST = r"(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion"
ONION_RE = re.compile(r"(?:https?://)?" + ONION_HOST + r"[^\s\"'<>]*", re.IGNORECASE)
AD_MARKDOWN_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")


class Tor66Source(SearchSource):
    name = "tor66"
    kind = "search"

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def search(self, term, fetcher, isolation="default", limit=50):
        url = "%s/search?%s" % (self.base_url, urlencode({"q": term}))
        result = fetcher.get_with_retry(url, isolation=isolation)
        return self._parse(result["text"], limit)

    def _parse(self, html, limit):
        soup = BeautifulSoup(html, "lxml")
        hits = []
        seen = set()
        for block in soup.select("div.result-block"):
            hit = self._parse_block(block)
            if hit is None or hit.url in seen:
                continue
            seen.add(hit.url)
            hits.append(hit.finalize())
            if len(hits) >= limit:
                return hits
        if hits:
            return hits

        log.warning("tor66 result-block markup not matched, scanning onion links (markup may differ)")
        for link in soup.find_all("a", href=True):
            onion = self._extract_onion(link["href"])
            if onion is None or onion in seen:
                continue
            seen.add(onion)
            title = self._clean(link.get_text(" ")) or link.get("title") or onion
            hits.append(Hit(source=self.name, url=onion, title=title, snippet="").finalize())
            if len(hits) >= limit:
                break
        return hits

    def _parse_block(self, block):
        link = (block.select_one("div.title a[href]")
                or block.select_one('a[data-category="text-result"][href]'))
        if link is None:
            return None
        onion = self._extract_onion(link["href"])
        if onion is None:
            return None
        title = self._clean(link.get_text(" ")) or link.get("title") or onion
        return Hit(source=self.name, url=onion, title=title, snippet=self._snippet(block))

    def _snippet(self, block):
        desc = block.find("p", id="desc")
        if desc is not None:
            text = self._clean(AD_MARKDOWN_RE.sub("", desc.get_text(" ")))
            if text:
                return text
        crumb = block.select_one("div.sbreadcrub")
        if crumb is not None:
            return self._clean(crumb.get_text(" "))
        return ""

    def _extract_onion(self, href):
        parsed = urlparse(href)
        params = parse_qs(parsed.query)
        for key in ("redirect_url", "url", "u", "r"):
            if key in params and params[key]:
                candidate = unquote(params[key][0])
                if ".onion" in candidate:
                    return self._normalize(candidate)
        if ".onion" in href:
            match = ONION_RE.search(href)
            if match:
                return self._normalize(match.group(0))
        return None

    def _normalize(self, value):
        value = value.strip()
        if not value.lower().startswith(("http://", "https://")):
            value = "http://" + value
        return value

    @staticmethod
    def _clean(text):
        return " ".join((text or "").split())
