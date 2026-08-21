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
# Purpose: onion.live "Deep Search" onion search-engine source, queried over Tor.
#          Submits the term as a direct GET to result.php with the engine's own
#          onion host echoed back in the hidden url field the search form expects,
#          so no landing-page fetch or session cookie is needed. Results are a flat
#          run of sibling elements rather than per-result containers, so parsing
#          anchors on each a.title, reads the onion from its href, and walks
#          forward siblings to that result's div.description -- healing the nested
#          highlight tags the engine wraps matched terms in. Degrades to scanning
#          onion-bearing anchors if the result markup changes.
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
# Location: darkweb-recon/sources/onionlive.py

"""onion.live "Deep Search" onion search-engine source queried over Tor.

The engine serves results from a plain GET on ``result.php?search=<term>&url=<host>``
where the hidden ``url`` field the form carries is the engine's own onion host;
it is derived from the base url, so no landing-page fetch and no session cookie
are required. Results are not wrapped in per-result containers -- they are a flat
sequence of sibling nodes inside one cell (``a.link``, ``a.title``,
``div.description``, ``div.date``, repeating). Parsing therefore anchors on each
``a.title`` (one per result), takes the onion from its href, and walks forward
siblings to that result's ``div.description``, stopping at the next result's
boundary. The engine wraps matched terms in nested inline tags that can split a
word, so title/snippet text is extracted with those tags unwrapped first. If the
result markup ever changes, parsing degrades to scanning onion-bearing anchors so
recall drops rather than raising. Hits are deduplicated by url.
"""

from __future__ import annotations

import re
import logging
from urllib.parse import urlencode, urlparse, parse_qs, unquote

from bs4 import BeautifulSoup

from sources.base import SearchSource, Hit

log = logging.getLogger("recon.onionlive")

ONION_HOST = r"(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion"
ONION_RE = re.compile(r"(?:https?://)?" + ONION_HOST + r"[^\s\"'<>]*", re.IGNORECASE)


class OnionLiveSource(SearchSource):
    name = "onionlive"
    kind = "search"

    INLINE_TAGS = ("b", "strong", "em", "i", "mark", "u", "span", "font", "small")

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def search(self, term, fetcher, isolation="default", limit=50):
        host = urlparse(self.base_url).hostname or self.base_url
        url = "%s/result.php?%s" % (self.base_url, urlencode({"search": term, "url": host}))
        result = fetcher.get_with_retry(url, isolation=isolation)
        return self._parse(result["text"], limit)

    def _parse(self, html, limit):
        soup = BeautifulSoup(html, "lxml")
        hits = []
        seen = set()
        for title_a in soup.select("a.title[href]"):
            onion = self._extract_onion(title_a.get("href", ""))
            if onion is None or onion in seen:
                continue
            seen.add(onion)
            hits.append(Hit(source=self.name, url=onion,
                            title=self._text(title_a) or onion,
                            snippet=self._snippet_for(title_a)).finalize())
            if len(hits) >= limit:
                return hits
        if hits:
            return hits

        log.warning("onionlive result markup not matched, scanning onion links (markup may differ)")
        for link in soup.find_all("a", href=True):
            onion = self._extract_onion(link["href"])
            if onion is None or onion in seen:
                continue
            seen.add(onion)
            hits.append(Hit(source=self.name, url=onion,
                            title=self._text(link) or onion, snippet="").finalize())
            if len(hits) >= limit:
                break
        return hits

    def _snippet_for(self, title_a):
        node = title_a.next_sibling
        while node is not None:
            name = getattr(node, "name", None)
            if name:
                classes = node.get("class") or []
                if name == "a" and ("title" in classes or "link" in classes):
                    break
                if name == "div" and "description" in classes:
                    return self._text(node)
            node = node.next_sibling
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

    def _text(self, node):
        if node is None:
            return ""
        frag = BeautifulSoup(str(node), "lxml")
        for tag in frag.find_all(self.INLINE_TAGS):
            tag.unwrap()
        frag = BeautifulSoup(str(frag), "lxml")
        return self._clean(frag.get_text(" "))

    @staticmethod
    def _clean(text):
        return " ".join((text or "").split())
