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
# Purpose: Excavator onion search-engine source, queried over Tor. Discovers the
#          engine's search form from its landing page and submits the term as a
#          GET query, falling back to conventional query paths if no form is
#          present. Parses results defensively into normalized Hit records: it
#          tries result-container markup first, then falls back to scanning every
#          onion-bearing link on the page, so a markup change degrades to reduced
#          recall rather than a hard failure.
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
"""Excavator onion search-engine source queried over Tor.

The engine's exact query interface is discovered at runtime rather than
hardcoded: search() reads the landing page, locates the search form, and submits
the term through the form's own action and field name. If no form is found it
falls back to the conventional ``/search/?q=`` and ``/?q=`` paths. Result parsing
is deliberately defensive -- it prefers structured result containers but degrades
to scanning every onion-bearing anchor on the page, so an upstream markup change
lowers recall instead of raising an exception. Hits carry the onion url, a title,
and a snippet, deduplicated by url.
"""

from __future__ import annotations

import re
import logging
from urllib.parse import urlencode, urlparse, parse_qs, unquote

from bs4 import BeautifulSoup

from sources.base import SearchSource, Hit
from fetch import FetchError

log = logging.getLogger("recon.excavator")

ONION_HOST = r"(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion"
ONION_RE = re.compile(r"(?:https?://)?" + ONION_HOST + r"[^\s\"'<>]*", re.IGNORECASE)

# Result-container selectors tried in order before the generic anchor fallback.
RESULT_SELECTORS = (
    "li.result",
    "div.result",
    "div.result-item",
    "article",
    "div.results a",
)


class ExcavatorSource(SearchSource):
    name = "excavator"
    kind = "search"

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def search(self, term, fetcher, isolation="default", limit=50):
        home = fetcher.get_with_retry(self.base_url + "/", isolation=isolation)
        url = self._build_query_url(home["text"], term)
        result = fetcher.get_with_retry(url, isolation=isolation)
        return self._parse(result["text"], limit)

    def _build_query_url(self, html, term):
        action, fields, query_field = self._read_search_form(html)
        if action is not None:
            fields[query_field] = term
            return "%s?%s" % (self._resolve(action), urlencode(fields))
        # No discoverable form: fall back to conventional query paths.
        return "%s/search/?%s" % (self.base_url, urlencode({"q": term}))

    def _read_search_form(self, html):
        soup = BeautifulSoup(html, "lxml")
        form = (
            soup.find("form", id=re.compile(r"search", re.IGNORECASE))
            or soup.find("form", attrs={"role": "search"})
            or soup.find("form")
        )
        if form is None:
            return None, {}, "q"
        action = form.get("action") or "/search/"
        fields = {}
        query_field = "q"
        for field in form.find_all("input"):
            fname = field.get("name")
            if not fname:
                continue
            itype = (field.get("type") or "").lower()
            if itype in ("submit", "button", "image", "reset"):
                continue
            if itype in ("hidden", "search", "text", ""):
                if itype in ("search", "text", ""):
                    query_field = fname
                else:
                    fields[fname] = field.get("value") or ""
        return action, fields, query_field

    def _resolve(self, action):
        if action.startswith("http://") or action.startswith("https://"):
            return action
        if not action.startswith("/"):
            action = "/" + action
        return self.base_url + action

    def _parse(self, html, limit):
        soup = BeautifulSoup(html, "lxml")
        hits = []
        seen = set()

        for selector in RESULT_SELECTORS:
            nodes = soup.select(selector)
            if not nodes:
                continue
            for node in nodes:
                hit = self._parse_node(node)
                if hit is None or hit.url in seen:
                    continue
                seen.add(hit.url)
                hits.append(hit.finalize())
                if len(hits) >= limit:
                    return hits
            if hits:
                return hits

        # Fallback: no known container matched, scan every onion-bearing anchor.
        log.warning("no known result container matched, scanning onion links (markup may differ)")
        for link in soup.find_all("a", href=True):
            onion = self._extract_onion(link["href"], link)
            if onion is None or onion in seen:
                continue
            seen.add(onion)
            title = link.get_text(strip=True) or onion
            snippet = self._nearby_text(link)
            hits.append(Hit(source=self.name, url=onion, title=title, snippet=snippet).finalize())
            if len(hits) >= limit:
                break
        return hits

    def _parse_node(self, node):
        link = node if node.name == "a" else node.find("a", href=True)
        if link is None or not link.get("href"):
            return None
        onion = self._extract_onion(link["href"], node)
        if onion is None:
            return None
        title = link.get_text(strip=True) or onion
        snippet = ""
        desc = node.find("p") if node.name != "a" else None
        if desc is not None:
            snippet = desc.get_text(" ", strip=True)
        if not snippet:
            snippet = self._nearby_text(link)
        return Hit(source=self.name, url=onion, title=title, snippet=snippet)

    def _nearby_text(self, link):
        parent = link.find_parent(["li", "div", "article", "p"]) or link.parent
        if parent is None:
            return ""
        text = parent.get_text(" ", strip=True)
        title = link.get_text(strip=True)
        if title and text.startswith(title):
            text = text[len(title):].strip()
        return text[:500]

    def _extract_onion(self, href, node):
        # Redirect-wrapped links (?redirect_url=/?url=) as seen on some engines.
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
        # Some engines render the target as visible text (cite / span) not the href.
        cite = node.find("cite") if hasattr(node, "find") else None
        if cite is not None and ".onion" in cite.get_text():
            match = ONION_RE.search(cite.get_text())
            if match:
                return self._normalize(match.group(0))
        return None

    def _normalize(self, value):
        value = value.strip()
        if not value.lower().startswith(("http://", "https://")):
            value = "http://" + value
        return value
