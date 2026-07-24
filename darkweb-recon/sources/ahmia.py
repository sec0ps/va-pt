"""Ahmia search-engine source queried over Tor."""

import logging
from urllib.parse import urlencode, urlparse, parse_qs, unquote

from bs4 import BeautifulSoup

from sources.base import BaseSource, Hit

log = logging.getLogger("recon.ahmia")


class AhmiaSource(BaseSource):
    name = "ahmia"
    kind = "search"

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def search(self, term, fetcher, isolation="default", limit=50):
        query = urlencode({"q": term})
        url = "%s/search/?%s" % (self.base_url, query)
        result = fetcher.get_with_retry(url, isolation=isolation)
        return self._parse(result["text"], limit)

    def _parse(self, html, limit):
        soup = BeautifulSoup(html, "lxml")
        hits = []
        results = soup.select("li.result")
        if not results:
            log.warning("no li.result nodes found, ahmia markup may have changed")
        for node in results:
            if len(hits) >= limit:
                break
            hit = self._parse_node(node)
            if hit is not None:
                hits.append(hit.finalize())
        return hits

    def _parse_node(self, node):
        link = node.find("a", href=True)
        if link is None:
            return None
        onion = self._extract_onion(link["href"], node)
        if onion is None:
            return None
        title = link.get_text(strip=True) or onion
        snippet = ""
        desc = node.find("p")
        if desc is not None:
            snippet = desc.get_text(" ", strip=True)
        return Hit(source=self.name, url=onion, title=title, snippet=snippet)

    def _extract_onion(self, href, node):
        cite = node.find("cite")
        if cite is not None:
            text = cite.get_text(strip=True)
            if ".onion" in text:
                return self._normalize(text)
        parsed = urlparse(href)
        params = parse_qs(parsed.query)
        for key in ("redirect_url", "url"):
            if key in params and params[key]:
                candidate = unquote(params[key][0])
                if ".onion" in candidate:
                    return self._normalize(candidate)
        if ".onion" in href:
            return self._normalize(href)
        return None

    def _normalize(self, value):
        value = value.strip()
        if not value.startswith("http://") and not value.startswith("https://"):
            value = "http://" + value
        return value
