"""Ahmia search-engine source queried over Tor."""

import logging
from urllib.parse import urlencode, urlparse, parse_qs, unquote

from bs4 import BeautifulSoup

from sources.base import SearchSource, Hit
from fetch import FetchError

log = logging.getLogger("recon.ahmia")


class AhmiaSource(SearchSource):
    name = "ahmia"
    kind = "search"

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def search(self, term, fetcher, isolation="default", limit=50):
        home = fetcher.get_with_retry(self.base_url + "/", isolation=isolation)
        action, fields, query_field = self._read_search_form(home["text"])
        fields[query_field] = term
        url = "%s?%s" % (self._resolve(action), urlencode(fields))
        result = fetcher.get_with_retry(url, isolation=isolation)
        return self._parse(result["text"], limit)

    def _read_search_form(self, html):
        soup = BeautifulSoup(html, "lxml")
        form = soup.find("form", id="searchForm") or soup.find("form")
        if form is None:
            raise FetchError("ahmia landing page had no search form, markup may have changed")
        action = form.get("action") or "/search/"
        fields = {}
        query_field = "q"
        for field in form.find_all("input"):
            name = field.get("name")
            if not name:
                continue
            itype = (field.get("type") or "").lower()
            if itype == "submit":
                continue
            if itype == "hidden":
                fields[name] = field.get("value") or ""
            else:
                query_field = name
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
