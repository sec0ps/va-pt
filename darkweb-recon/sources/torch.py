"""Torch onion search source over Tor via the Ivory Search ajax endpoint."""

import logging
import re

from bs4 import BeautifulSoup

from sources.base import SearchSource, Hit
from fetch import FetchError

log = logging.getLogger("recon.torch")

ONION_HOST = r"(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion"
ONION_URL = r"(?:https?://)?" + ONION_HOST + r"[^\s\"'<>]*"
ONION_RE = re.compile(ONION_URL, re.IGNORECASE)
LINK_RE = re.compile(r"LINK\s*:\s*(" + ONION_URL + r")", re.IGNORECASE)
NONCE_RE = re.compile(r'"ajax_nonce"\s*:\s*"([a-f0-9]+)"', re.IGNORECASE)
AJAXURL_RE = re.compile(r'"ajaxurl"\s*:\s*"([^"]+)"', re.IGNORECASE)


class TorchSource(SearchSource):
    name = "torch"

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def search(self, term, fetcher, isolation="default", limit=50):
        home = fetcher.get_with_retry(self.base_url + "/", isolation=isolation)
        nonce, ajax_url, form_id = self._read_home(home["text"])
        data = {
            "s": term,
            "action": "is_ajax_load_posts",
            "page": "1",
            "security": nonce,
            "id": form_id,
        }
        result = fetcher.post_with_retry(ajax_url, data, isolation=isolation)
        return self._parse(result["text"], limit)

    def _read_home(self, html):
        nonce_match = NONCE_RE.search(html)
        if not nonce_match:
            raise FetchError("torch home page had no ajax nonce, markup may have changed")
        nonce = nonce_match.group(1)
        ajax_match = AJAXURL_RE.search(html)
        if ajax_match:
            ajax_url = ajax_match.group(1).replace("\\/", "/")
        else:
            ajax_url = self.base_url + "/wp-admin/admin-ajax.php"
        return nonce, ajax_url, self._form_id(html)

    def _form_id(self, html):
        soup = BeautifulSoup(html, "lxml")
        form = soup.find("form", attrs={"data-form-id": True})
        if form is not None:
            return str(form.get("data-form-id"))
        form = soup.find("form", class_=re.compile(r"is-form-id-\d+"))
        if form is not None:
            match = re.search(r"is-form-id-(\d+)", " ".join(form.get("class", [])))
            if match:
                return match.group(1)
        return "16"

    def _parse(self, html, limit):
        soup = BeautifulSoup(html, "lxml")
        hits = []
        for node in soup.select("div.is-ajax-search-post")[:limit]:
            title_el = node.select_one(".is-title")
            title = title_el.get_text(strip=True) if title_el else ""
            desc_el = node.select_one(".is-ajax-result-description")
            desc = desc_el.get_text(" ", strip=True) if desc_el else ""
            onion = self._extract_onion(desc, node)
            if not onion:
                continue
            hits.append(Hit(source=self.name, url=onion, title=title, snippet=desc).finalize())
        return hits

    def _extract_onion(self, desc, node):
        link_match = LINK_RE.search(desc)
        if link_match:
            return self._normalize_onion(link_match.group(1))
        any_match = ONION_RE.search(desc)
        if any_match:
            return self._normalize_onion(any_match.group(0))
        link = node.find("a", href=True)
        if link and ".onion" in link["href"]:
            return link["href"]
        return None

    def _normalize_onion(self, value):
        value = value.strip()
        if not value.lower().startswith(("http://", "https://")):
            value = "http://" + value
        return value
