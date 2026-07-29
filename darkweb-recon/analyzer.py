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
