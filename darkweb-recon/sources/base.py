"""Base source plugin interfaces and normalized hit record."""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Hit:
    source: str
    url: str
    title: str
    snippet: str
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    content_hash: str = ""

    def finalize(self):
        if not self.content_hash:
            basis = "%s|%s|%s" % (self.source, self.url, self.title)
            self.content_hash = hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()
        return self

    def as_dict(self):
        return {
            "source": self.source,
            "url": self.url,
            "title": self.title,
            "snippet": self.snippet,
            "discovered_at": self.discovered_at,
            "content_hash": self.content_hash,
        }


class BaseSource(ABC):
    name = "base"
    kind = "search"


class SearchSource(BaseSource):
    kind = "search"

    @abstractmethod
    def search(self, term, fetcher, isolation="default", limit=50):
        raise NotImplementedError


class MonitorSource(BaseSource):
    kind = "monitor"

    # Interface placeholder for curated source monitoring. A monitor source crawls a fixed
    # set of known urls on a schedule and returns hits for the match engine. Session and
    # auth injection are deferred until a real monitor source is added. The auth_blob column
    # on the sources table exists to carry that state when it lands.

    @abstractmethod
    def crawl(self, fetcher, isolation="default", auth_blob=None):
        raise NotImplementedError
