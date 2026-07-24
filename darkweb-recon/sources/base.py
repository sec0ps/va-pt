"""Base source plugin interface and normalized hit record."""

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


class BaseSource(ABC):
    name = "base"
    kind = "search"

    @abstractmethod
    def search(self, term, fetcher, isolation="default", limit=50):
        raise NotImplementedError
