"""Source registry that instantiates enabled sources from database configuration."""

import json
import logging

import db
from sources.ahmia import AhmiaSource

log = logging.getLogger("recon.registry")


class SourceRegistry:
    def __init__(self, config):
        self.config = config

    def _build(self, row):
        try:
            cfg = json.loads(row.get("config_json") or "{}")
        except ValueError:
            cfg = {}
        if row["name"] == "ahmia":
            base_url = cfg.get("base_url") or self.config.ahmia_base_url
            return AhmiaSource(base_url)
        log.warning("no plugin implementation for source %s, skipping", row["name"])
        return None

    def search_sources(self, subset=None):
        rows = db.list_enabled_sources()
        instances = []
        for row in rows:
            if row["kind"] != "search":
                continue
            if subset and row["name"] not in subset:
                continue
            source = self._build(row)
            if source is not None:
                instances.append(source)
        return instances
