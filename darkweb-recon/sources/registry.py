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
# Purpose: Source registry that instantiates enabled source plugins from database configuration, mapping each stored source row (ahmia, torch, excavator) to its implementation and filtering by kind and requested subset.
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
# Location: darkweb-recon/sources/registry.py

"""Source registry that instantiates enabled sources from database configuration."""

import json
import logging

import db
from sources.ahmia import AhmiaSource
from sources.torch import TorchSource
from sources.excavator import ExcavatorSource

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
        if row["name"] == "torch":
            base_url = cfg.get("base_url") or self.config.torch_base_url
            return TorchSource(base_url)
        if row["name"] == "excavator":
            base_url = cfg.get("base_url") or self.config.excavator_base_url
            return ExcavatorSource(base_url)
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
