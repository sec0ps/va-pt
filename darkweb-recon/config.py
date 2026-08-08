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
# Purpose: Central configuration for the darkweb recon subsystem. Resolves each setting with database-override, then environment-variable, then default precedence, coerces and bounds values, and exposes derived paths, search-engine endpoints, and the console secret. Settings are grouped live (apply to the next job) or restart (require a process restart).
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
# Location: darkweb-recon/config.py

"""Environment plus database-backed configuration for the darkweb recon service."""

import os
import secrets
import sqlite3

_ROOT = os.path.dirname(os.path.abspath(__file__))

_DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"
_TORCH_DEFAULT = "http://rz6wxogwwbqdadlncnp2q26kbgcbbaqnitzueohj73fzmlx3mt467wqd.onion"
_EXCAVATOR_DEFAULT = "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion"

# Settings that can be overridden from the database via the admin settings page.
# Precedence per value is database override, then environment variable, then default.
SETTINGS = [
    {"name": "fetch_connect_timeout", "env": "FETCH_CONNECT_TIMEOUT", "type": "int",
     "default": 30, "group": "live", "min": 1, "max": 600, "label": "fetch connect timeout (s)"},
    {"name": "fetch_read_timeout", "env": "FETCH_READ_TIMEOUT", "type": "int",
     "default": 60, "group": "live", "min": 1, "max": 600, "label": "fetch read timeout (s)"},
    {"name": "fetch_max_bytes", "env": "FETCH_MAX_BYTES", "type": "int",
     "default": 2 * 1024 * 1024, "group": "live", "min": 65536, "max": 52428800,
     "label": "fetch max bytes"},
    {"name": "fetch_user_agent", "env": "FETCH_USER_AGENT", "type": "str",
     "default": _DEFAULT_UA, "group": "live", "label": "fetch user agent"},
    {"name": "job_tor_wait", "env": "JOB_TOR_WAIT", "type": "int",
     "default": 180, "group": "live", "min": 1, "max": 1200, "label": "job tor wait (s)"},
    {"name": "snippet_max_chars", "env": "SNIPPET_MAX_CHARS", "type": "int",
     "default": 500, "group": "live", "min": 50, "max": 20000, "label": "snippet max chars"},
    {"name": "body_match", "env": "BODY_MATCH", "type": "bool",
     "default": True, "group": "live", "label": "match watch terms against fetched page body"},
    {"name": "body_match_cap", "env": "BODY_MATCH_CAP", "type": "int",
     "default": 25, "group": "live", "min": 0, "max": 500, "label": "max result pages fetched per job for body matching"},
    {"name": "body_match_delay", "env": "BODY_MATCH_DELAY", "type": "int",
     "default": 2, "group": "live", "min": 0, "max": 60, "label": "seconds between body-match fetches"},
    {"name": "match_value_max_chars", "env": "MATCH_VALUE_MAX_CHARS", "type": "int",
     "default": 200, "group": "live", "min": 20, "max": 2000, "label": "match value max chars"},
    {"name": "match_per_term_cap", "env": "MATCH_PER_TERM_CAP", "type": "int",
     "default": 25, "group": "live", "min": 1, "max": 1000, "label": "match per term cap"},
    {"name": "credential_mask", "env": "CREDENTIAL_MASK", "type": "bool",
     "default": True, "group": "live", "label": "mask credentials and cards"},
    {"name": "analyze_max_pages", "env": "ANALYZE_MAX_PAGES", "type": "int",
     "default": 15, "group": "live", "min": 1, "max": 200, "label": "analyze max pages"},
    {"name": "analyze_max_links_per_page", "env": "ANALYZE_MAX_LINKS_PER_PAGE", "type": "int",
     "default": 200, "group": "live", "min": 1, "max": 2000, "label": "analyze max links per page"},
    {"name": "analyze_page_text_cap", "env": "ANALYZE_PAGE_TEXT_CAP", "type": "int",
     "default": 20000, "group": "live", "min": 500, "max": 500000, "label": "analyze page text cap"},
    {"name": "worker_pool_size", "env": "WORKER_POOL_SIZE", "type": "int",
     "default": 4, "group": "restart", "min": 1, "max": 32, "label": "worker pool size"},
    {"name": "tor_socks_port", "env": "TOR_SOCKS_PORT", "type": "int",
     "default": 9050, "group": "restart", "min": 1, "max": 65535, "label": "tor socks port"},
    {"name": "tor_control_port", "env": "TOR_CONTROL_PORT", "type": "int",
     "default": 9051, "group": "restart", "min": 1, "max": 65535, "label": "tor control port"},
    {"name": "tor_bootstrap_timeout", "env": "TOR_BOOTSTRAP_TIMEOUT", "type": "int",
     "default": 180, "group": "restart", "min": 30, "max": 1200, "label": "tor bootstrap timeout (s)"},
    {"name": "tor_newnym_guard", "env": "TOR_NEWNYM_GUARD", "type": "int",
     "default": 10, "group": "restart", "min": 1, "max": 120, "label": "tor newnym guard (s)"},
    {"name": "tor_verbose", "env": "TOR_VERBOSE", "type": "bool",
     "default": True, "group": "restart", "label": "tor verbose logging"},
    {"name": "console_bind", "env": "CONSOLE_BIND", "type": "str",
     "default": "0.0.0.0:8080", "group": "restart", "label": "console bind address"},
]


def _coerce(type_, raw):
    if type_ == "int":
        return int(raw)
    if type_ == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    return str(raw)


class Config:
    def __init__(self):
        self.tor_cmd = os.environ.get("TOR_CMD", "tor")
        self.tor_data_dir = os.environ.get("TOR_DATA_DIR", os.path.join(_ROOT, "tordata"))
        self.tor_extra_config = {}
        self.fetch_allowed_content_types = (
            "text/html",
            "text/plain",
            "application/json",
            "application/xhtml+xml",
        )
        self.ahmia_base_url = os.environ.get("AHMIA_BASE_URL", "https://ahmia.fi")
        self.torch_base_url = os.environ.get("TORCH_BASE_URL", _TORCH_DEFAULT)
        self.excavator_base_url = os.environ.get("EXCAVATOR_BASE_URL", _EXCAVATOR_DEFAULT)

        self.data_dir = os.environ.get("DARKWEB_DATA_DIR", os.path.join(_ROOT, "data"))
        self.db_path = os.environ.get("DARKWEB_DB", os.path.join(self.data_dir, "recon.db"))
        self.secret_path = os.path.join(self.data_dir, "secret.key")
        self._console_secret_env = os.environ.get("CONSOLE_SECRET")
        self.admin_user = os.environ.get("CONSOLE_ADMIN_USER")
        self.admin_password = os.environ.get("CONSOLE_ADMIN_PASSWORD")

        self._apply_settings()

    def _load_overrides(self):
        if not os.path.exists(self.db_path):
            return {}
        try:
            conn = sqlite3.connect(self.db_path, timeout=5)
            try:
                rows = conn.execute("SELECT key, value FROM settings").fetchall()
                return {key: value for key, value in rows}
            finally:
                conn.close()
        except Exception:
            return {}

    def _apply_settings(self):
        overrides = self._load_overrides()
        for spec in SETTINGS:
            name = spec["name"]
            if name in overrides:
                raw = overrides[name]
            elif spec["env"] in os.environ and os.environ[spec["env"]] != "":
                raw = os.environ[spec["env"]]
            else:
                raw = spec["default"]
            try:
                value = _coerce(spec["type"], raw)
            except (ValueError, TypeError):
                value = spec["default"]
            setattr(self, name, value)

    def refresh(self):
        self._apply_settings()

    def ensure_dirs(self):
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.tor_data_dir, exist_ok=True)

    def console_secret(self):
        if self._console_secret_env:
            return self._console_secret_env
        try:
            if os.path.exists(self.secret_path):
                with open(self.secret_path, "r") as handle:
                    value = handle.read().strip()
                    if value:
                        return value
            os.makedirs(self.data_dir, exist_ok=True)
            value = secrets.token_hex(32)
            with open(self.secret_path, "w") as handle:
                handle.write(value)
            os.chmod(self.secret_path, 0o600)
            return value
        except OSError:
            return secrets.token_hex(32)
