"""Environment-driven configuration for the darkweb recon service."""

import os


def _int(name, default):
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return int(value)


def _bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class Config:
    def __init__(self):
        self.tor_cmd = os.environ.get("TOR_CMD", "tor")
        self.tor_socks_port = _int("TOR_SOCKS_PORT", 9050)
        self.tor_control_port = _int("TOR_CONTROL_PORT", 9051)
        self.tor_data_dir = os.environ.get("TOR_DATA_DIR", "/app/tordata")
        self.tor_bootstrap_timeout = _int("TOR_BOOTSTRAP_TIMEOUT", 180)
        self.tor_newnym_guard = _int("TOR_NEWNYM_GUARD", 10)
        self.tor_verbose = _bool("TOR_VERBOSE", True)
        self.tor_extra_config = {}

        self.fetch_max_bytes = _int("FETCH_MAX_BYTES", 2 * 1024 * 1024)
        self.fetch_connect_timeout = _int("FETCH_CONNECT_TIMEOUT", 30)
        self.fetch_read_timeout = _int("FETCH_READ_TIMEOUT", 60)
        self.fetch_user_agent = os.environ.get(
            "FETCH_USER_AGENT",
            "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
        )
        self.fetch_allowed_content_types = (
            "text/html",
            "text/plain",
            "application/json",
            "application/xhtml+xml",
        )

        self.ahmia_base_url = os.environ.get("AHMIA_BASE_URL", "https://ahmia.fi")
