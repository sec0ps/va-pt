"""Environment-driven configuration for the darkweb recon service."""

import os
import secrets

_ROOT = os.path.dirname(os.path.abspath(__file__))


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
        self.tor_data_dir = os.environ.get("TOR_DATA_DIR", os.path.join(_ROOT, "tordata"))
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
        self.torch_base_url = os.environ.get(
            "TORCH_BASE_URL",
            "http://rz6wxogwwbqdadlncnp2q26kbgcbbaqnitzueohj73fzmlx3mt467wqd.onion",
        )

        self.data_dir = os.environ.get("DARKWEB_DATA_DIR", os.path.join(_ROOT, "data"))
        self.db_path = os.environ.get("DARKWEB_DB", os.path.join(self.data_dir, "recon.db"))
        self.secret_path = os.path.join(self.data_dir, "secret.key")

        self.console_bind = os.environ.get("CONSOLE_BIND", "0.0.0.0:8080")
        self._console_secret_env = os.environ.get("CONSOLE_SECRET")

        self.worker_pool_size = _int("WORKER_POOL_SIZE", 4)
        self.job_tor_wait = _int("JOB_TOR_WAIT", 180)

        self.admin_user = os.environ.get("CONSOLE_ADMIN_USER")
        self.admin_password = os.environ.get("CONSOLE_ADMIN_PASSWORD")

        self.snippet_max_chars = _int("SNIPPET_MAX_CHARS", 500)
        self.match_value_max_chars = _int("MATCH_VALUE_MAX_CHARS", 200)
        self.match_per_term_cap = _int("MATCH_PER_TERM_CAP", 25)
        self.credential_mask = _bool("CREDENTIAL_MASK", True)

        self.analyze_max_pages = _int("ANALYZE_MAX_PAGES", 15)
        self.analyze_max_links_per_page = _int("ANALYZE_MAX_LINKS_PER_PAGE", 200)
        self.analyze_page_text_cap = _int("ANALYZE_PAGE_TEXT_CAP", 20000)

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
