"""SOCKS-over-Tor HTTP fetcher with hostile-content safeguards and per-stream circuit isolation."""

import requests

from config import Config


class FetchError(Exception):
    pass


class ContentRejected(FetchError):
    pass


class TorFetcher:
    def __init__(self, tor_controller, config=None):
        self.tor = tor_controller
        self.config = config or Config()
        self._session = requests.Session()

    def _proxies(self, isolation):
        host = "127.0.0.1"
        port = self.config.tor_socks_port
        auth = "%s:%s" % (isolation, isolation)
        url = "socks5h://%s@%s:%d" % (auth, host, port)
        return {"http": url, "https": url}

    def get(self, url, isolation="default"):
        headers = {"User-Agent": self.config.fetch_user_agent}
        timeout = (self.config.fetch_connect_timeout, self.config.fetch_read_timeout)
        try:
            resp = self._session.get(
                url,
                proxies=self._proxies(isolation),
                headers=headers,
                timeout=timeout,
                stream=True,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise FetchError("request failed: %s" % exc)

        try:
            self._check_content_type(resp)
            body = self._read_capped(resp)
        finally:
            resp.close()

        return {
            "url": url,
            "status": resp.status_code,
            "final_url": resp.headers.get("Location", url),
            "text": body,
        }

    def get_with_retry(self, url, isolation="default", retries=2):
        last_exc = None
        for attempt in range(retries + 1):
            tag = isolation if attempt == 0 else "%s-%d" % (isolation, attempt)
            try:
                return self.get(url, isolation=tag)
            except ContentRejected:
                raise
            except FetchError as exc:
                last_exc = exc
                if attempt < retries:
                    self.tor.new_identity()
        raise last_exc

    def _check_content_type(self, resp):
        ctype = resp.headers.get("Content-Type", "")
        base = ctype.split(";", 1)[0].strip().lower()
        if base and base not in self.config.fetch_allowed_content_types:
            raise ContentRejected("rejected content-type: %s" % base)

    def _read_capped(self, resp):
        max_bytes = self.config.fetch_max_bytes
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise ContentRejected("response exceeded %d bytes" % max_bytes)
            chunks.append(chunk)
        raw = b"".join(chunks)
        encoding = resp.encoding or "utf-8"
        try:
            return raw.decode(encoding, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")
