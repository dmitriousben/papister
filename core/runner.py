"""
core/runner.py — HTTP Engine
==============================
Every module that sends HTTP requests imports Runner from here.
Nobody else creates a requests.Session directly.

Features
--------
  • Configurable timeout, retries with exponential backoff
  • Auth injection (any auth/* class)
  • Optional proxy routing (core/proxy.py intercept mode)
  • Response timing
  • Consistent return format → RequestResult dataclass
"""

import time
import requests
import urllib3
from dataclasses import dataclass, field
from typing import Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress SSL warnings when verify=False is used intentionally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ═══════════════════════════════════════════════════════════════════════════
#  Result dataclass — every request returns one of these
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RequestResult:
    url:          str
    method:       str
    status_code:  int | None        = None
    response_ms:  float | None      = None
    headers:      dict              = field(default_factory=dict)
    body:         str               = ""
    json_body:    Any               = None
    error:        str | None        = None       # set on exception
    timed_out:    bool              = False
    redirects:    list[str]         = field(default_factory=list)
    request_headers: dict           = field(default_factory=dict)

    # filled in by detector.py later
    category:     str               = "pending"
    detail:       dict              = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300

    @property
    def is_error(self) -> bool:
        return self.error is not None or self.timed_out

    def __repr__(self):
        return f"<RequestResult {self.method} {self.url} → {self.status_code} ({self.response_ms:.0f}ms)>"


# ═══════════════════════════════════════════════════════════════════════════
#  Runner
# ═══════════════════════════════════════════════════════════════════════════

class Runner:
    """
    Usage
    -----
        runner = Runner(timeout=10, retries=2)
        result = runner.send("GET", "https://api.example.com/v1/users")

    With auth
    ---------
        from auth.apikey import APIKeyAuth
        auth = APIKeyAuth(key="abc123", header="X-API-Key")
        result = runner.send("GET", url, auth=auth)
    """

    DEFAULT_HEADERS = {
        "User-Agent": "Papister/0.1.0 (API Security Tester)",
        "Accept": "application/json, text/plain, */*",
    }

    def __init__(
        self,
        timeout:    int   = 15,
        retries:    int   = 2,
        verify_ssl: bool  = True,
        proxy:      str | None = None,    # e.g. "http://127.0.0.1:8080"
        extra_headers: dict | None = None,
    ):
        self.timeout      = timeout
        self.verify_ssl   = verify_ssl
        self.proxy        = proxy
        self.extra_headers = extra_headers or {}

        self._session = self._build_session(retries)

    # ── Session setup ───────────────────────────────────────────────────────
    def _build_session(self, retries: int) -> requests.Session:
        session = requests.Session()

        retry_strategy = Retry(
            total=retries,
            backoff_factor=0.5,             # 0.5s, 1s, 2s …
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://",  adapter)
        session.mount("https://", adapter)

        session.headers.update(self.DEFAULT_HEADERS)
        session.headers.update(self.extra_headers)

        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}

        session.verify = self.verify_ssl
        return session

    # ── Core send ───────────────────────────────────────────────────────────
    def send(
        self,
        method:  str,
        url:     str,
        headers: dict | None       = None,
        params:  dict | None       = None,
        body:    dict | str | None = None,
        auth:    Any               = None,   # any auth/* instance
        json_body: dict | None     = None,
        follow_redirects: bool     = True,
    ) -> RequestResult:

        method = method.upper()
        result = RequestResult(url=url, method=method)

        # Merge headers
        req_headers = {}
        req_headers.update(headers or {})

        # Inject auth
        if auth is not None:
            auth_headers, params = auth.inject(req_headers, params or {})
            req_headers.update(auth_headers)

        result.request_headers = req_headers

        # Decide body kwargs
        kwargs: dict = {
            "headers":          req_headers,
            "params":           params,
            "timeout":          self.timeout,
            "allow_redirects":  follow_redirects,
            "verify":           self.verify_ssl,
        }

        if json_body is not None:
            kwargs["json"] = json_body
        elif isinstance(body, dict):
            kwargs["data"] = body
        elif isinstance(body, str):
            kwargs["data"] = body.encode()

        # Fire
        t0 = time.perf_counter()
        try:
            response = self._session.request(method, url, **kwargs)
            result.response_ms  = (time.perf_counter() - t0) * 1000
            result.status_code  = response.status_code
            result.headers      = dict(response.headers)
            result.redirects    = [r.url for r in response.history]

            # Body — try JSON first
            try:
                result.json_body = response.json()
                result.body      = response.text
            except Exception:
                result.body      = response.text

        except requests.exceptions.Timeout:
            result.response_ms = (time.perf_counter() - t0) * 1000
            result.timed_out   = True
            result.error       = f"Timed out after {self.timeout}s"

        except requests.exceptions.SSLError as e:
            result.error = f"SSL error: {e}"

        except requests.exceptions.ConnectionError as e:
            result.error = f"Connection error: {e}"

        except requests.exceptions.RequestException as e:
            result.error = f"Request error: {e}"

        return result

    # ── Convenience wrappers ────────────────────────────────────────────────
    def get(self, url: str, **kwargs)    -> RequestResult:
        return self.send("GET",    url, **kwargs)

    def post(self, url: str, **kwargs)   -> RequestResult:
        return self.send("POST",   url, **kwargs)

    def put(self, url: str, **kwargs)    -> RequestResult:
        return self.send("PUT",    url, **kwargs)

    def patch(self, url: str, **kwargs)  -> RequestResult:
        return self.send("PATCH",  url, **kwargs)

    def delete(self, url: str, **kwargs) -> RequestResult:
        return self.send("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs)   -> RequestResult:
        return self.send("HEAD",   url, **kwargs)

    def options(self, url: str, **kwargs) -> RequestResult:
        return self.send("OPTIONS", url, **kwargs)

    # ── Multi-send — fires a list of (method, url, kwargs) tuples ──────────
    def send_many(self, requests_list: list[tuple]) -> list[RequestResult]:
        """
        requests_list: list of (method, url) or (method, url, kwargs_dict)
        Returns results in the same order.
        """
        results = []
        for item in requests_list:
            if len(item) == 2:
                method, url = item
                kwargs = {}
            else:
                method, url, kwargs = item
            results.append(self.send(method, url, **kwargs))
        return results

    def close(self):
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ═══════════════════════════════════════════════════════════════════════════
#  Module-level default runner (quick use without instantiating)
# ═══════════════════════════════════════════════════════════════════════════
_default_runner = None

def get_default_runner() -> Runner:
    global _default_runner
    if _default_runner is None:
        _default_runner = Runner()
    return _default_runner
