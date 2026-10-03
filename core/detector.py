"""
core/detector.py — Response Classifier
========================================
Takes a RequestResult and assigns it a category + detail dict.
Called by scanner.py after every request.

Categories
----------
  ok            — 2xx, everything fine
  broken        — non-2xx that isn't auth or server error
  auth_fail     — 401 / 403
  server_error  — 5xx
  timeout       — request timed out
  ssl_error     — SSL/TLS issue
  connection_err— couldn't reach the host
  redirect_loop — too many redirects
  sqli_vuln     — SQL injection indicators found  (set by sqli.py)
  info_leak     — sensitive data in response
  empty         — 2xx but empty body (possibly broken)
  unknown       — couldn't classify
"""

import re
from core.runner import RequestResult

# ── Patterns that suggest SQL errors in response body ──────────────────────
_SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"pg_query\(\)",
    r"Warning.*mysqli",
    r"Unclosed quotation mark",
    r"SQLite3::query",
    r"syntax error.*SQL",
    r"Microsoft SQL Server",
    r"SQLSTATE\[",
]

# ── Patterns that suggest info leakage ────────────────────────────────────
_LEAK_PATTERNS = [
    r"stack trace",
    r"at \w+\.\w+\([\w\.]+:\d+\)",   # Java stack trace
    r"Traceback \(most recent call",  # Python traceback
    r"SQLSTATE",
    r"password\s*[:=]\s*['\"]?\w+",
    r"secret\s*[:=]\s*['\"]?\w+",
    r"api[_-]?key\s*[:=]\s*['\"]?\w+",
    r"private[_-]?key",
    r"BEGIN RSA PRIVATE KEY",
]

_SQLI_RE  = [re.compile(p, re.IGNORECASE) for p in _SQLI_ERROR_PATTERNS]
_LEAK_RE  = [re.compile(p, re.IGNORECASE) for p in _LEAK_PATTERNS]


def classify(result: RequestResult) -> RequestResult:
    """
    Mutates result.category and result.detail in-place, then returns it.
    """
    detail: dict = {}

    # ── Connection/timeout failures ────────────────────────────────────────
    if result.timed_out:
        result.category = "timeout"
        detail["message"] = result.error
        result.detail = detail
        return result

    if result.error:
        if "ssl" in result.error.lower():
            result.category = "ssl_error"
        elif "connection" in result.error.lower():
            result.category = "connection_err"
        else:
            result.category = "unknown"
        detail["message"] = result.error
        result.detail = detail
        return result

    # ── Redirect loop ──────────────────────────────────────────────────────
    if len(result.redirects) >= 5:
        result.category = "redirect_loop"
        detail["redirects"] = result.redirects
        result.detail = detail
        return result

    code = result.status_code

    # ── Auth failures ──────────────────────────────────────────────────────
    if code in (401, 403):
        result.category = "auth_fail"
        detail["status_code"] = code
        detail["hint"] = "401 = no auth / expired token  |  403 = wrong permissions"
        result.detail = detail
        return result

    # ── Server errors ──────────────────────────────────────────────────────
    if code and code >= 500:
        result.category = "server_error"
        detail["status_code"] = code
        # Check for info leakage inside error response
        leaks = _find_leaks(result.body)
        if leaks:
            detail["leaks"] = leaks
            result.category = "info_leak"   # escalate
        result.detail = detail
        return result

    # ── Client errors that aren't auth ────────────────────────────────────
    if code and 400 <= code < 500:
        result.category = "broken"
        detail["status_code"] = code
        result.detail = detail
        return result

    # ── 2xx ───────────────────────────────────────────────────────────────
    if code and 200 <= code < 300:
        # Empty body on a GET?
        if not result.body.strip() and result.method == "GET":
            result.category = "empty"
            detail["status_code"] = code
            detail["hint"] = "2xx but response body is empty"
            result.detail = detail
            return result

        # SQLi error strings in a successful response?
        sqli_hits = _find_sqli_errors(result.body)
        if sqli_hits:
            result.category = "sqli_vuln"
            detail["status_code"] = code
            detail["patterns_matched"] = sqli_hits
            result.detail = detail
            return result

        # Info leakage
        leaks = _find_leaks(result.body)
        if leaks:
            result.category = "info_leak"
            detail["status_code"] = code
            detail["leaks"] = leaks
            result.detail = detail
            return result

        result.category = "ok"
        detail["status_code"] = code
        result.detail = detail
        return result

    # ── Fallback ──────────────────────────────────────────────────────────
    result.category = "unknown"
    detail["status_code"] = code
    result.detail = detail
    return result


# ── Pattern helpers ────────────────────────────────────────────────────────

def _find_sqli_errors(body: str) -> list[str]:
    hits = []
    for pattern in _SQLI_RE:
        m = pattern.search(body)
        if m:
            hits.append(m.group(0)[:120])
    return hits


def _find_leaks(body: str) -> list[str]:
    hits = []
    for pattern in _LEAK_RE:
        m = pattern.search(body)
        if m:
            hits.append(m.group(0)[:120])
    return hits


# ── Category metadata (used by reporter) ──────────────────────────────────

CATEGORY_META = {
    "ok":            {"color": "green",   "icon": "✓", "label": "OK"},
    "broken":        {"color": "yellow",  "icon": "✗", "label": "BROKEN"},
    "auth_fail":     {"color": "magenta", "icon": "🔒", "label": "AUTH FAIL"},
    "server_error":  {"color": "red",     "icon": "💥", "label": "SERVER ERR"},
    "timeout":       {"color": "yellow",  "icon": "⏱", "label": "TIMEOUT"},
    "ssl_error":     {"color": "red",     "icon": "🔓", "label": "SSL ERROR"},
    "connection_err":{"color": "red",     "icon": "✗", "label": "NO CONNECTION"},
    "redirect_loop": {"color": "yellow",  "icon": "↻", "label": "REDIRECT LOOP"},
    "sqli_vuln":     {"color": "red",     "icon": "💉", "label": "SQLi VULN"},
    "info_leak":     {"color": "red",     "icon": "⚠", "label": "INFO LEAK"},
    "empty":         {"color": "yellow",  "icon": "∅", "label": "EMPTY"},
    "unknown":       {"color": "dim",     "icon": "?", "label": "UNKNOWN"},
    "pending":       {"color": "dim",     "icon": "…", "label": "PENDING"},
}
