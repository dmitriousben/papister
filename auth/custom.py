"""
auth/custom.py — Custom / Raw Header Injection
Anything that doesn't fit a standard scheme.
Example: Till auth, vendor-specific tokens, API gateways.
"""
from auth.base import BaseAuth


class CustomAuth(BaseAuth):
    def __init__(self, headers: dict | None = None, params: dict | None = None):
        """
        headers: dict of header name → value to inject
        params:  dict of query param name → value to inject
        """
        self._headers = headers or {}
        self._params  = params  or {}

    def inject(self, headers: dict, params: dict) -> tuple[dict, dict]:
        h = dict(headers)
        p = dict(params)
        h.update(self._headers)
        p.update(self._params)
        return h, p
