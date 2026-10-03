"""
auth/apikey.py — API Key Auth
Supports:  X-API-Key header  |  query param  |  custom header name
"""
from auth.base import BaseAuth


class APIKeyAuth(BaseAuth):
    def __init__(self, key: str, header: str = "X-API-Key", in_query: bool = False, param_name: str = "api_key"):
        self.key        = key
        self.header     = header
        self.in_query   = in_query
        self.param_name = param_name

    def inject(self, headers: dict, params: dict) -> tuple[dict, dict]:
        h = dict(headers)
        p = dict(params)
        if self.in_query:
            p[self.param_name] = self.key
        else:
            h[self.header] = self.key
        return h, p
