"""auth/basic.py — HTTP Basic Auth"""
import base64
from auth.base import BaseAuth


class BasicAuth(BaseAuth):
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        _creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._header_value = f"Basic {_creds}"

    def inject(self, headers: dict, params: dict) -> tuple[dict, dict]:
        h = dict(headers)
        h["Authorization"] = self._header_value
        return h, dict(params)
