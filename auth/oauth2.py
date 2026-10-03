"""
auth/oauth2.py — OAuth 2.0  (Bearer token)
Also handles client-credentials flow (fetches token automatically).
"""
import requests
from auth.base import BaseAuth


class OAuth2Auth(BaseAuth):
    def __init__(
        self,
        token:          str  = "",
        token_url:      str  = "",
        client_id:      str  = "",
        client_secret:  str  = "",
        scope:          str  = "",
        auto_fetch:     bool = False,
    ):
        self._token        = token
        self.token_url     = token_url
        self.client_id     = client_id
        self.client_secret = client_secret
        self.scope         = scope
        self.auto_fetch    = auto_fetch

        if auto_fetch and not token:
            self._token = self._fetch_token()

    def _fetch_token(self) -> str:
        data: dict = {"grant_type": "client_credentials"}
        if self.scope:
            data["scope"] = self.scope
        resp = requests.post(
            self.token_url,
            data=data,
            auth=(self.client_id, self.client_secret),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("access_token", "")

    def inject(self, headers: dict, params: dict) -> tuple[dict, dict]:
        h = dict(headers)
        p = dict(params)
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h, p

    @property
    def token(self) -> str:
        return self._token
