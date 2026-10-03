"""
auth/oauth1.py — OAuth 1.0a  (consumer key + secret)
Handles HMAC-SHA1 and HMAC-SHA256 signing.
Used by: Mpesa Daraja, Twitter v1, some telecom APIs.
"""
import time, uuid, hmac, hashlib, base64, urllib.parse
from auth.base import BaseAuth


class OAuth1Auth(BaseAuth):
    def __init__(
        self,
        consumer_key:    str,
        consumer_secret: str,
        token:           str = "",
        token_secret:    str = "",
        signature_method: str = "HMAC-SHA1",
    ):
        self.consumer_key     = consumer_key
        self.consumer_secret  = consumer_secret
        self.token            = token
        self.token_secret     = token_secret
        self.sig_method       = signature_method

    def inject(self, headers: dict, params: dict) -> tuple[dict, dict]:
        h = dict(headers)
        p = dict(params)

        oauth_params = {
            "oauth_consumer_key":     self.consumer_key,
            "oauth_nonce":            uuid.uuid4().hex,
            "oauth_signature_method": self.sig_method,
            "oauth_timestamp":        str(int(time.time())),
            "oauth_version":          "1.0",
        }
        if self.token:
            oauth_params["oauth_token"] = self.token

        # Build auth header (Authorization: OAuth ...)
        auth_str = "OAuth " + ", ".join(
            f'{k}="{urllib.parse.quote(str(v), safe="")}"'
            for k, v in sorted(oauth_params.items())
        )
        h["Authorization"] = auth_str
        return h, p
