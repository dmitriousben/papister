"""
integrations/__base__.py — Base Integration Class
Every integration inherits from BaseIntegration.
"""
from abc import ABC, abstractmethod
from core.runner import Runner
from core import reporter
from storage import db


class BaseIntegration(ABC):

    SANDBOX_BASE    = ""
    PRODUCTION_BASE = ""
    NAME            = "base"

    def __init__(self, mode: str = "S", auth_profile: str | None = None):
        self.mode         = mode.upper()
        self.auth_profile = auth_profile
        self.base_url     = self.SANDBOX_BASE if self.mode == "S" else self.PRODUCTION_BASE
        self.runner       = Runner(verify_ssl=True, timeout=20)
        self._auth        = self._load_auth()

    def _load_auth(self):
        if not self.auth_profile:
            return None
        profile = db.get_auth_profile(self.auth_profile)
        if not profile:
            reporter.console.print(f"  [yellow]⚠ Auth profile '{self.auth_profile}' not found[/yellow]")
            return None
        from auth.oauth2 import OAuth2Auth
        from auth.oauth1 import OAuth1Auth
        from auth.apikey import APIKeyAuth
        from auth.basic  import BasicAuth
        t = profile["auth_type"]
        c = profile["config"]
        if t == "oauth2":  return OAuth2Auth(**c)
        if t == "oauth1":  return OAuth1Auth(**c)
        if t == "apikey":  return APIKeyAuth(**c)
        if t == "basic":   return BasicAuth(**c)
        return None

    @abstractmethod
    def run(self):
        """Execute the integration test suite."""
        ...

    def _get(self, path: str, **kwargs):
        return self.runner.get(self.base_url + path, auth=self._auth, **kwargs)

    def _post(self, path: str, **kwargs):
        return self.runner.post(self.base_url + path, auth=self._auth, **kwargs)
