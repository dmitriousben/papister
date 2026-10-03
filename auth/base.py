"""
auth/base.py — Abstract Auth Interface
Every auth class inherits from BaseAuth and implements inject().
"""
from abc import ABC, abstractmethod


class BaseAuth(ABC):
    @abstractmethod
    def inject(self, headers: dict, params: dict) -> tuple[dict, dict]:
        """
        Receives current headers and params dicts.
        Returns (updated_headers, updated_params).
        Must not mutate the originals — return new dicts.
        """
        ...
