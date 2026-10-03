"""
collections/loader.py — Endpoint Collection Loader
====================================================
Reads endpoints from .txt, .yaml, or .json files
and returns a normalised list of EndpointEntry objects.

Supported formats
-----------------
  .txt   — one URL per line  (GET assumed, no auth, no body)
  .json  — list of endpoint objects  (see schema.py for shape)
  .yaml  — same as json but YAML

EndpointEntry fields
--------------------
  url       : str           (required)
  method    : str           (default GET)
  headers   : dict          (extra headers for this endpoint)
  params    : dict          (query params)
  body      : dict|str|None
  auth_profile : str|None   (name of saved auth profile)
  mode      : str           (S or P — overrides global mode if set)
  tags      : list[str]     (free labels, e.g. ["mpesa", "auth"])
  note      : str           (human note, shown in reports)
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False


# ═══════════════════════════════════════════════════════════════════════════
#  Data model
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EndpointEntry:
    url:           str
    method:        str             = "GET"
    headers:       dict            = field(default_factory=dict)
    params:        dict            = field(default_factory=dict)
    body:          Any             = None
    json_body:     dict | None     = None
    auth_profile:  str | None      = None
    mode:          str | None      = None    # S | P | None (inherits global)
    tags:          list[str]       = field(default_factory=list)
    note:          str             = ""

    def __post_init__(self):
        self.method = self.method.upper()
        if self.mode:
            self.mode = self.mode.upper()


# ═══════════════════════════════════════════════════════════════════════════
#  Loader
# ═══════════════════════════════════════════════════════════════════════════

def load(file_path: str) -> list[EndpointEntry]:
    """
    Auto-detects format from extension and returns list of EndpointEntry.
    Raises FileNotFoundError or ValueError on bad input.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Collection file not found: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".txt":
        return _load_txt(file_path)
    elif ext == ".json":
        return _load_json(file_path)
    elif ext in (".yaml", ".yml"):
        return _load_yaml(file_path)
    else:
        raise ValueError(f"Unsupported collection format: {ext}  (use .txt, .json, .yaml)")


# ── .txt loader ─────────────────────────────────────────────────────────────

def _load_txt(path: str) -> list[EndpointEntry]:
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue   # skip empty lines and comments

            # Optional: "METHOD URL" on same line
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].upper() in \
               {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}:
                method, url = parts[0].upper(), parts[1]
            else:
                method, url = "GET", line

            if not url.startswith(("http://", "https://")):
                print(f"  [!] Line {lineno}: skipping invalid URL → {url}")
                continue

            entries.append(EndpointEntry(url=url, method=method))

    return entries


# ── .json loader ────────────────────────────────────────────────────────────

def _load_json(path: str) -> list[EndpointEntry]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return _parse_list(data, path)


# ── .yaml loader ────────────────────────────────────────────────────────────

def _load_yaml(path: str) -> list[EndpointEntry]:
    if not _YAML_OK:
        raise ImportError("PyYAML not installed. Run: pip install pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return _parse_list(data, path)


# ── common dict→EndpointEntry parser ────────────────────────────────────────

def _parse_list(data: Any, path: str) -> list[EndpointEntry]:
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a top-level list of endpoint objects")

    entries = []
    for i, item in enumerate(data):
        if isinstance(item, str):
            # bare string URL inside a structured file — fine
            if item.startswith(("http://", "https://")):
                entries.append(EndpointEntry(url=item))
            continue

        if not isinstance(item, dict):
            print(f"  [!] Item {i}: skipping non-dict entry")
            continue

        url = item.get("url")
        if not url:
            print(f"  [!] Item {i}: missing 'url' field — skipped")
            continue

        entries.append(EndpointEntry(
            url          = url,
            method       = item.get("method", "GET"),
            headers      = item.get("headers", {}),
            params       = item.get("params", {}),
            body         = item.get("body"),
            json_body    = item.get("json_body") or item.get("json"),
            auth_profile = item.get("auth_profile") or item.get("auth"),
            mode         = item.get("mode"),
            tags         = item.get("tags", []),
            note         = item.get("note", ""),
        ))

    return entries


# ═══════════════════════════════════════════════════════════════════════════
#  Summary helper
# ═══════════════════════════════════════════════════════════════════════════

def summarise(entries: list[EndpointEntry]) -> dict:
    methods = {}
    for e in entries:
        methods[e.method] = methods.get(e.method, 0) + 1
    return {
        "total":   len(entries),
        "methods": methods,
        "with_auth": sum(1 for e in entries if e.auth_profile),
    }
