"""
collections/writer.py — Append discovered endpoints to file
"""
import os
import yaml
from datetime import datetime
from papister import DISCOVERED


def append_to_discovered(url: str, method: str = "GET", source: str = "manual"):
    """Append a new endpoint entry to storage/discovered.yaml"""
    entry = {
        "url":      url,
        "method":   method.upper(),
        "source":   source,
        "added_at": datetime.utcnow().isoformat(),
    }
    existing = []
    if os.path.exists(DISCOVERED):
        with open(DISCOVERED, "r") as f:
            try:
                data = yaml.safe_load(f) or []
                existing = data if isinstance(data, list) else []
            except Exception:
                existing = []

    # Deduplicate by URL+method
    for e in existing:
        if e.get("url") == url and e.get("method") == method.upper():
            return  # already there

    existing.append(entry)
    with open(DISCOVERED, "w") as f:
        yaml.dump(existing, f, default_flow_style=False, allow_unicode=True)
