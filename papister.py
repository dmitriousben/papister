"""
Papister — Local API Security & Testing Toolkit
================================================
Author  : You
Version : 0.1.0
License : MIT

Every module imports VERSION, BANNER and path constants from here.
Nothing else lives in this file.
"""

import sys
import os

# ── Version ────────────────────────────────────────────────────────────────
VERSION  = "1.0.1"
APP_NAME = "Papister"

# ── Paths (always relative to this file's location) ────────────────────────
ROOT_DIR      = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR   = os.path.join(ROOT_DIR, "storage")
REPORTS_DIR   = os.path.join(ROOT_DIR, "reports")
ENDPOINTS_DIR = os.path.join(ROOT_DIR, "endpoints")
CONFIG_FILE   = os.path.join(ROOT_DIR, "config", "settings.yaml")
DOCS_FILE     = os.path.join(ROOT_DIR, "docs", "commands.html")
HISTORY_DB    = os.path.join(STORAGE_DIR, "history.db")
CVE_DB        = os.path.join(STORAGE_DIR, "cve.db")
SECRETS_FILE  = os.path.join(STORAGE_DIR, "secrets.enc")
DISCOVERED    = os.path.join(STORAGE_DIR, "discovered.yaml")

# ── Ensure critical dirs exist on first run ────────────────────────────────
for _dir in [STORAGE_DIR, REPORTS_DIR]:
    os.makedirs(_dir, exist_ok=True)

# ── Banner (uses rich markup — printed by cli.py) ──────────────────────────
BANNER = f"""[bold cyan]
  ██████╗  █████╗ ██████╗ ██╗███████╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝███████║██████╔╝██║███████╗   ██║   █████╗  ██████╔╝
  ██╔═══╝ ██╔══██║██╔═══╝ ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
  ██║     ██║  ██║██║     ██║███████║   ██║   ███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/bold cyan]
[dim]  Local API Security & Testing Toolkit  ·  v{VERSION}[/dim]
[dim]  [bold white]papister --help[/bold white] to list commands  ·  [bold white]papister docs[/bold white] to open reference[/dim]
"""

# ── Python version guard ───────────────────────────────────────────────────
if sys.version_info < (3, 9):
    print(f"[!] Papister requires Python 3.9+  —  you have {sys.version}")
    sys.exit(1)
