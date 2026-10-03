"""
security/cve.py — CVE Manager
================================
Pulls NVD feeds locally, stores in cve.db.
Provides lookup by tech + version.
"""

import json
import sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich import box

from storage.db import search_cve, get_cve_last_updated, set_cve_last_updated, get_cve_conn

console = Console()


class CVEManager:

    def update(self):
        console.print("[cyan]📥 Updating local CVE database from NVD…[/cyan]")
        try:
            import nvdlib
        except ImportError:
            console.print("[red]nvdlib not installed. Run: pip install nvdlib[/red]")
            return

        try:
            # Pull CVEs modified in the last 120 days
            console.print("  Fetching recent CVEs (this may take a minute)…")
            results = nvdlib.searchCVE(keywordSearch="API", limit=500)
            saved = 0
            with get_cve_conn() as conn:
                for cve in results:
                    try:
                        cve_id    = cve.id
                        desc      = cve.descriptions[0].value if cve.descriptions else ""
                        severity  = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity \
                                    if hasattr(cve, 'metrics') and cve.metrics.cvssMetricV31 \
                                    else "UNKNOWN"
                        score     = cve.metrics.cvssMetricV31[0].cvssData.baseScore \
                                    if hasattr(cve, 'metrics') and cve.metrics.cvssMetricV31 \
                                    else None
                        published = str(cve.published)
                        modified  = str(cve.lastModified)
                        raw       = "{}"

                        conn.execute(
                            """INSERT OR REPLACE INTO cve_entries
                               (cve_id, description, severity, cvss_score, published, modified, affected_cpe, raw)
                               VALUES (?,?,?,?,?,?,?,?)""",
                            (cve_id, desc, severity, score, published, modified, "[]", raw)
                        )
                        saved += 1
                    except Exception:
                        continue

            ts = datetime.utcnow().isoformat()
            set_cve_last_updated(ts)
            console.print(f"  [green]✓ Saved {saved} CVE entries.  Updated: {ts}[/green]")

        except Exception as e:
            console.print(f"  [red]CVE update failed: {e}[/red]")
            console.print("  [dim]Check your network connection. NVD API may require a key for bulk pulls.[/dim]")

    def check(self, tech: str, version: str) -> list[dict]:
        return search_cve(tech, version)

    def print_results(self, results: list[dict], tech: str, version: str):
        if not results:
            console.print(f"[green]✓ No CVEs found for {tech} {version} in local DB.[/green]")
            console.print("[dim]  Run 'papister cve update' to refresh the database.[/dim]")
            return
        console.print(f"\n[bold red]⚠ {len(results)} CVE(s) found for {tech} {version}:[/bold red]\n")
        t = Table("CVE ID", "Severity", "CVSS", "Published", "Description",
                  box=box.ROUNDED, header_style="bold red")
        for r in results:
            sev   = r.get("severity","?")
            color = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"dim"}.get(sev,"white")
            t.add_row(
                f"[bold]{r['cve_id']}[/bold]",
                f"[{color}]{sev}[/{color}]",
                str(r.get("cvss_score","?")),
                (r.get("published","?") or "")[:10],
                (r.get("description","") or "")[:80],
            )
        console.print(t)
