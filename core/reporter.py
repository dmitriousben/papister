"""
core/reporter.py — Output & Report Writer
==========================================
Handles all output to the terminal and writes
report_[timestamp].json + report_[timestamp].html
to the reports/ directory after every scan.

Uses Rich for terminal output — tables, panels, progress.
"""

import json
import os
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from core.runner import RequestResult
from core.detector import CATEGORY_META
from papister import BANNER, VERSION, REPORTS_DIR

console = Console()


# ═══════════════════════════════════════════════════════════════════════════
#  Banner
# ═══════════════════════════════════════════════════════════════════════════

def print_banner():
    console.print(BANNER)


# ═══════════════════════════════════════════════════════════════════════════
#  Single result — inline print during a live scan
# ═══════════════════════════════════════════════════════════════════════════

def print_result(result: RequestResult):
    meta   = CATEGORY_META.get(result.category, CATEGORY_META["unknown"])
    color  = meta["color"]
    icon   = meta["icon"]
    label  = meta["label"]

    code_str  = str(result.status_code) if result.status_code else "—"
    ms_str    = f"{result.response_ms:.0f}ms" if result.response_ms else "—"
    url_short = result.url[:72] + "…" if len(result.url) > 72 else result.url

    console.print(
        f"  [{color}]{icon} {label:<14}[/{color}]"
        f"  [dim]{result.method:<7}[/dim]"
        f"  [bold]{code_str:<5}[/bold]"
        f"  [dim]{ms_str:<8}[/dim]"
        f"  {url_short}"
    )

    # Show detail hints for interesting categories
    if result.category in ("sqli_vuln", "info_leak") and result.detail:
        for item in result.detail.get("patterns_matched", []) + result.detail.get("leaks", []):
            console.print(f"    [red dim]↳ {item}[/red dim]")

    if result.category == "auth_fail" and result.detail.get("hint"):
        console.print(f"    [dim]↳ {result.detail['hint']}[/dim]")


# ═══════════════════════════════════════════════════════════════════════════
#  Summary table — printed at end of scan
# ═══════════════════════════════════════════════════════════════════════════

def print_summary(results: list[RequestResult], run_id: int | None = None, mode: str = "S"):
    counts: dict[str, int] = {}
    for r in results:
        counts[r.category] = counts.get(r.category, 0) + 1

    table = Table(
        title=f"Papister Scan Summary  [dim](mode={'SANDBOX' if mode=='S' else 'PRODUCTION'}, run #{run_id})[/dim]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    table.add_column("Category",    style="bold", width=18)
    table.add_column("Count",       justify="right", width=8)
    table.add_column("Status",      width=14)

    order = ["ok","broken","auth_fail","server_error","timeout",
             "ssl_error","connection_err","redirect_loop","sqli_vuln","info_leak","empty","unknown"]

    for cat in order:
        if cat not in counts:
            continue
        meta = CATEGORY_META.get(cat, CATEGORY_META["unknown"])
        table.add_row(
            f"[{meta['color']}]{meta['icon']}  {meta['label']}[/{meta['color']}]",
            f"[bold]{counts[cat]}[/bold]",
            "⚠ Review" if cat not in ("ok", "pending") else "[green]Clean[/green]",
        )

    console.print()
    console.print(table)
    console.print(f"  [dim]Total endpoints tested: {len(results)}[/dim]")
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#  Full report — JSON + HTML written to reports/
# ═══════════════════════════════════════════════════════════════════════════

def write_reports(results: list[RequestResult], meta: dict | None = None) -> tuple[str, str]:
    """
    Writes both reports. Returns (json_path, html_path).
    meta: optional dict with run info (run_id, mode, source_file, command)
    """
    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(REPORTS_DIR, f"report_{ts}.json")
    html_path = os.path.join(REPORTS_DIR, f"report_{ts}.html")

    payload = _build_payload(results, meta or {})

    # JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)

    # HTML
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_build_html(payload, ts))

    console.print(f"  [green]📄 JSON report →[/green] {json_path}")
    console.print(f"  [green]🌐 HTML report →[/green] {html_path}")

    return json_path, html_path


def _build_payload(results: list[RequestResult], meta: dict) -> dict:
    return {
        "papister_version": VERSION,
        "generated_at":     datetime.utcnow().isoformat(),
        "meta":             meta,
        "summary": {
            "total":    len(results),
            "by_category": _count_by(results, "category"),
        },
        "results": [
            {
                "url":         r.url,
                "method":      r.method,
                "status_code": r.status_code,
                "response_ms": round(r.response_ms, 2) if r.response_ms else None,
                "category":    r.category,
                "detail":      r.detail,
                "redirects":   r.redirects,
                "error":       r.error,
            }
            for r in results
        ],
    }


def _count_by(results: list, attr: str) -> dict:
    counts: dict = {}
    for r in results:
        v = getattr(r, attr, "unknown")
        counts[v] = counts.get(v, 0) + 1
    return counts


def _build_html(payload: dict, ts: str) -> str:
    rows_html = ""
    for r in payload["results"]:
        meta    = CATEGORY_META.get(r["category"], CATEGORY_META["unknown"])
        color   = {"green":"#22c55e","red":"#ef4444","yellow":"#eab308",
                   "magenta":"#d946ef","dim":"#6b7280"}.get(meta["color"], "#6b7280")
        badge   = f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{meta["icon"]} {meta["label"]}</span>'
        code    = r["status_code"] or "—"
        ms      = f'{r["response_ms"]}ms' if r["response_ms"] else "—"
        detail  = json.dumps(r["detail"], indent=2) if r["detail"] else ""
        detail_html = f'<pre style="font-size:11px;color:#94a3b8;margin:4px 0 0 0">{detail}</pre>' if detail else ""

        rows_html += f"""
        <tr>
          <td style="padding:8px 12px">{badge}</td>
          <td style="padding:8px 12px;font-weight:bold;color:#94a3b8">{r['method']}</td>
          <td style="padding:8px 12px;font-family:monospace;font-size:12px;color:#cbd5e1;word-break:break-all">
            {r['url']}{detail_html}
          </td>
          <td style="padding:8px 12px;text-align:center">{code}</td>
          <td style="padding:8px 12px;text-align:right;color:#94a3b8">{ms}</td>
        </tr>"""

    summary_chips = ""
    for cat, count in payload["summary"]["by_category"].items():
        m = CATEGORY_META.get(cat, CATEGORY_META["unknown"])
        c = {"green":"#22c55e","red":"#ef4444","yellow":"#eab308",
             "magenta":"#d946ef","dim":"#6b7280"}.get(m["color"],"#6b7280")
        summary_chips += f'<span style="background:{c}22;color:{c};border:1px solid {c}55;padding:4px 12px;border-radius:20px;font-size:13px;margin:4px">{m["icon"]} {m["label"]}: <b>{count}</b></span>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Papister Report — {ts}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; padding: 32px; }}
  h1 {{ font-size: 28px; color: #38bdf8; margin-bottom: 4px; }}
  .meta {{ color: #64748b; font-size: 13px; margin-bottom: 24px; }}
  .summary {{ margin-bottom: 28px; display: flex; flex-wrap: wrap; gap: 6px; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; }}
  thead {{ background: #0f172a; }}
  th {{ padding: 10px 12px; text-align: left; font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .05em; }}
  tr:hover {{ background: #162032; }}
  tr + tr {{ border-top: 1px solid #1e293b; }}
  td {{ vertical-align: top; }}
</style>
</head>
<body>
<h1>🔎 Papister Report</h1>
<p class="meta">
  Generated: {payload['generated_at']} &nbsp;|&nbsp;
  Version: {payload['papister_version']} &nbsp;|&nbsp;
  Total: {payload['summary']['total']} endpoints
</p>
<div class="summary">{summary_chips}</div>
<table>
  <thead>
    <tr>
      <th>Status</th><th>Method</th><th>Endpoint</th><th>Code</th><th>Time</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>
</body>
</html>"""
