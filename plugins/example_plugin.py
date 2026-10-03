"""
plugins/example_plugin.py — Papister Plugin Template
======================================================
Copy this file, rename it, and drop it in the plugins/ folder.
Register your command in cli.py — that's all that's needed.

A plugin is just a Python module that:
  1. Uses core/runner.py to send requests
  2. Uses core/reporter.py to display output
  3. Optionally reads from vault/ for keys
  4. Optionally writes results to storage/db.py

This example plugin checks if an API returns a specific
response header and reports it. Replace the logic with
whatever you need.
"""

from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich import box

from core.runner import Runner, RequestResult
from core.detector import classify
from core import reporter

console = Console()


# ═══════════════════════════════════════════════════════════════════════════
#  Config — change these for your plugin
# ═══════════════════════════════════════════════════════════════════════════

PLUGIN_NAME    = "example"
PLUGIN_VERSION = "0.1.0"
PLUGIN_DESC    = "Example plugin — checks for a specific response header"


# ═══════════════════════════════════════════════════════════════════════════
#  Result dataclass — define what your plugin returns
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ExamplePluginResult:
    url:        str
    found:      bool       = False
    header_val: str        = ""
    status:     int | None = None
    note:       str        = ""


# ═══════════════════════════════════════════════════════════════════════════
#  Plugin class
# ═══════════════════════════════════════════════════════════════════════════

class ExamplePlugin:
    """
    How to use in cli.py:
    ─────────────────────
    @app.command("example")
    def example_cmd(url: str = typer.Argument(...)):
        from plugins.example_plugin import ExamplePlugin
        p = ExamplePlugin()
        result = p.run(url)
        p.print_result(result)
    """

    def __init__(
        self,
        target_header: str       = "X-Request-Id",  # header to look for
        proxy:         str | None = None,
        timeout:       int        = 15,
        auth                      = None,            # any auth/* instance
    ):
        self.target_header = target_header
        self.runner        = Runner(proxy=proxy, timeout=timeout, verify_ssl=False)
        self.auth          = auth

    # ── Main run ────────────────────────────────────────────────────────────

    def run(self, url: str) -> ExamplePluginResult:
        result = ExamplePluginResult(url=url)

        console.print(f"\n[cyan]🔌 {PLUGIN_NAME} plugin:[/cyan] {url}")
        console.print(f"   Looking for header: [bold]{self.target_header}[/bold]\n")

        r = self.runner.get(url, auth=self.auth)
        classify(r)
        reporter.print_result(r)

        result.status = r.status_code

        if r.error:
            result.note = f"Request failed: {r.error}"
            return result

        # ── Your plugin logic goes here ─────────────────────────────────
        header_val = r.headers.get(self.target_header) or \
                     r.headers.get(self.target_header.lower(), "")

        if header_val:
            result.found      = True
            result.header_val = header_val
            result.note       = f"Header present: {self.target_header} = {header_val}"
        else:
            result.found = False
            result.note  = f"Header '{self.target_header}' not found in response"

        return result

    # ── Bulk run against a list of URLs ─────────────────────────────────────

    def run_many(self, urls: list[str]) -> list[ExamplePluginResult]:
        results = []
        for url in urls:
            results.append(self.run(url))
        return results

    # ── Output ──────────────────────────────────────────────────────────────

    def print_result(self, result: ExamplePluginResult):
        console.print()
        if result.found:
            console.print(
                f"  [green]✓ Found:[/green]  "
                f"[bold]{self.target_header}[/bold] = {result.header_val}"
            )
        else:
            console.print(
                f"  [yellow]✗ Not found:[/yellow]  "
                f"{self.target_header} missing from response"
            )
        if result.note:
            console.print(f"  [dim]{result.note}[/dim]")

    def print_many_results(self, results: list[ExamplePluginResult]):
        console.print()
        t = Table(
            "URL", "Found", "Value", "Status",
            box=box.ROUNDED, header_style="bold cyan",
        )
        for r in results:
            found_str = "[green]✓ Yes[/green]" if r.found else "[yellow]✗ No[/yellow]"
            t.add_row(
                r.url[:60],
                found_str,
                r.header_val or "—",
                str(r.status or "—"),
            )
        console.print(t)

    def close(self):
        self.runner.close()


# ═══════════════════════════════════════════════════════════════════════════
#  Quick standalone test — python plugins/example_plugin.py
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "..")

    url    = "https://httpbin.org/get"
    plugin = ExamplePlugin(target_header="Content-Type")
    result = plugin.run(url)
    plugin.print_result(result)
    plugin.close()
