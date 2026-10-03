"""
security/fuzzer.py — Parameter Fuzzer
=======================================
Throws unexpected values at endpoint params:
  nulls, empty strings, oversized strings, type confusion,
  special chars, negative numbers, unicode bombs.
Reports status code changes and body anomalies.
"""

import urllib.parse
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich import box
from core.runner import Runner

console = Console()

FUZZ_PAYLOADS = [
    ("null",          None),
    ("empty",         ""),
    ("space",         " "),
    ("zero",          "0"),
    ("negative",      "-1"),
    ("float",         "1.99999"),
    ("large_int",     "999999999999"),
    ("bool_true",     "true"),
    ("bool_false",    "false"),
    ("array",         "[]"),
    ("object",        "{}"),
    ("sql_quote",     "'"),
    ("double_quote",  '"'),
    ("null_byte",     "\x00"),
    ("crlf",          "\r\n"),
    ("long_str",      "A" * 512),
    ("very_long",     "B" * 8192),
    ("unicode",       "\u202e\u0000\uffff"),
    ("path_traversal","../../../etc/passwd"),
    ("format_str",    "%s%s%s%n"),
    ("xss_basic",     "<script>alert(1)</script>"),
    ("template",      "{{7*7}}"),
]


@dataclass
class FuzzFinding:
    param:   str
    payload_label: str
    payload_value: str
    status_code:   int | None
    baseline_code: int | None
    body_delta:    int
    note:          str


class Fuzzer:

    def __init__(self, proxy: str | None = None, timeout: int = 15):
        self.runner = Runner(proxy=proxy, verify_ssl=False, timeout=timeout)

    def fuzz_url(self, url: str, method: str = "GET") -> list[FuzzFinding]:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query)) or {"id": "1"}
        base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        console.print(f"\n[yellow]🎯 Fuzzing:[/yellow] {base}  params={list(params.keys())}\n")

        # Baseline
        baseline = self.runner.send(method, base, params=params)
        baseline_len  = len(baseline.body or "")
        baseline_code = baseline.status_code

        findings: list[FuzzFinding] = []

        for param in params:
            console.print(f"  [dim]Param:[/dim] [bold]{param}[/bold]")
            for label, value in FUZZ_PAYLOADS:
                p = dict(params)
                p[param] = value
                r = self.runner.send(method, base, params=p)

                delta = abs(len(r.body or "") - baseline_len)
                code_changed = r.status_code != baseline_code

                if code_changed or delta > 200:
                    note = ""
                    if code_changed:
                        note += f"status {baseline_code}→{r.status_code}  "
                    if delta > 200:
                        note += f"body Δ{delta}b"
                    findings.append(FuzzFinding(
                        param=param, payload_label=label,
                        payload_value=str(value)[:40],
                        status_code=r.status_code,
                        baseline_code=baseline_code,
                        body_delta=delta,
                        note=note.strip(),
                    ))
                    color = "red" if code_changed else "yellow"
                    console.print(f"    [{color}]⚠ {label:<15}[/{color}] {note}")

        return findings

    def print_results(self, findings: list[FuzzFinding]):
        console.print()
        if not findings:
            console.print("[green]✓ No anomalies detected during fuzzing.[/green]")
            return
        console.print(f"[bold yellow]⚠ {len(findings)} anomaly/anomalies detected:[/bold yellow]\n")
        t = Table("Param", "Payload", "Value", "Code Δ", "Body Δ", "Note",
                  box=box.SIMPLE, header_style="bold yellow")
        for f in findings:
            t.add_row(
                f.param, f.payload_label, f.payload_value,
                f"{f.baseline_code}→{f.status_code}" if f.status_code != f.baseline_code else "—",
                f"{f.body_delta}b" if f.body_delta > 0 else "—",
                f.note,
            )
        console.print(t)

    def close(self):
        self.runner.close()
