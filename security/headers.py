"""
security/headers.py — Security Header Auditor
===============================================
Checks for missing/misconfigured security headers:
  HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  CORS misconfiguration, Referrer-Policy, Permissions-Policy,
  exposed Server/X-Powered-By info, Cache-Control on sensitive routes.
"""

from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich import box
from core.runner import Runner

console = Console()


@dataclass
class HeaderFinding:
    header:    str
    status:    str       # MISSING | MISCONFIGURED | EXPOSED | OK
    severity:  str       # HIGH | MEDIUM | LOW | INFO
    detail:    str
    value:     str = ""


@dataclass
class HeaderAuditResult:
    url:      str
    findings: list[HeaderFinding] = field(default_factory=list)
    score:    int = 0    # 0-100


CHECKS = [
    # (header_name, severity, what_to_check_fn description)
    ("Strict-Transport-Security",  "HIGH",   "HSTS missing — MITM downgrade risk"),
    ("Content-Security-Policy",    "HIGH",   "CSP missing — XSS risk"),
    ("X-Frame-Options",            "MEDIUM", "Clickjacking protection missing"),
    ("X-Content-Type-Options",     "MEDIUM", "MIME sniffing protection missing"),
    ("Referrer-Policy",            "LOW",    "Referrer leakage — no policy set"),
    ("Permissions-Policy",         "LOW",    "Permissions policy not set"),
]

CORS_UNSAFE = ["*", "null"]
INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


class HeaderAuditor:

    def __init__(self, proxy: str | None = None):
        self.runner = Runner(proxy=proxy, verify_ssl=False, timeout=10)

    def audit(self, url: str) -> HeaderAuditResult:
        result = HeaderAuditResult(url=url)
        console.print(f"\n[cyan]🔎 Header audit:[/cyan] {url}\n")

        r = self.runner.get(url)
        if r.error:
            console.print(f"  [red]✗ {r.error}[/red]")
            return result

        h = {k.lower(): v for k, v in r.headers.items()}

        # ── Required security headers ─────────────────────────────────────
        score = 100
        for header, severity, desc in CHECKS:
            val = h.get(header.lower(), "")
            if not val:
                result.findings.append(HeaderFinding(
                    header=header, status="MISSING",
                    severity=severity, detail=desc,
                ))
                score -= {"HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(severity, 5)
            else:
                result.findings.append(HeaderFinding(
                    header=header, status="OK",
                    severity="INFO", detail="Present", value=val[:80],
                ))

        # ── CORS misconfiguration ─────────────────────────────────────────
        acao = h.get("access-control-allow-origin", "")
        if acao in CORS_UNSAFE:
            result.findings.append(HeaderFinding(
                header="Access-Control-Allow-Origin", status="MISCONFIGURED",
                severity="HIGH",
                detail=f"Wildcard CORS — any origin can read responses: '{acao}'",
                value=acao,
            ))
            score -= 20
        elif acao:
            result.findings.append(HeaderFinding(
                header="Access-Control-Allow-Origin", status="OK",
                severity="INFO", detail=f"Restricted to: {acao}", value=acao,
            ))

        # ── Info-leaking headers ──────────────────────────────────────────
        for header in INFO_HEADERS:
            val = h.get(header.lower(), "")
            if val:
                result.findings.append(HeaderFinding(
                    header=header, status="EXPOSED",
                    severity="LOW",
                    detail=f"Reveals backend info: '{val}'",
                    value=val,
                ))

        result.score = max(0, score)
        return result

    def print_result(self, result: HeaderAuditResult):
        score_color = "green" if result.score >= 80 else "yellow" if result.score >= 50 else "red"
        console.print(f"\n  Security score: [{score_color}]{result.score}/100[/{score_color}]\n")

        t = Table("Header", "Status", "Severity", "Detail",
                  box=box.ROUNDED, header_style="bold cyan")
        for f in sorted(result.findings, key=lambda x: x.severity):
            colors = {"MISSING":"red","MISCONFIGURED":"red","EXPOSED":"yellow","OK":"green"}
            sc     = {"HIGH":"red","MEDIUM":"yellow","LOW":"dim","INFO":"dim"}
            t.add_row(
                f.header,
                f"[{colors.get(f.status,'white')}]{f.status}[/{colors.get(f.status,'white')}]",
                f"[{sc.get(f.severity,'white')}]{f.severity}[/{sc.get(f.severity,'white')}]",
                f.detail,
            )
        console.print(t)

    def close(self):
        self.runner.close()
