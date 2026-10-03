"""
security/bola.py — BOLA (Broken Object Level Authorization) Scanner
=====================================================================
OWASP API Security Top 10 — #1

What it does
------------
  1. Extracts object IDs from URL path, query params, request body
  2. Mutates those IDs using multiple strategies
  3. Fires requests with the caller's auth token
  4. Compares responses — detects when unauthorized objects are returned
  5. Cross-account mode — tests user_A accessing user_B's objects
  6. Reports findings with confidence level + evidence

Strategies
----------
  sequential   — id±1, id±2, id±5, id±10
  zero_neg     — 0, -1, -99
  admin_ids    — 1, 2, admin, root, 000, test
  type_switch  — "1" → 1 → 01 → 1.0 → 0x01
  uuid_mutate  — swap last UUID segment
  enumerate    — configurable range (default 1-20)
  cross_account— auth_A requests obj owned by auth_B

Confidence scoring
------------------
  HIGH   — 200 returned, body has meaningful data, different from empty baseline
  MEDIUM — 200 returned but body is small / similar to error baseline
  LOW    — status changed in unexpected way (e.g. 403→200 on mutation)
"""

import re
import json
import uuid
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.runner import Runner, RequestResult
from core.detector import classify

console = Console()


# ═══════════════════════════════════════════════════════════════════════════
#  ID extraction
# ═══════════════════════════════════════════════════════════════════════════

# Patterns that look like object IDs in a URL path segment
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE    = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SLUG_RE    = re.compile(r"^[a-zA-Z0-9_-]{4,64}$")

# Query param names that likely carry object IDs
_ID_PARAM_NAMES = {
    "id", "user_id", "account_id", "order_id", "invoice_id",
    "transaction_id", "record_id", "resource_id", "object_id",
    "customer_id", "product_id", "item_id", "doc_id", "file_id",
    "profile_id", "plan_id", "sub_id", "subscription_id",
    "payment_id", "charge_id", "ref", "reference", "uid",
}


@dataclass
class ExtractedID:
    location:  str        # "path" | "query" | "body"
    key:       str        # param name or path position e.g. "seg:3"
    value:     str        # original value
    id_type:   str        # "numeric" | "uuid" | "slug"


def extract_ids(url: str, body: dict | None = None) -> list[ExtractedID]:
    """Pull all candidate object IDs from URL and body."""
    found: list[ExtractedID] = []
    parsed = urllib.parse.urlparse(url)

    # ── Path segments ────────────────────────────────────────────────────
    segments = [s for s in parsed.path.split("/") if s]
    for i, seg in enumerate(segments):
        if _UUID_RE.match(seg):
            found.append(ExtractedID("path", f"seg:{i}", seg, "uuid"))
        elif _NUMERIC_RE.match(seg) and len(seg) <= 12:
            found.append(ExtractedID("path", f"seg:{i}", seg, "numeric"))
        # slugs in path — only if preceded by a resource-name segment
        elif i > 0 and _SLUG_RE.match(seg) and not _NUMERIC_RE.match(segments[i-1]):
            found.append(ExtractedID("path", f"seg:{i}", seg, "slug"))

    # ── Query params ─────────────────────────────────────────────────────
    for key, val in urllib.parse.parse_qsl(parsed.query):
        if key.lower() in _ID_PARAM_NAMES:
            id_type = "uuid" if _UUID_RE.match(val) else \
                      "numeric" if _NUMERIC_RE.match(val) else "slug"
            found.append(ExtractedID("query", key, val, id_type))

    # ── Body params ──────────────────────────────────────────────────────
    if body:
        for key, val in body.items():
            if key.lower() in _ID_PARAM_NAMES and isinstance(val, (str, int)):
                str_val = str(val)
                id_type = "uuid" if _UUID_RE.match(str_val) else \
                          "numeric" if _NUMERIC_RE.match(str_val) else "slug"
                found.append(ExtractedID("body", key, str_val, id_type))

    return found


# ═══════════════════════════════════════════════════════════════════════════
#  ID mutation strategies
# ═══════════════════════════════════════════════════════════════════════════

def mutate_id(original: str, id_type: str, strategy: str,
              enum_range: tuple[int,int] = (1, 20)) -> list[tuple[str, str]]:
    """
    Returns list of (mutated_value, strategy_label) tuples.
    """
    results: list[tuple[str, str]] = []

    if strategy == "sequential" and id_type == "numeric":
        n = int(original)
        for delta in [-10, -5, -2, -1, 1, 2, 5, 10]:
            candidate = n + delta
            if candidate > 0:
                results.append((str(candidate), f"sequential({delta:+d})"))

    elif strategy == "zero_neg":
        for v in ["0", "-1", "-99", "null", "undefined"]:
            results.append((v, f"zero_neg({v})"))

    elif strategy == "admin_ids":
        admins = ["1", "2", "admin", "root", "000", "test",
                  "administrator", "superuser", "system", "default"]
        for a in admins:
            if a != original:
                results.append((a, f"admin_id({a})"))

    elif strategy == "type_switch" and id_type == "numeric":
        n = original
        for v, label in [
            (f"0{n}",  "leading_zero"),
            (f"{n}.0", "float"),
            (f" {n}",  "space_prefix"),
            (f"{n} ",  "space_suffix"),
            (f"[{n}]", "array_wrap"),
        ]:
            results.append((v, f"type({label})"))

    elif strategy == "uuid_mutate" and id_type == "uuid":
        # Swap last segment with a new random UUID segment
        parts = original.split("-")
        if len(parts) == 5:
            new_last = uuid.uuid4().hex[:12]
            mutated  = "-".join(parts[:4] + [new_last])
            results.append((mutated, "uuid_mutate(last_seg)"))
            # Also try all zeros last segment
            zero_last = "-".join(parts[:4] + ["000000000000"])
            results.append((zero_last, "uuid_mutate(zero_seg)"))

    elif strategy == "enumerate":
        start, end = enum_range
        for i in range(start, end + 1):
            if str(i) != original:
                results.append((str(i), f"enum({i})"))

    return results


# ═══════════════════════════════════════════════════════════════════════════
#  URL / param rebuilder
# ═══════════════════════════════════════════════════════════════════════════

def _rebuild_url(original_url: str, extracted: ExtractedID, new_value: str) -> str:
    """Swap one ID in the URL and return the new URL."""
    parsed   = urllib.parse.urlparse(original_url)
    segments = parsed.path.split("/")

    if extracted.location == "path":
        idx = int(extracted.key.split(":")[1])
        non_empty = [s for s in segments if s]
        if idx < len(non_empty):
            non_empty[idx] = new_value
            new_path = "/" + "/".join(non_empty)
            return urllib.parse.urlunparse(parsed._replace(path=new_path))

    elif extracted.location == "query":
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[extracted.key] = new_value
        new_query = urllib.parse.urlencode(params)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    return original_url


def _rebuild_body(body: dict | None, extracted: ExtractedID, new_value: str) -> dict | None:
    if body is None or extracted.location != "body":
        return body
    updated = dict(body)
    original_type = type(body.get(extracted.key, ""))
    try:
        updated[extracted.key] = original_type(new_value)
    except (ValueError, TypeError):
        updated[extracted.key] = new_value
    return updated


# ═══════════════════════════════════════════════════════════════════════════
#  Finding
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BOLAFinding:
    url:             str
    original_id:     str
    mutated_id:      str
    strategy:        str
    location:        str        # path | query | body
    param:           str
    baseline_status: int | None
    result_status:   int | None
    baseline_size:   int
    result_size:     int
    confidence:      str        # HIGH | MEDIUM | LOW
    evidence:        str
    cross_account:   bool = False


# ═══════════════════════════════════════════════════════════════════════════
#  BOLA Scanner
# ═══════════════════════════════════════════════════════════════════════════

class BOLAScanner:

    STRATEGIES = ["sequential", "zero_neg", "admin_ids", "type_switch",
                  "uuid_mutate", "enumerate"]

    def __init__(
        self,
        proxy:       str | None  = None,
        timeout:     int         = 15,
        enum_range:  tuple       = (1, 20),
        strategies:  list | None = None,
        auth        = None,       # primary auth object
        alt_auth    = None,       # secondary auth (cross-account)
    ):
        self.runner     = Runner(proxy=proxy, verify_ssl=False, timeout=timeout)
        self.enum_range = enum_range
        self.strategies = strategies or self.STRATEGIES
        self.auth       = auth
        self.alt_auth   = alt_auth

    # ── Public ──────────────────────────────────────────────────────────────

    def scan_url(
        self,
        url:    str,
        method: str        = "GET",
        body:   dict | None = None,
    ) -> list[BOLAFinding]:

        console.print(f"\n[cyan]🔓 BOLA scan:[/cyan] {method} {url}")

        # ── Baseline ────────────────────────────────────────────────────
        baseline = self.runner.send(method, url, json_body=body, auth=self.auth)
        b_status = baseline.status_code
        b_size   = len(baseline.body or "")

        console.print(
            f"   Baseline → [bold]{b_status}[/bold]  {b_size}b  "
            f"[dim]{baseline.response_ms:.0f}ms[/dim]"
        )

        # ── Extract IDs ─────────────────────────────────────────────────
        ids = extract_ids(url, body)
        if not ids:
            console.print("   [dim]No object IDs detected in this endpoint.[/dim]")
            return []

        console.print(f"   IDs found: {[(e.key, e.value, e.id_type) for e in ids]}\n")

        findings: list[BOLAFinding] = []

        for extracted in ids:
            console.print(
                f"  [dim]Testing ID:[/dim] [bold]{extracted.key}[/bold] = "
                f"[cyan]{extracted.value}[/cyan] ({extracted.id_type})"
            )

            for strategy in self.strategies:
                mutations = mutate_id(
                    extracted.value, extracted.id_type,
                    strategy, self.enum_range,
                )

                for mutated_val, strat_label in mutations:
                    new_url  = _rebuild_url(url, extracted, mutated_val)
                    new_body = _rebuild_body(body, extracted, mutated_val)

                    r = self.runner.send(
                        method, new_url,
                        json_body=new_body,
                        auth=self.auth,
                    )

                    finding = self._evaluate(
                        url=url,
                        original_id=extracted.value,
                        mutated_id=mutated_val,
                        strategy=strat_label,
                        location=extracted.location,
                        param=extracted.key,
                        baseline_status=b_status,
                        baseline_size=b_size,
                        result=r,
                    )

                    if finding:
                        findings.append(finding)
                        color = {"HIGH":"red","MEDIUM":"yellow","LOW":"dim"}.get(
                            finding.confidence,"white"
                        )
                        console.print(
                            f"    [bold {color}]⚠ BOLA [{finding.confidence}][/bold {color}]  "
                            f"id={mutated_val}  {strat_label}  "
                            f"status={r.status_code}  size={len(r.body or '')}b"
                        )

            # ── Cross-account mode ───────────────────────────────────────
            if self.alt_auth:
                findings += self._cross_account_test(
                    url, method, body, extracted, b_status, b_size
                )

        return findings

    def scan_entries(self, entries) -> list[BOLAFinding]:
        findings: list[BOLAFinding] = []
        for entry in entries:
            body = entry.json_body or (entry.body if isinstance(entry.body, dict) else None)
            findings += self.scan_url(url=entry.url, method=entry.method, body=body)
        return findings

    # ── Cross-account ────────────────────────────────────────────────────

    def _cross_account_test(
        self, url, method, body, extracted, b_status, b_size
    ) -> list[BOLAFinding]:
        """
        User B (alt_auth) tries to access the object from the baseline
        which belongs to User A (primary auth).
        """
        findings: list[BOLAFinding] = []
        console.print(f"    [magenta]↔ Cross-account check…[/magenta]")

        r = self.runner.send(method, url, json_body=body, auth=self.alt_auth)
        finding = self._evaluate(
            url=url,
            original_id=extracted.value,
            mutated_id=extracted.value,    # same ID, different auth
            strategy="cross_account",
            location=extracted.location,
            param=extracted.key,
            baseline_status=b_status,
            baseline_size=b_size,
            result=r,
            cross_account=True,
        )
        if finding:
            findings.append(finding)
            console.print(
                f"    [bold red]⚠ CROSS-ACCOUNT BOLA [{finding.confidence}][/bold red]  "
                f"alt-auth got {r.status_code}  size={len(r.body or '')}b"
            )
        return findings

    # ── Evaluation logic ─────────────────────────────────────────────────

    def _evaluate(
        self,
        url, original_id, mutated_id, strategy,
        location, param,
        baseline_status, baseline_size,
        result: RequestResult,
        cross_account: bool = False,
    ) -> BOLAFinding | None:

        r_status = result.status_code
        r_size   = len(result.body or "")
        r_body   = result.body or ""

        # ── Not a BOLA if server errored or timed out ───────────────────
        if result.error or result.timed_out:
            return None

        # ── Not interesting if we just got a proper 404/403 ────────────
        if r_status in (404, 410) and baseline_status == 200:
            return None   # correctly rejected
        if r_status == 403 and baseline_status == 200:
            return None   # correctly rejected

        # ── Interesting conditions ───────────────────────────────────────
        confidence = None
        evidence   = ""

        # Case 1: Got 200 on a mutated ID — potentially unauthorized data
        if r_status == 200 and baseline_status == 200:
            if r_size > 50:                        # non-trivial body
                size_delta = abs(r_size - baseline_size)
                if size_delta < baseline_size * 0.5:
                    # Similar size to baseline = real data returned
                    confidence = "HIGH"
                    evidence   = (
                        f"Got 200 with {r_size}b body on mutated id={mutated_id}. "
                        f"Baseline was {baseline_size}b. "
                        f"Likely returned another user's object."
                    )
                else:
                    confidence = "MEDIUM"
                    evidence   = (
                        f"Got 200 with {r_size}b body (baseline={baseline_size}b). "
                        f"Body size differs — may be partial data or different object."
                    )

        # Case 2: baseline was 403/401, mutation got 200 — auth bypass
        elif r_status == 200 and baseline_status in (401, 403):
            confidence = "HIGH"
            evidence   = (
                f"Baseline returned {baseline_status} but mutated id={mutated_id} "
                f"returned 200 with {r_size}b. Possible auth bypass."
            )

        # Case 3: Got 200 with empty/small body — endpoint exists but may be leaking structure
        elif r_status == 200 and r_size < 50:
            confidence = "LOW"
            evidence   = f"200 with tiny body ({r_size}b) on id={mutated_id}. Endpoint accessible."

        # Case 4: 500 on mutation — object exists but caused server error
        elif r_status == 500:
            confidence = "LOW"
            evidence   = f"Server error 500 on mutated id={mutated_id}. Object may exist."

        # ── Check for data in body that looks like a real object ────────
        if confidence in ("HIGH", "MEDIUM") and r_body:
            # If body has ID-like fields that match the mutated value → confirmed
            if mutated_id in r_body and mutated_id != original_id:
                confidence = "HIGH"
                evidence  += f" | Mutated ID ({mutated_id}) found in response body — object confirmed."

        if confidence is None:
            return None

        return BOLAFinding(
            url=url,
            original_id=original_id,
            mutated_id=mutated_id,
            strategy=strategy,
            location=location,
            param=param,
            baseline_status=baseline_status,
            result_status=r_status,
            baseline_size=baseline_size,
            result_size=r_size,
            confidence=confidence,
            evidence=evidence[:200],
            cross_account=cross_account,
        )

    # ── Output ──────────────────────────────────────────────────────────────

    def print_results(self, findings: list[BOLAFinding]):
        console.print()

        if not findings:
            console.print(Panel(
                "[green]✓ No BOLA vulnerabilities detected.[/green]\n"
                "[dim]All object ID mutations returned expected responses.[/dim]",
                border_style="green",
                box=box.ROUNDED,
            ))
            return

        high   = [f for f in findings if f.confidence == "HIGH"]
        medium = [f for f in findings if f.confidence == "MEDIUM"]
        low    = [f for f in findings if f.confidence == "LOW"]
        cross  = [f for f in findings if f.cross_account]

        console.print(Panel(
            f"[bold red]⚠ BOLA findings: {len(findings)} total[/bold red]\n"
            f"  [red]HIGH:   {len(high)}[/red]    "
            f"[yellow]MEDIUM: {len(medium)}[/yellow]    "
            f"[dim]LOW:    {len(low)}[/dim]    "
            f"[magenta]Cross-account: {len(cross)}[/magenta]",
            border_style="red",
            title="[bold]OWASP API #1 — Broken Object Level Authorization[/bold]",
            box=box.ROUNDED,
        ))

        t = Table(
            "Confidence", "Strategy", "Param", "Original ID",
            "Mutated ID", "Status", "Size Δ", "Cross",
            box=box.ROUNDED,
            header_style="bold red",
            show_lines=True,
        )

        color_map = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}

        for f in findings:
            color  = color_map.get(f.confidence, "white")
            delta  = f.result_size - f.baseline_size
            delta_str = f"{delta:+d}b"

            t.add_row(
                f"[{color}]{f.confidence}[/{color}]",
                f.strategy,
                f"[bold]{f.param}[/bold]",
                f"[dim]{f.original_id[:20]}[/dim]",
                f"[cyan]{f.mutated_id[:20]}[/cyan]",
                f"[{color}]{f.result_status}[/{color}]",
                delta_str,
                "[magenta]✓[/magenta]" if f.cross_account else "",
            )

        console.print(t)
        console.print()

        # Detail per HIGH finding
        if high:
            console.print("[bold red]HIGH confidence details:[/bold red]")
            for f in high:
                console.print(f"\n  [red]↳[/red] {f.url}")
                console.print(f"     Param=[bold]{f.param}[/bold]  "
                              f"original=[dim]{f.original_id}[/dim]  "
                              f"mutated=[cyan]{f.mutated_id}[/cyan]")
                console.print(f"     [dim]{f.evidence}[/dim]")

    def close(self):
        self.runner.close()
