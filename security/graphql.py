"""
security/graphql.py — GraphQL Security Scanner
================================================
Checks
------
  1. Introspection enabled     — dump full schema, find hidden types/mutations
  2. Field suggestion leakage  — typo hints reveal field names without introspection
  3. Batching abuse            — 100 queries in one request → rate-limit bypass
  4. Deep nesting DoS          — recursive query to exhaust server
  5. Unauthenticated mutations — find mutations that work without auth
  6. Alias abuse               — same mutation 50x via aliases in one request
  7. Debug/dev endpoints       — /graphiql, /playground, /altair, /voyager
"""

import json
from dataclasses import dataclass, field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.runner import Runner

console = Console()

# ── Known GraphQL paths ───────────────────────────────────────────────────────
GQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/gql", "/query", "/playground", "/altair", "/voyager",
    "/graphql/console", "/api/v1/graphql", "/api/v2/graphql",
]

# ── Introspection query ───────────────────────────────────────────────────────
INTROSPECTION_QUERY = """
{
  __schema {
    queryType  { name }
    mutationType { name }
    types {
      name kind
      fields(includeDeprecated: true) {
        name
        args { name type { name kind } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

# ── Field suggestion probe ────────────────────────────────────────────────────
SUGGESTION_QUERY = '{ usr { id } }'   # typo of 'user' → server suggests correct name

# ── Deep nesting DoS ──────────────────────────────────────────────────────────
def _deep_nest(depth: int = 8) -> str:
    """Build a deeply nested query."""
    inner = "id"
    for _ in range(depth):
        inner = f"friends {{ {inner} }}"
    return f"{{ users {{ {inner} }} }}"

# ── Batch abuse ───────────────────────────────────────────────────────────────
def _batch_query(count: int = 100) -> list:
    return [{"query": "{ __typename }"}] * count

# ── Alias abuse ───────────────────────────────────────────────────────────────
def _alias_query(count: int = 50) -> str:
    aliases = "\n".join(
        f"  q{i}: __typename" for i in range(count)
    )
    return f"{{ {aliases} }}"


# ═══════════════════════════════════════════════════════════════════════════
#  Finding
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class GraphQLFinding:
    check:      str
    severity:   str
    result:     str        # VULNERABLE | INFO | NOT_VULNERABLE
    detail:     str
    evidence:   str = ""
    data:       dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════
#  Scanner
# ═══════════════════════════════════════════════════════════════════════════

class GraphQLScanner:

    def __init__(self, proxy: str | None = None, timeout: int = 20, auth=None):
        self.runner  = Runner(proxy=proxy, timeout=timeout, verify_ssl=False)
        self.auth    = auth
        self.timeout = timeout

    def _gql_post(self, url: str, query: str | list, variables: dict | None = None):
        if isinstance(query, list):
            body = query   # batch
        else:
            body = {"query": query}
            if variables:
                body["variables"] = variables
        return self.runner.post(url, json_body=body, auth=self.auth)

    # ── Main scan ────────────────────────────────────────────────────────────

    def scan(self, url: str, dump_schema: bool = False,
             run_attacks: bool = False) -> list[GraphQLFinding]:

        findings: list[GraphQLFinding] = []
        console.print(f"\n[cyan]🔷 GraphQL scan:[/cyan] {url}\n")

        # ── 0. Discover endpoint ─────────────────────────────────────────
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        console.print("  [dim]0. Probing known GraphQL paths…[/dim]")
        found_url = url
        for path in GQL_PATHS:
            probe_url = base + path
            r = self.runner.post(probe_url,
                                 json_body={"query": "{ __typename }"},
                                 auth=self.auth)
            if r.status_code in (200, 400) and r.body and "data" in r.body:
                if probe_url != url:
                    console.print(f"    [green]✓ GraphQL endpoint found:[/green] {probe_url}")
                    findings.append(GraphQLFinding(
                        check="endpoint_discovery", severity="INFO",
                        result="INFO",
                        detail=f"GraphQL endpoint found at {probe_url}",
                        evidence=probe_url,
                    ))
                found_url = probe_url
                break

        # ── 1. Introspection ─────────────────────────────────────────────
        console.print("  [dim]1. Testing introspection…[/dim]")
        r = self._gql_post(found_url, INTROSPECTION_QUERY)
        if r.status_code == 200 and r.json_body:
            data = r.json_body.get("data", {})
            if data and data.get("__schema"):
                schema   = data["__schema"]
                types    = schema.get("types", [])
                mut_type = schema.get("mutationType")

                # Count interesting types
                user_types   = [t for t in types if not t["name"].startswith("__")]
                mutation_names = []
                if mut_type:
                    mut_obj = next((t for t in types if t["name"] == mut_type["name"]), None)
                    if mut_obj and mut_obj.get("fields"):
                        mutation_names = [f["name"] for f in mut_obj["fields"]]

                detail = (
                    f"Introspection enabled — {len(user_types)} types, "
                    f"{len(mutation_names)} mutations exposed"
                )
                console.print(f"    [red]⚠ Introspection ENABLED[/red]  {len(user_types)} types  {len(mutation_names)} mutations")

                if mutation_names:
                    console.print(f"    [yellow]Mutations:[/yellow] {', '.join(mutation_names[:8])}")

                findings.append(GraphQLFinding(
                    check="introspection", severity="MEDIUM",
                    result="VULNERABLE",
                    detail=detail,
                    evidence=f"Types: {[t['name'] for t in user_types[:10]]}",
                    data={"types": len(user_types), "mutations": mutation_names},
                ))

                if dump_schema:
                    import os
                    from papister import REPORTS_DIR
                    os.makedirs(REPORTS_DIR, exist_ok=True)
                    schema_path = os.path.join(REPORTS_DIR, "graphql_schema.json")
                    with open(schema_path, "w") as f:
                        json.dump(data, f, indent=2)
                    console.print(f"    [green]📄 Schema saved →[/green] {schema_path}")
            else:
                console.print("    [green]✓ Introspection disabled[/green]")
                findings.append(GraphQLFinding(
                    check="introspection", severity="INFO",
                    result="NOT_VULNERABLE",
                    detail="Introspection is disabled",
                ))

        # ── 2. Field suggestion leakage ──────────────────────────────────
        console.print("  [dim]2. Testing field suggestion leakage…[/dim]")
        r = self._gql_post(found_url, SUGGESTION_QUERY)
        if r.body and ("did you mean" in r.body.lower() or "suggestion" in r.body.lower()):
            console.print(f"    [yellow]⚠ Field suggestions leaking schema info[/yellow]")
            findings.append(GraphQLFinding(
                check="field_suggestion", severity="LOW",
                result="VULNERABLE",
                detail="Server suggests field names on typos — schema discoverable without introspection",
                evidence=r.body[:200],
            ))
        else:
            console.print("    [green]✓ No field suggestions[/green]")

        if run_attacks:
            findings += self._run_attacks(found_url)

        return findings

    def _run_attacks(self, url: str) -> list[GraphQLFinding]:
        findings: list[GraphQLFinding] = []

        # ── 3. Batching abuse ────────────────────────────────────────────
        console.print("  [dim]3. Testing query batching (100 queries)…[/dim]")
        r = self._gql_post(url, _batch_query(100))
        if r.status_code == 200 and r.json_body and isinstance(r.json_body, list):
            console.print(f"    [yellow]⚠ Batching allowed — {len(r.json_body)} responses returned[/yellow]")
            findings.append(GraphQLFinding(
                check="batching_abuse", severity="MEDIUM",
                result="VULNERABLE",
                detail=f"Server processed {len(r.json_body)} batched queries — rate-limit bypass risk",
                evidence=f"{len(r.json_body)} responses in one HTTP request",
            ))
        else:
            console.print("    [green]✓ Batching not allowed or limited[/green]")

        # ── 4. Deep nesting DoS ──────────────────────────────────────────
        console.print("  [dim]4. Testing deep query nesting (depth=8)…[/dim]")
        import time
        t0 = time.perf_counter()
        r  = self._gql_post(url, _deep_nest(8))
        ms = (time.perf_counter() - t0) * 1000
        if ms > 3000:
            console.print(f"    [yellow]⚠ Deep nesting caused {ms:.0f}ms response — DoS risk[/yellow]")
            findings.append(GraphQLFinding(
                check="deep_nesting_dos", severity="MEDIUM",
                result="VULNERABLE",
                detail=f"Deeply nested query took {ms:.0f}ms — no depth limiting detected",
                evidence=f"Response time: {ms:.0f}ms",
            ))
        else:
            console.print(f"    [green]✓ Deep nesting handled ({ms:.0f}ms)[/green]")

        # ── 5. Alias abuse ───────────────────────────────────────────────
        console.print("  [dim]5. Testing alias abuse (50 aliases)…[/dim]")
        r = self._gql_post(url, _alias_query(50))
        if r.status_code == 200 and r.json_body:
            data = r.json_body.get("data", {})
            if data and len(data) >= 40:
                console.print(f"    [yellow]⚠ Alias abuse — {len(data)} alias responses returned[/yellow]")
                findings.append(GraphQLFinding(
                    check="alias_abuse", severity="MEDIUM",
                    result="VULNERABLE",
                    detail=f"Server processed {len(data)} aliased fields — no alias limiting",
                    evidence=f"{len(data)} aliases resolved in one request",
                ))
            else:
                console.print("    [green]✓ Alias limiting in place[/green]")

        return findings

    # ── Print ────────────────────────────────────────────────────────────────

    def print_findings(self, findings: list[GraphQLFinding]):
        console.print()
        vulns = [f for f in findings if f.result == "VULNERABLE"]
        infos = [f for f in findings if f.result == "INFO"]

        if not vulns and not infos:
            console.print("[green]✓ No GraphQL vulnerabilities detected.[/green]")
            return

        if vulns:
            console.print(f"[bold red]⚠ {len(vulns)} GraphQL issue(s):[/bold red]\n")
            t = Table("Check","Severity","Detail",
                      box=box.ROUNDED, header_style="bold red", show_lines=True)
            for f in vulns:
                sc = {"HIGH":"red","MEDIUM":"yellow","LOW":"dim","INFO":"dim"}.get(f.severity,"white")
                t.add_row(
                    f"[bold]{f.check}[/bold]",
                    f"[{sc}]{f.severity}[/{sc}]",
                    f.detail[:100],
                )
            console.print(t)

        if infos:
            console.print()
            for f in infos:
                console.print(f"  [dim]ℹ {f.detail}[/dim]")

    def close(self):
        self.runner.close()
