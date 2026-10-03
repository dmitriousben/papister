"""
cli.py — Papister v1.0.1 Entry Point
======================================
All commands registered here. Logic lives in modules.

Run:
  python cli.py --help
  python cli.py scan endpoints/endpoints.yaml --mode S
  python cli.py test https://api.example.com/v1/users
"""

import os
import sys
import json
import webbrowser
import subprocess
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

# ── make sure papister root is always on the path ───────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app     = typer.Typer(
    name="papister",
    help="🔎 Papister v1.0.1 — Local API Security & Testing Toolkit",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()

# ── lazy imports — keep startup fast ────────────────────────────────────────
def _scanner():
    from core import scanner; return scanner

def _reporter():
    from core import reporter; return reporter

def _db():
    from storage import db; return db


# ═══════════════════════════════════════════════════════════════════════════
#  papister scan
# ═══════════════════════════════════════════════════════════════════════════

@app.command("scan")
def scan(
    file:    str           = typer.Argument(..., help="Collection file: .txt / .yaml / .json"),
    mode:    str           = typer.Option("S",   "--mode",    "-m", metavar="S|P"),
    proxy:   Optional[str] = typer.Option(None,  "--proxy",   help="e.g. http://127.0.0.1:8080"),
    timeout: int           = typer.Option(15,    "--timeout", "-t"),
    retries: int           = typer.Option(2,     "--retries", "-r"),
    no_ssl:  bool          = typer.Option(False, "--no-ssl-verify"),
):
    """[bold cyan]Scan all endpoints[/bold cyan] from a collection file (.txt/.yaml/.json)."""
    mode = mode.upper()
    if mode not in ("S", "P"):
        console.print("[red]--mode must be S or P[/red]"); raise typer.Exit(1)
    if mode == "P":
        if not typer.confirm("⚠  Production mode — requests hit live systems. Continue?"):
            raise typer.Exit()
    _scanner().scan_file(
        file_path=file, mode=mode, proxy=proxy,
        timeout=timeout, retries=retries, verify_ssl=not no_ssl,
        command=f"scan {file} --mode {mode}",
    )


# ═══════════════════════════════════════════════════════════════════════════
#  papister test
# ═══════════════════════════════════════════════════════════════════════════

@app.command("test")
def test(
    url:     str           = typer.Argument(..., help="Endpoint URL"),
    method:  str           = typer.Option("GET", "--method", "-X"),
    mode:    str           = typer.Option("S",   "--mode",   "-m", metavar="S|P"),
    auth:    Optional[str] = typer.Option(None,  "--auth",   "-a", help="Saved auth profile name"),
    proxy:   Optional[str] = typer.Option(None,  "--proxy"),
    timeout: int           = typer.Option(15,    "--timeout", "-t"),
):
    """[bold cyan]Test a single endpoint[/bold cyan] directly — no collection file needed."""
    _scanner().test_single(
        url=url, method=method.upper(), mode=mode.upper(),
        auth_profile=auth, proxy=proxy, timeout=timeout,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  papister add
# ═══════════════════════════════════════════════════════════════════════════

@app.command("add")
def add(
    url:    str = typer.Argument(..., help="Endpoint URL to save"),
    method: str = typer.Option("GET", "--method", "-X"),
    source: str = typer.Option("manual", "--source"),
):
    """[bold cyan]Save a discovered endpoint[/bold cyan] to discovered.yaml and DB."""
    from endpoint_collections.writer import append_to_discovered
    _db().add_discovered(url=url, method=method.upper(), source=source)
    append_to_discovered(url=url, method=method.upper(), source=source)
    console.print(f"[green]✓ Added:[/green] {method.upper()} {url}")


# ═══════════════════════════════════════════════════════════════════════════
#  papister sqli
# ═══════════════════════════════════════════════════════════════════════════

@app.command("sqli")
def sqli(
    target:  str           = typer.Argument(..., help="URL or collection file"),
    mode:    str           = typer.Option("S",  "--mode",    "-m", metavar="S|P"),
    proxy:   Optional[str] = typer.Option(None, "--proxy"),
    timeout: int           = typer.Option(20,   "--timeout", "-t"),
    level:   int           = typer.Option(2,    "--level",   "-l",
                                          help="1=error-based  2=+blind  3=+time+stacked"),
):
    """[bold red]Deep SQL injection[/bold red] — error, boolean-blind, time-based, stacked."""
    from security.sqli import SQLiScanner
    _reporter().print_banner()
    scanner = SQLiScanner(proxy=proxy, timeout=timeout, level=level)
    if target.startswith(("http://", "https://")):
        results = scanner.scan_url(target)
    else:
        from endpoint_collections.loader import load
        results = scanner.scan_entries(load(target))
    scanner.print_results(results)
    scanner.close()


# ═══════════════════════════════════════════════════════════════════════════
#  papister bola  ← FIXED: now in correct position before __main__
# ═══════════════════════════════════════════════════════════════════════════

@app.command("bola")
def bola(
    target:     str           = typer.Argument(..., help="URL or collection file"),
    method:     str           = typer.Option("GET",  "--method",     "-X"),
    mode:       str           = typer.Option("S",    "--mode",       "-m", metavar="S|P"),
    auth:       Optional[str] = typer.Option(None,   "--auth",       "-a", help="Primary auth profile"),
    alt_auth:   Optional[str] = typer.Option(None,   "--alt-auth",   help="Alt auth for cross-account"),
    proxy:      Optional[str] = typer.Option(None,   "--proxy"),
    timeout:    int           = typer.Option(15,     "--timeout",    "-t"),
    enum_start: int           = typer.Option(1,      "--enum-start", help="ID range start"),
    enum_end:   int           = typer.Option(20,     "--enum-end",   help="ID range end"),
    strategies: str           = typer.Option("all",  "--strategies",
                                             help="all  or  sequential,zero_neg,admin_ids,"
                                                  "type_switch,uuid_mutate,enumerate"),
):
    """
    [bold red]BOLA[/bold red] — Broken Object Level Authorization (OWASP API #1).

    Mutates object IDs in URLs/params. Detects unauthorized data access.
    Use --alt-auth for cross-account testing.
    """
    from security.bola import BOLAScanner
    _reporter().print_banner()

    def _resolve_auth(name):
        if not name: return None
        p = _db().get_auth_profile(name)
        if not p:
            console.print(f"[red]Auth profile '{name}' not found[/red]"); return None
        t, c = p["auth_type"], p["config"]
        if t == "oauth2":
            from auth.oauth2 import OAuth2Auth; return OAuth2Auth(**c)
        if t == "apikey":
            from auth.apikey import APIKeyAuth; return APIKeyAuth(**c)
        if t == "basic":
            from auth.basic  import BasicAuth;  return BasicAuth(**c)
        if t == "oauth1":
            from auth.oauth1 import OAuth1Auth; return OAuth1Auth(**c)
        return None

    strat_list = None if strategies == "all" else [s.strip() for s in strategies.split(",")]
    scanner    = BOLAScanner(
        proxy=proxy, timeout=timeout,
        enum_range=(enum_start, enum_end),
        strategies=strat_list,
        auth=_resolve_auth(auth),
        alt_auth=_resolve_auth(alt_auth),
    )

    if target.startswith(("http://", "https://")):
        findings = scanner.scan_url(target, method=method.upper())
    else:
        from endpoint_collections.loader import load
        findings = scanner.scan_entries(load(target))

    scanner.print_results(findings)
    scanner.close()

    if findings:
        _reporter().write_reports([], meta={
            "command": f"bola {target}", "mode": mode,
            "findings": len(findings),
            "bola_summary": [
                {"url": f.url, "param": f.param, "original": f.original_id,
                 "mutated": f.mutated_id, "strategy": f.strategy,
                 "confidence": f.confidence, "evidence": f.evidence,
                 "cross_account": f.cross_account}
                for f in findings
            ],
        })


# ═══════════════════════════════════════════════════════════════════════════
#  papister fuzz
# ═══════════════════════════════════════════════════════════════════════════

@app.command("fuzz")
def fuzz(
    url:     str           = typer.Argument(...),
    method:  str           = typer.Option("GET", "--method", "-X"),
    proxy:   Optional[str] = typer.Option(None,  "--proxy"),
    timeout: int           = typer.Option(15,    "--timeout"),
):
    """[bold yellow]Fuzz parameters[/bold yellow] — nulls, oversized, type confusion, path traversal."""
    from security.fuzzer import Fuzzer
    _reporter().print_banner()
    fuzzer  = Fuzzer(proxy=proxy, timeout=timeout)
    results = fuzzer.fuzz_url(url=url, method=method.upper())
    fuzzer.print_results(results)
    fuzzer.close()


# ═══════════════════════════════════════════════════════════════════════════
#  papister headers
# ═══════════════════════════════════════════════════════════════════════════

@app.command("headers")
def headers(
    url:   str           = typer.Argument(...),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
):
    """[bold yellow]Audit security headers[/bold yellow] — HSTS, CSP, CORS, X-Frame. Score 0-100."""
    from security.headers import HeaderAuditor
    _reporter().print_banner()
    auditor = HeaderAuditor(proxy=proxy)
    result  = auditor.audit(url)
    auditor.print_result(result)
    auditor.close()


# ═══════════════════════════════════════════════════════════════════════════
#  papister fingerprint
# ═══════════════════════════════════════════════════════════════════════════

@app.command("fingerprint")
def fingerprint(
    url:       str           = typer.Argument(...),
    proxy:     Optional[str] = typer.Option(None,  "--proxy"),
    cve_check: bool          = typer.Option(True,  "--cve/--no-cve"),
):
    """[bold cyan]Detect backend stack[/bold cyan] — server, framework, Redis, Spring Boot, CVE match."""
    from security.fingerprint import Fingerprinter
    _reporter().print_banner()
    fp     = Fingerprinter(proxy=proxy, check_cve=cve_check)
    result = fp.fingerprint(url)
    fp.print_result(result)
    fp.close()


# ═══════════════════════════════════════════════════════════════════════════
#  papister mailprobe
# ═══════════════════════════════════════════════════════════════════════════

@app.command("mailprobe")
def mailprobe(
    host:    str = typer.Argument(..., help="Host to probe e.g. mail.example.com"),
    port:    int = typer.Option(0,  "--port",    "-p", help="0 = probe all common ports"),
    timeout: int = typer.Option(10, "--timeout"),
):
    """[bold yellow]Probe mail APIs[/bold yellow] — POP3, IMAP, SMTP banners and capabilities."""
    from security.mailprobe import MailProber
    _reporter().print_banner()
    prober = MailProber(timeout=timeout)
    result = prober.probe(host=host, port=port or None)
    prober.print_result(result)


# ═══════════════════════════════════════════════════════════════════════════
#  papister jwt  (v1.0.1)
# ═══════════════════════════════════════════════════════════════════════════

@app.command("jwt")
def jwt_cmd(
    target:  str           = typer.Argument(..., help="Token string OR URL to extract token from"),
    attack:  bool          = typer.Option(False, "--attack",  help="Run all attack strategies"),
    brute:   bool          = typer.Option(False, "--brute",   help="Brute-force weak secret"),
    proxy:   Optional[str] = typer.Option(None,  "--proxy"),
    timeout: int           = typer.Option(15,    "--timeout"),
    url:     Optional[str] = typer.Option(None,  "--url",     help="Endpoint to test attacks against"),
    auth:    Optional[str] = typer.Option(None,  "--auth",    "-a"),
):
    """
    [bold cyan]JWT security testing[/bold cyan] — inspect, attack, brute-force.

    Detects: alg:none, RS256→HS256 confusion, weak secrets,
    expired token acceptance, claim tampering, kid injection.
    """
    from security.jwt import JWTScanner
    _reporter().print_banner()
    scanner = JWTScanner(proxy=proxy, timeout=timeout)

    if target.startswith(("http://", "https://")):
        # Extract token from a live endpoint
        token = scanner.extract_token_from_url(target)
        if not token:
            console.print("[red]No JWT found in response headers or body.[/red]")
            return
        console.print(f"[green]✓ Token extracted from response[/green]")
    else:
        token = target

    # Always inspect first
    scanner.inspect(token)

    if attack and url:
        findings = scanner.attack(token=token, url=url)
        scanner.print_findings(findings)

    if brute:
        result = scanner.brute_force(token)
        scanner.print_brute_result(result)

    scanner.close()


# ═══════════════════════════════════════════════════════════════════════════
#  papister graphql  (v1.0.1)
# ═══════════════════════════════════════════════════════════════════════════

@app.command("graphql")
def graphql_cmd(
    url:         str           = typer.Argument(..., help="GraphQL endpoint URL"),
    dump_schema: bool          = typer.Option(False, "--dump-schema", help="Save full schema to file"),
    attack:      bool          = typer.Option(False, "--attack",      help="Run all attack strategies"),
    proxy:       Optional[str] = typer.Option(None,  "--proxy"),
    timeout:     int           = typer.Option(20,    "--timeout"),
    auth:        Optional[str] = typer.Option(None,  "--auth", "-a"),
):
    """
    [bold cyan]GraphQL security testing[/bold cyan] — introspect, audit, attack.

    Detects: introspection enabled, batching abuse, deep nesting DoS,
    field suggestion leakage, unauthenticated mutations, alias abuse.
    """
    from security.graphql import GraphQLScanner
    _reporter().print_banner()

    def _resolve_auth(name):
        if not name: return None
        p = _db().get_auth_profile(name)
        if not p: return None
        t, c = p["auth_type"], p["config"]
        if t == "oauth2":
            from auth.oauth2 import OAuth2Auth; return OAuth2Auth(**c)
        if t == "apikey":
            from auth.apikey import APIKeyAuth; return APIKeyAuth(**c)
        return None

    scanner  = GraphQLScanner(proxy=proxy, timeout=timeout, auth=_resolve_auth(auth))
    findings = scanner.scan(url, dump_schema=dump_schema, run_attacks=attack)
    scanner.print_findings(findings)
    scanner.close()


# ═══════════════════════════════════════════════════════════════════════════
#  papister soap  (v1.0.1)
# ═══════════════════════════════════════════════════════════════════════════

@app.command("soap")
def soap_cmd(
    url:    str           = typer.Argument(..., help="WSDL URL or SOAP endpoint"),
    attack: bool          = typer.Option(False, "--attack", help="Run XXE, header strip, param tampering"),
    proxy:  Optional[str] = typer.Option(None,  "--proxy"),
    timeout:int           = typer.Option(20,    "--timeout"),
    auth:   Optional[str] = typer.Option(None,  "--auth", "-a"),
):
    """
    [bold cyan]SOAP / WSDL security testing[/bold cyan] — discover, enumerate, attack.

    Detects: WSDL exposure, XXE injection, SOAPAction spoofing,
    WS-Security header stripping, large payload DoS, param tampering.
    """
    from security.soap import SOAPScanner
    _reporter().print_banner()
    scanner  = SOAPScanner(proxy=proxy, timeout=timeout)
    findings = scanner.scan(url, run_attacks=attack)
    scanner.print_findings(findings)
    scanner.close()


# ═══════════════════════════════════════════════════════════════════════════
#  CVE sub-commands
# ═══════════════════════════════════════════════════════════════════════════

cve_app = typer.Typer(help="CVE database management")
app.add_typer(cve_app, name="cve")

@cve_app.command("update")
def cve_update():
    """Pull latest NVD CVE feed into local DB."""
    from security.cve import CVEManager
    CVEManager().update()

@cve_app.command("check")
def cve_check(
    tech:    str = typer.Argument(..., help="Tech name e.g. nginx, spring-boot, django"),
    version: str = typer.Argument(..., help="Version string e.g. 1.18.0"),
):
    """Look up CVEs for a specific tech + version."""
    from security.cve import CVEManager
    mgr     = CVEManager()
    results = mgr.check(tech, version)
    mgr.print_results(results, tech, version)


# ═══════════════════════════════════════════════════════════════════════════
#  Auth sub-commands
# ═══════════════════════════════════════════════════════════════════════════

auth_app = typer.Typer(help="Auth profile management")
app.add_typer(auth_app, name="auth")

@auth_app.command("set")
def auth_set(
    name:      str = typer.Argument(...),
    auth_type: str = typer.Option(..., "--type", "-t",
                                  help="apikey | oauth1 | oauth2 | basic | custom"),
):
    """Store an auth profile interactively."""
    config: dict = {}
    console.print(f"[cyan]Setting up:[/cyan] {name}  (type={auth_type})")

    if auth_type == "apikey":
        config["key"]      = typer.prompt("API Key", hide_input=True)
        config["header"]   = typer.prompt("Header name", default="X-API-Key")
        in_q               = typer.confirm("Send as query param?", default=False)
        config["in_query"] = in_q
        if in_q:
            config["param_name"] = typer.prompt("Param name", default="api_key")
    elif auth_type == "oauth2":
        config["token"] = typer.prompt("Bearer Token (blank = client-credentials flow)", default="")
        if not config["token"]:
            config["auto_fetch"]    = True
            config["token_url"]     = typer.prompt("Token URL")
            config["client_id"]     = typer.prompt("Client ID")
            config["client_secret"] = typer.prompt("Client Secret", hide_input=True)
            config["scope"]         = typer.prompt("Scope (optional)", default="")
    elif auth_type == "basic":
        config["username"] = typer.prompt("Username")
        config["password"] = typer.prompt("Password", hide_input=True)
    elif auth_type == "oauth1":
        config["consumer_key"]    = typer.prompt("Consumer Key")
        config["consumer_secret"] = typer.prompt("Consumer Secret", hide_input=True)
        config["token"]           = typer.prompt("Access Token (optional)", default="")
        config["token_secret"]    = typer.prompt("Token Secret (optional)", default="")
    elif auth_type == "custom":
        console.print("[dim]Enter KEY=VALUE headers (blank to finish)[/dim]")
        h: dict = {}
        while True:
            entry = typer.prompt("Header", default="")
            if not entry: break
            if "=" in entry:
                k, v = entry.split("=", 1)
                h[k.strip()] = v.strip()
        config["headers"] = h

    _db().save_auth_profile(name=name, auth_type=auth_type, config=config)
    console.print(f"[green]✓ Auth profile '{name}' saved.[/green]")

@auth_app.command("list")
def auth_list():
    """List all saved auth profiles."""
    profiles = _db().list_auth_profiles()
    if not profiles:
        console.print("[dim]No profiles yet.  papister auth set <name>[/dim]"); return
    t = Table("Name", "Type", "Created", "Updated", box=box.SIMPLE)
    for p in profiles:
        t.add_row(p["name"], p["auth_type"], p["created_at"][:19], p["updated_at"][:19])
    console.print(t)


# ═══════════════════════════════════════════════════════════════════════════
#  Proxy sub-commands
# ═══════════════════════════════════════════════════════════════════════════

proxy_app = typer.Typer(help="Built-in intercept proxy")
app.add_typer(proxy_app, name="proxy")

@proxy_app.command("start")
def proxy_start(port: int = typer.Option(8787, "--port", "-p")):
    """Start Papister intercept proxy."""
    from core.proxy import PapisterProxy
    console.print(f"[cyan]🔌 Proxy on 127.0.0.1:{port}[/cyan]  (Ctrl+C to stop)")
    PapisterProxy(port=port).start()

@proxy_app.command("stop")
def proxy_stop():
    """Stop the intercept proxy (send Ctrl+C to the proxy process)."""
    console.print("[yellow]Send Ctrl+C to the running proxy process.[/yellow]")

@proxy_app.command("replay")
def proxy_replay(request_id: str = typer.Argument(...)):
    """Replay a captured request by ID."""
    from core.proxy import PapisterProxy
    PapisterProxy.replay(request_id)


# ═══════════════════════════════════════════════════════════════════════════
#  Integrations sub-commands
# ═══════════════════════════════════════════════════════════════════════════

integrations_app = typer.Typer(help="Third-party integration test suites")
app.add_typer(integrations_app, name="integrations")

@integrations_app.command("list")
def integrations_list():
    """List all available integration modules."""
    items = [
        ("mpesa",          "Safaricom Daraja — STK Push, C2B, B2C, Balance"),
        ("africastalking", "Africa's Talking — SMS, USSD, Voice, Airtime"),
        ("flutterwave",    "Flutterwave — Card, Mobile Money, Bank Transfer"),
        ("stripe",         "Stripe — Charges, Customers, Webhooks"),
        ("twilio",         "Twilio — SMS, Voice, Verify"),
    ]
    t = Table("Integration", "Description", box=box.SIMPLE, header_style="bold cyan")
    for name, desc in items:
        t.add_row(f"[cyan]{name}[/cyan]", desc)
    console.print(t)

@integrations_app.command("run")
def integrations_run(
    name: str           = typer.Argument(...),
    mode: str           = typer.Option("S", "--mode", "-m", metavar="S|P"),
    auth: Optional[str] = typer.Option(None, "--auth", "-a"),
):
    """Run an integration test suite."""
    _reporter().print_banner()
    n = name.lower()
    if n == "mpesa":
        from integrations.mpesa import MpesaIntegration
        MpesaIntegration(mode=mode, auth_profile=auth).run()
    elif n == "africastalking":
        from integrations.africastalking import AfricasTalkingIntegration
        AfricasTalkingIntegration(mode=mode, auth_profile=auth).run()
    elif n == "flutterwave":
        from integrations.flutterwave import FlutterwaveIntegration
        FlutterwaveIntegration(mode=mode, auth_profile=auth).run()
    elif n == "stripe":
        from integrations.stripe import StripeIntegration
        StripeIntegration(mode=mode, auth_profile=auth).run()
    elif n == "twilio":
        from integrations.twilio import TwilioIntegration
        TwilioIntegration(mode=mode, auth_profile=auth).run()
    else:
        console.print(f"[red]Unknown: {name}[/red]  —  papister integrations list")


# ═══════════════════════════════════════════════════════════════════════════
#  Vault sub-commands
# ═══════════════════════════════════════════════════════════════════════════

vault_app = typer.Typer(help="Encrypted API key vault")
app.add_typer(vault_app, name="vault")

@vault_app.command("set")
def vault_set(provider: str = typer.Argument(...)):
    """Prompt and encrypt keys for a provider."""
    from vault.vault import interactive_set
    interactive_set(provider)

@vault_app.command("rotate")
def vault_rotate(provider: str = typer.Argument(...)):
    """Re-prompt and re-encrypt all keys for a provider."""
    from vault.vault import Vault
    Vault().rotate(provider)

@vault_app.command("get")
def vault_get(provider: str = typer.Argument(...)):
    """Show stored field names (not values) for a provider."""
    from vault.vault import interactive_show
    interactive_show(provider)

@vault_app.command("delete")
def vault_delete(provider: str = typer.Argument(...)):
    """Delete all keys for a provider."""
    if typer.confirm(f"Delete vault entry for '{provider}'?"):
        from vault.vault import Vault
        Vault().delete(provider)

@vault_app.command("list")
def vault_list():
    """List all providers stored in the vault."""
    from vault.vault import Vault
    providers = Vault().list_providers()
    if not providers:
        console.print("[dim]Vault empty.  papister vault set <provider>[/dim]"); return
    t = Table("Provider","Fields","Passphrase","Updated","File", box=box.ROUNDED, header_style="bold cyan")
    for p in providers:
        t.add_row(
            f"[bold cyan]{p['provider']}[/bold cyan]",
            ", ".join(p["fields"]),
            "[green]Yes[/green]" if p["requires_passphrase"] else "[dim]No[/dim]",
            p["updated_at"][:19],
            "[green]✓[/green]" if p["file_exists"] else "[red]✗[/red]",
        )
    console.print(t)

@vault_app.command("providers")
def vault_providers():
    """List all supported provider schemas."""
    from vault.schemas import PROVIDER_SCHEMAS, PROVIDER_ALIASES
    t = Table("Provider", "Fields", box=box.SIMPLE, header_style="bold cyan")
    for name, fields in sorted(PROVIDER_SCHEMAS.items()):
        req = [f.name for f in fields if f.required]
        opt = [f.name for f in fields if not f.required]
        s   = ", ".join(req)
        if opt: s += f"  [dim](opt: {', '.join(opt)})[/dim]"
        t.add_row(f"[cyan]{name}[/cyan]", s)
    console.print(t)
    console.print(f"\n[dim]Aliases: {', '.join(f'{k}→{v}' for k,v in PROVIDER_ALIASES.items())}[/dim]")


# ═══════════════════════════════════════════════════════════════════════════
#  History
# ═══════════════════════════════════════════════════════════════════════════

@app.command("history")
def history(limit: int = typer.Option(20, "--limit", "-n")):
    """Show past scan runs from the local DB."""
    runs = _db().list_runs(limit=limit)
    if not runs:
        console.print("[dim]No history yet.[/dim]"); return
    t = Table("ID","Mode","Started","Source","Summary", box=box.SIMPLE, header_style="bold cyan")
    for r in runs:
        summary = json.loads(r["summary"]) if r.get("summary") else {}
        t.add_row(
            str(r["id"]), r["mode"], r["started_at"][:19],
            (r.get("source_file") or "—")[-40:],
            str(summary.get("by_category", {})),
        )
    console.print(t)

@app.command("history-show")
def history_show(run_id: int = typer.Argument(...)):
    """Full detail on one past run."""
    results = _db().get_run_results(run_id)
    if not results:
        console.print(f"[red]Run #{run_id} not found.[/red]"); return
    t = Table("Category","Method","Code","ms","URL", box=box.SIMPLE)
    for r in results:
        t.add_row(r["category"], r["method"],
                  str(r.get("status_code") or "—"),
                  str(round(r["response_ms"],1) if r.get("response_ms") else "—"),
                  r["url"])
    console.print(t)


# ═══════════════════════════════════════════════════════════════════════════
#  papister report  ← FIXED: auto-creates reports dir, fallback to print path
# ═══════════════════════════════════════════════════════════════════════════

@app.command("report")
def report(
    timestamp: Optional[str] = typer.Argument(None, help="Timestamp e.g. 20240601_143022. Blank = latest."),
):
    """[bold cyan]Open an HTML report[/bold cyan] in the browser. No argument = latest report."""
    from papister import REPORTS_DIR

    # ensure dir exists
    os.makedirs(REPORTS_DIR, exist_ok=True)

    try:
        all_files = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".html")]
    except Exception as e:
        console.print(f"[red]Cannot read reports directory: {e}[/red]")
        return

    if not all_files:
        console.print("[yellow]No reports yet — run a scan first:[/yellow]")
        console.print("  [dim]python cli.py scan endpoints/endpoints.yaml[/dim]")
        console.print("  [dim]python cli.py test https://httpbin.org/get[/dim]")
        return

    all_files = sorted(all_files)

    if timestamp:
        match = [f for f in all_files if timestamp in f]
        target = match[-1] if match else None
    else:
        target = all_files[-1]

    if not target:
        console.print(f"[red]No report matching '{timestamp}'[/red]")
        console.print(f"[dim]Available: {', '.join(all_files[-5:])}[/dim]")
        return

    path = os.path.abspath(os.path.join(REPORTS_DIR, target))

    if not os.path.exists(path):
        console.print(f"[red]File not found: {path}[/red]"); return

    console.print(f"[green]📄 Opening report:[/green]  {path}")

    # Try webbrowser, fallback to OS open commands
    try:
        opened = webbrowser.open(f"file://{path}")
        if not opened:
            raise Exception("webbrowser returned False")
    except Exception:
        # Fallback — try xdg-open (Linux), open (macOS)
        for cmd in ["xdg-open", "open", "start"]:
            try:
                subprocess.Popen([cmd, path],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
                break
            except FileNotFoundError:
                continue
        else:
            console.print(f"[yellow]Could not auto-open. Open manually:[/yellow]")
            console.print(f"  {path}")


# ═══════════════════════════════════════════════════════════════════════════
#  papister docs
# ═══════════════════════════════════════════════════════════════════════════

@app.command("docs")
def docs():
    """Open the offline command reference in the browser."""
    from papister import DOCS_FILE
    path = os.path.abspath(DOCS_FILE)
    if not os.path.exists(path):
        console.print(f"[yellow]Docs file not found: {path}[/yellow]"); return
    console.print(f"[green]📖 Opening docs:[/green]  {path}")
    try:
        webbrowser.open(f"file://{path}")
    except Exception:
        console.print(f"[yellow]Open manually:[/yellow]  {path}")


# ═══════════════════════════════════════════════════════════════════════════
#  papister version
# ═══════════════════════════════════════════════════════════════════════════

@app.command("version")
def version():
    """Show Papister version and CVE DB status."""
    from papister import VERSION, APP_NAME
    console.print(f"[bold cyan]{APP_NAME}[/bold cyan]  v{VERSION}")
    last = _db().get_cve_last_updated()
    console.print(f"[dim]CVE DB last updated: {last or 'never — run: papister cve update'}[/dim]")


# ═══════════════════════════════════════════════════════════════════════════
#  Entrypoint  ← always last
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app()
