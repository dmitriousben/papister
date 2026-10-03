"""
core/scanner.py — Scan Orchestrator
=====================================
Wires together: loader → runner → detector → reporter → db

This is what cli.py calls for:
  papister scan [file]
  papister test [url]
"""

from endpoint_collections.loader import load, EndpointEntry, summarise
from core.runner import Runner, RequestResult
from core.detector import classify
from core import reporter
from storage import db
from auth.base import BaseAuth
from papister import DISCOVERED


def _load_auth(profile_name: str | None) -> BaseAuth | None:
    """Fetch auth profile from DB and build the right auth object."""
    if not profile_name:
        return None
    profile = db.get_auth_profile(profile_name)
    if not profile:
        reporter.console.print(f"  [yellow]⚠ Auth profile '{profile_name}' not found — skipping auth[/yellow]")
        return None

    auth_type = profile["auth_type"]
    config    = profile["config"]

    if auth_type == "apikey":
        from auth.apikey import APIKeyAuth
        return APIKeyAuth(**config)
    elif auth_type == "oauth1":
        from auth.oauth1 import OAuth1Auth
        return OAuth1Auth(**config)
    elif auth_type == "oauth2":
        from auth.oauth2 import OAuth2Auth
        return OAuth2Auth(**config)
    elif auth_type == "basic":
        from auth.basic import BasicAuth
        return BasicAuth(**config)
    elif auth_type == "custom":
        from auth.custom import CustomAuth
        return CustomAuth(**config)
    else:
        reporter.console.print(f"  [yellow]⚠ Unknown auth type '{auth_type}'[/yellow]")
        return None


def scan_file(
    file_path: str,
    mode: str = "S",
    proxy: str | None = None,
    timeout: int = 15,
    retries: int = 2,
    verify_ssl: bool = True,
    command: str = "",
) -> list[RequestResult]:
    """
    Full scan from a collection file.
    Prints live results, summary, writes reports, saves to DB.
    Returns list of RequestResult.
    """
    reporter.print_banner()

    # ── Load collection ──────────────────────────────────────────────────
    reporter.console.print(f"[cyan]📂 Loading collection:[/cyan] {file_path}")
    entries = load(file_path)
    info    = summarise(entries)
    reporter.console.print(
        f"   {info['total']} endpoints  ·  "
        f"methods: {info['methods']}  ·  "
        f"with auth: {info['with_auth']}\n"
    )

    if not entries:
        reporter.console.print("[yellow]No valid endpoints found. Exiting.[/yellow]")
        return []

    if mode == "P":
        reporter.console.print(
            "[bold red]⚠  PRODUCTION MODE — requests go to live systems  ⚠[/bold red]\n"
        )

    # ── DB: start run ────────────────────────────────────────────────────
    run_id = db.start_run(mode=mode, source_file=file_path, command=command)

    # ── Runner ───────────────────────────────────────────────────────────
    runner  = Runner(timeout=timeout, retries=retries, verify_ssl=verify_ssl, proxy=proxy)
    results: list[RequestResult] = []

    reporter.console.print("[bold]  Status          Method  Code   Time      Endpoint[/bold]")
    reporter.console.rule(style="dim")

    for entry in entries:
        # Per-endpoint mode override
        effective_mode = entry.mode or mode

        # Auth
        auth = _load_auth(entry.auth_profile)

        result = runner.send(
            method     = entry.method,
            url        = entry.url,
            headers    = entry.headers,
            params     = entry.params,
            body       = entry.body,
            json_body  = entry.json_body,
            auth       = auth,
        )

        classify(result)
        reporter.print_result(result)
        results.append(result)

        db.save_result(
            run_id      = run_id,
            url         = result.url,
            method      = result.method,
            status_code = result.status_code,
            response_ms = result.response_ms,
            category    = result.category,
            detail      = result.detail,
        )

    runner.close()

    # ── Summary ──────────────────────────────────────────────────────────
    reporter.console.rule(style="dim")
    reporter.print_summary(results, run_id=run_id, mode=mode)

    # ── Reports ──────────────────────────────────────────────────────────
    reporter.write_reports(results, meta={
        "run_id":      run_id,
        "mode":        mode,
        "source_file": file_path,
        "command":     command,
    })

    # ── Finish run in DB ─────────────────────────────────────────────────
    counts = {}
    for r in results:
        counts[r.category] = counts.get(r.category, 0) + 1
    db.finish_run(run_id, summary={"total": len(results), "by_category": counts})

    return results


def test_single(
    url: str,
    method: str = "GET",
    mode: str = "S",
    auth_profile: str | None = None,
    proxy: str | None = None,
    timeout: int = 15,
    headers: dict | None = None,
    params: dict | None = None,
    json_body: dict | None = None,
) -> RequestResult:
    """
    Test a single endpoint. Prints result and writes reports.
    """
    reporter.print_banner()

    run_id = db.start_run(mode=mode, source_file=None, command=f"test {url}")
    runner = Runner(timeout=timeout, proxy=proxy)
    auth   = _load_auth(auth_profile)

    reporter.console.print(f"[cyan]🔍 Testing:[/cyan] {method} {url}\n")
    reporter.console.print("[bold]  Status          Method  Code   Time      Endpoint[/bold]")
    reporter.console.rule(style="dim")

    result = runner.send(
        method    = method,
        url       = url,
        headers   = headers or {},
        params    = params or {},
        json_body = json_body,
        auth      = auth,
    )
    classify(result)
    reporter.print_result(result)
    runner.close()

    reporter.console.rule(style="dim")
    reporter.print_summary([result], run_id=run_id, mode=mode)
    reporter.write_reports([result], meta={"run_id": run_id, "mode": mode, "command": f"test {url}"})
    db.save_result(run_id, result.url, result.method, result.status_code,
                   result.response_ms, result.category, result.detail)
    db.finish_run(run_id, summary={"total": 1, "by_category": {result.category: 1}})

    return result
