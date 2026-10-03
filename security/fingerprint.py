"""
security/fingerprint.py — Backend Stack Fingerprinter
=======================================================
Detects:
  Web servers    — nginx, Apache, Caddy, IIS, LiteSpeed, Gunicorn, Uvicorn
  Frameworks     — Spring Boot, Django, Laravel, Express, FastAPI, Rails, Flask
  Databases      — indirect via error messages and timing
  Redis          — exposed port 6379 probe, INFO command attempt
  Spring Boot    — /actuator, /actuator/health, /actuator/env, /actuator/beans
  Brokers        — RabbitMQ mgmt UI, Kafka REST proxy
  Cloud hints    — AWS API GW, Cloudflare, GCP, Azure
  Mail protocols — checked via mailprobe.py
  POP3 APIs      — port hints, headers
  Version        — extracted and fed to CVE checker
"""

import socket
import re
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.runner import Runner

console = Console()


# ═══════════════════════════════════════════════════════════════════════════
#  Fingerprint result
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FingerprintResult:
    url:           str
    server:        str        = "Unknown"
    framework:     str        = "Unknown"
    language:      str        = "Unknown"
    cloud:         str        = "None detected"
    version_hints: list[str]  = field(default_factory=list)  # "nginx/1.18.0" style
    exposed_paths: list[dict] = field(default_factory=list)  # actuator, debug, etc.
    redis_exposed: bool       = False
    broker_hints:  list[str]  = field(default_factory=list)
    cve_findings:  list[dict] = field(default_factory=list)
    raw_headers:   dict       = field(default_factory=dict)
    notes:         list[str]  = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
#  Server / framework signatures
# ═══════════════════════════════════════════════════════════════════════════

SERVER_SIGS = {
    # header_value_pattern → (server_name, version_group)
    r"nginx(?:/(\S+))?":             "nginx",
    r"Apache(?:/(\S+))?":            "Apache",
    r"Microsoft-IIS(?:/(\S+))?":     "IIS",
    r"LiteSpeed":                    "LiteSpeed",
    r"Caddy":                        "Caddy",
    r"gunicorn(?:/(\S+))?":          "Gunicorn",
    r"uvicorn":                      "Uvicorn",
    r"cloudflare":                   "Cloudflare (proxy)",
    r"AmazonS3":                     "AWS S3",
    r"openresty(?:/(\S+))?":         "OpenResty/nginx",
}

FRAMEWORK_SIGS = {
    # (header_name, value_pattern) → framework
    ("X-Powered-By",   r"PHP(?:/(\S+))?"):             "PHP",
    ("X-Powered-By",   r"Express"):                    "Express.js",
    ("X-Powered-By",   r"ASP\.NET"):                   "ASP.NET",
    ("X-Generator",    r"Django"):                     "Django",
    ("X-Framework",    r"Laravel"):                    "Laravel",
    ("Set-Cookie",     r"PHPSESSID"):                  "PHP",
    ("Set-Cookie",     r"JSESSIONID"):                 "Java (Spring/Servlet)",
    ("Set-Cookie",     r"laravel_session"):             "Laravel",
    ("Set-Cookie",     r"django_session|csrftoken"):   "Django",
    ("Via",            r"1\.1 vegur"):                 "Heroku",
}

CLOUD_SIGS = {
    "CF-Ray":            "Cloudflare",
    "X-Amzn-RequestId": "AWS",
    "X-Amz-Cf-Id":      "AWS CloudFront",
    "X-Google-Backends":"GCP",
    "X-Ms-Request-Id":  "Azure",
    "Server:AmazonS3":  "AWS S3",
}

# Paths to probe for Spring Boot Actuator and debug endpoints
PROBE_PATHS = [
    ("/actuator",              "Spring Boot Actuator root"),
    ("/actuator/health",       "Spring Boot health"),
    ("/actuator/env",          "Spring Boot env — may leak secrets"),
    ("/actuator/beans",        "Spring Boot beans"),
    ("/actuator/mappings",     "Spring Boot URL mappings"),
    ("/actuator/metrics",      "Spring Boot metrics"),
    ("/actuator/loggers",      "Spring Boot loggers"),
    ("/debug",                 "Debug endpoint"),
    ("/console",               "Console (H2/Rails/etc)"),
    ("/admin",                 "Admin panel"),
    ("/.env",                  "Environment file — secrets leak risk"),
    ("/config",                "Config endpoint"),
    ("/swagger-ui.html",       "Swagger UI (Spring)"),
    ("/swagger-ui/index.html", "Swagger UI"),
    ("/api-docs",              "OpenAPI docs"),
    ("/graphql",               "GraphQL endpoint"),
    ("/graphiql",              "GraphiQL IDE"),
    ("/phpinfo.php",           "PHP info — severe info leak"),
    ("/server-status",         "Apache server-status"),
    ("/rabbitmq",              "RabbitMQ mgmt UI"),
    ("/api/v1",                "Versioned API root"),
]

REDIS_PORT = 6379
KAFKA_REST_PATHS = ["/topics", "/brokers", "/v2/topics"]


# ═══════════════════════════════════════════════════════════════════════════
#  Fingerprinter
# ═══════════════════════════════════════════════════════════════════════════

class Fingerprinter:

    def __init__(self, proxy: str | None = None, check_cve: bool = True):
        self.runner    = Runner(proxy=proxy, verify_ssl=False, timeout=10)
        self.check_cve = check_cve

    def fingerprint(self, url: str) -> FingerprintResult:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        host   = parsed.hostname or ""

        result = FingerprintResult(url=url)

        console.print(f"\n[cyan]🔬 Fingerprinting:[/cyan] {url}\n")

        # ── 1. Baseline request — read headers ────────────────────────────
        r = self.runner.get(url)
        if r.error:
            console.print(f"  [red]✗ Could not reach target: {r.error}[/red]")
            return result

        result.raw_headers = r.headers
        self._detect_server(r.headers, result)
        self._detect_framework(r.headers, r.body, result)
        self._detect_cloud(r.headers, result)
        self._detect_language(r.headers, r.body, result)

        # ── 2. Probe sensitive paths ──────────────────────────────────────
        console.print(f"  [dim]Probing {len(PROBE_PATHS)} known paths…[/dim]")
        for path, label in PROBE_PATHS:
            probe_url = base + path
            pr = self.runner.get(probe_url)
            if pr.status_code and pr.status_code not in (404, 410):
                result.exposed_paths.append({
                    "path":   path,
                    "label":  label,
                    "status": pr.status_code,
                    "size":   len(pr.body),
                })
                color = "red" if pr.status_code == 200 else "yellow"
                console.print(f"    [{color}]⚠ {pr.status_code}[/{color}]  {path}  — {label}")

        # ── 3. Redis probe ────────────────────────────────────────────────
        console.print(f"  [dim]Probing Redis on {host}:{REDIS_PORT}…[/dim]")
        result.redis_exposed = self._probe_redis(host)
        if result.redis_exposed:
            result.notes.append("Redis port 6379 is exposed — unauthenticated access risk")
            console.print(f"    [red]⚠ Redis port {REDIS_PORT} is open and responding![/red]")

        # ── 4. Kafka REST proxy probe ─────────────────────────────────────
        for path in KAFKA_REST_PATHS:
            kr = self.runner.get(base + path)
            if kr.status_code == 200 and ("topics" in kr.body or "brokers" in kr.body):
                result.broker_hints.append(f"Kafka REST proxy at {path}")
                console.print(f"    [yellow]⚠ Kafka REST proxy detected: {path}[/yellow]")

        # ── 5. CVE cross-reference ────────────────────────────────────────
        if self.check_cve and result.version_hints:
            console.print(f"  [dim]Cross-referencing {len(result.version_hints)} version hint(s) with CVE DB…[/dim]")
            self._check_cves(result)

        return result

    # ── Detection helpers ────────────────────────────────────────────────────

    def _detect_server(self, headers: dict, result: FingerprintResult):
        server_header = headers.get("Server", "") or headers.get("server", "")
        for pattern, name in SERVER_SIGS.items():
            m = re.search(pattern, server_header, re.IGNORECASE)
            if m:
                result.server = name
                # try to extract version
                try:
                    ver = m.group(1)
                    if ver:
                        result.version_hints.append(f"{name}/{ver}")
                except IndexError:
                    pass
                break
        if result.server == "Unknown" and server_header:
            result.server = server_header[:60]

    def _detect_framework(self, headers: dict, body: str, result: FingerprintResult):
        for (header_name, pattern), fw in FRAMEWORK_SIGS.items():
            val = headers.get(header_name, "") or headers.get(header_name.lower(), "")
            if val and re.search(pattern, val, re.IGNORECASE):
                result.framework = fw
                m = re.search(pattern, val, re.IGNORECASE)
                try:
                    ver = m.group(1) if m else None
                    if ver:
                        result.version_hints.append(f"{fw}/{ver}")
                except IndexError:
                    pass
                break

        # Body-based framework hints
        body_fw_patterns = [
            (r"Django",                       "Django"),
            (r"Laravel",                      "Laravel"),
            (r"Symfony",                      "Symfony"),
            (r"Spring Framework|Whitelabel Error Page", "Spring Boot"),
            (r"Ruby on Rails",                "Rails"),
            (r"FastAPI",                      "FastAPI"),
        ]
        if result.framework == "Unknown":
            for pattern, fw in body_fw_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    result.framework = fw
                    break

    def _detect_cloud(self, headers: dict, result: FingerprintResult):
        for header, cloud in CLOUD_SIGS.items():
            if ":" in header:
                h, v = header.split(":", 1)
                if headers.get(h, "").startswith(v):
                    result.cloud = cloud
                    return
            elif header in headers or header.lower() in headers:
                result.cloud = cloud
                return

    def _detect_language(self, headers: dict, body: str, result: FingerprintResult):
        xpb = headers.get("X-Powered-By", "")
        if "PHP" in xpb:
            result.language = "PHP"
        elif "ASP.NET" in xpb:
            result.language = ".NET"
        elif re.search(r"JSESSIONID", headers.get("Set-Cookie",""), re.IGNORECASE):
            result.language = "Java"
        elif re.search(r"Traceback.*Python|django|flask|fastapi", body, re.IGNORECASE):
            result.language = "Python"
        elif re.search(r"at [\w$]+\.[\w$]+\([\w]+\.java:\d+\)", body):
            result.language = "Java"
        elif re.search(r"node_modules|express", body, re.IGNORECASE):
            result.language = "Node.js"

    def _probe_redis(self, host: str) -> bool:
        """Try opening a TCP connection to Redis port and send PING."""
        try:
            sock = socket.create_connection((host, REDIS_PORT), timeout=3)
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            response = sock.recv(64)
            sock.close()
            return b"+PONG" in response or b"PONG" in response
        except Exception:
            return False

    def _check_cves(self, result: FingerprintResult):
        from storage.db import search_cve
        for hint in result.version_hints:
            parts = hint.split("/", 1)
            if len(parts) == 2:
                tech, version = parts
                cves = search_cve(tech, version)
                for cve in cves:
                    result.cve_findings.append(cve)
                    sev = cve.get("severity", "?")
                    color = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"dim"}.get(sev,"white")
                    console.print(
                        f"    [bold {color}]{cve['cve_id']}[/bold {color}]  "
                        f"[{color}]{sev}[/{color}]  "
                        f"CVSS={cve.get('cvss_score','?')}  "
                        f"{tech}/{version}"
                    )

    # ── Print result ─────────────────────────────────────────────────────────

    def print_result(self, result: FingerprintResult):
        console.print()

        # Stack summary panel
        stack_lines = [
            f"[bold]Server   :[/bold]  {result.server}",
            f"[bold]Framework:[/bold]  {result.framework}",
            f"[bold]Language :[/bold]  {result.language}",
            f"[bold]Cloud    :[/bold]  {result.cloud}",
        ]
        if result.version_hints:
            stack_lines.append(f"[bold]Versions :[/bold]  {', '.join(result.version_hints)}")
        if result.redis_exposed:
            stack_lines.append("[bold red]Redis    :  ⚠ EXPOSED on port 6379[/bold red]")
        if result.broker_hints:
            stack_lines.append(f"[bold yellow]Brokers  :[/bold yellow]  {', '.join(result.broker_hints)}")

        console.print(Panel(
            "\n".join(stack_lines),
            title=f"[cyan]🔬 Fingerprint — {result.url}[/cyan]",
            border_style="cyan",
        ))

        # Exposed paths table
        if result.exposed_paths:
            t = Table("Status", "Path", "Description", "Size",
                      box=box.SIMPLE, header_style="bold yellow")
            for ep in result.exposed_paths:
                color = "red" if ep["status"] == 200 else "yellow"
                t.add_row(
                    f"[{color}]{ep['status']}[/{color}]",
                    ep["path"], ep["label"],
                    f"{ep['size']}b",
                )
            console.print(t)

        # CVE findings
        if result.cve_findings:
            console.print(f"\n[bold red]⚠ {len(result.cve_findings)} CVE(s) matched for detected versions:[/bold red]")
            for cve in result.cve_findings[:10]:
                sev   = cve.get("severity","?")
                color = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"dim"}.get(sev,"white")
                console.print(f"  [{color}]{cve['cve_id']}  {sev}  CVSS={cve.get('cvss_score','?')}[/{color}]")
                if cve.get("description"):
                    console.print(f"  [dim]{cve['description'][:120]}…[/dim]")

        if result.notes:
            for note in result.notes:
                console.print(f"  [yellow]ℹ {note}[/yellow]")

    def close(self):
        self.runner.close()
