"""
core/proxy.py — Papister Built-in Intercept Proxy
====================================================
Lightweight HTTP proxy that:
  - Intercepts all requests Papister makes when enabled
  - Logs them to storage/history.db (proxy_captures table)
  - Allows replay of captured requests
  - Runs on 127.0.0.1:8787 by default

Based on Python's http.server + socket tunnelling.
Start with: papister proxy start
"""

import threading
import socket
import json
import time
import uuid
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, urlunparse
from rich.console import Console

console = Console()

# We store captures in a simple in-memory list (also written to DB)
_captures: list[dict] = []
_captures_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════
#  Capture store
# ═══════════════════════════════════════════════════════════════════════════

def _store_capture(capture: dict):
    with _captures_lock:
        _captures.append(capture)
    # Persist to DB
    try:
        from storage.db import get_history_conn
        with get_history_conn() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS proxy_captures (
                    id TEXT PRIMARY KEY,
                    captured_at TEXT,
                    method TEXT,
                    url TEXT,
                    request_headers TEXT,
                    request_body TEXT,
                    response_status INTEGER,
                    response_headers TEXT,
                    response_body TEXT,
                    duration_ms REAL
                )"""
            )
            conn.execute(
                "INSERT OR REPLACE INTO proxy_captures VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    capture["id"],
                    capture["captured_at"],
                    capture["method"],
                    capture["url"],
                    json.dumps(capture.get("request_headers", {})),
                    capture.get("request_body", ""),
                    capture.get("response_status"),
                    json.dumps(capture.get("response_headers", {})),
                    capture.get("response_body", ""),
                    capture.get("duration_ms"),
                )
            )
    except Exception as e:
        console.print(f"  [dim]Proxy DB write error: {e}[/dim]")


# ═══════════════════════════════════════════════════════════════════════════
#  Proxy request handler
# ═══════════════════════════════════════════════════════════════════════════

class ProxyHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Suppress default HTTP server logging — we do our own
        pass

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunnelling."""
        host, port = self.path.split(":", 1)
        port = int(port)
        try:
            remote = socket.create_connection((host, port), timeout=15)
            self.send_response(200, "Connection Established")
            self.end_headers()

            # Tunnel bytes between client and remote
            self._tunnel(self.connection, remote)
        except Exception as e:
            self.send_error(502, str(e))

    def _tunnel(self, client, remote):
        client.setblocking(False)
        remote.setblocking(False)
        while True:
            try:
                data = client.recv(4096)
                if data:
                    remote.sendall(data)
            except BlockingIOError:
                pass
            except Exception:
                break
            try:
                data = remote.recv(4096)
                if data:
                    client.sendall(data)
            except BlockingIOError:
                pass
            except Exception:
                break

    def do_GET(self):    self._forward("GET")
    def do_POST(self):   self._forward("POST")
    def do_PUT(self):    self._forward("PUT")
    def do_PATCH(self):  self._forward("PATCH")
    def do_DELETE(self): self._forward("DELETE")
    def do_HEAD(self):   self._forward("HEAD")
    def do_OPTIONS(self): self._forward("OPTIONS")

    def _forward(self, method: str):
        import requests
        url     = self.path
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("proxy-connection", "connection")}

        length  = int(self.headers.get("Content-Length", 0))
        body    = self.rfile.read(length) if length else b""

        capture_id = str(uuid.uuid4())[:8]
        t0 = time.perf_counter()

        try:
            resp = requests.request(
                method, url,
                headers=headers,
                data=body,
                allow_redirects=False,
                timeout=15,
                verify=False,
            )
            duration_ms = (time.perf_counter() - t0) * 1000

            # Print to terminal
            console.print(
                f"  [dim]{capture_id}[/dim]  "
                f"[bold]{method}[/bold]  "
                f"[cyan]{resp.status_code}[/cyan]  "
                f"[dim]{duration_ms:.0f}ms[/dim]  {url[:80]}"
            )

            # Store capture
            _store_capture({
                "id":               capture_id,
                "captured_at":      datetime.utcnow().isoformat(),
                "method":           method,
                "url":              url,
                "request_headers":  dict(headers),
                "request_body":     body.decode(errors="replace"),
                "response_status":  resp.status_code,
                "response_headers": dict(resp.headers),
                "response_body":    resp.text[:4096],
                "duration_ms":      duration_ms,
            })

            # Forward response to client
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() not in ("transfer-encoding",):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)

        except Exception as e:
            self.send_error(502, str(e))


# ═══════════════════════════════════════════════════════════════════════════
#  PapisterProxy — start / replay
# ═══════════════════════════════════════════════════════════════════════════

class PapisterProxy:

    def __init__(self, port: int = 8787):
        self.port   = port
        self.server = HTTPServer(("127.0.0.1", port), ProxyHandler)

    def start(self):
        console.print(f"[cyan]🔌 Proxy running on 127.0.0.1:{self.port}[/cyan]")
        console.print("[dim]  Configure your HTTP client to use this proxy.[/dim]")
        console.print("[dim]  All requests will be logged. Ctrl+C to stop.[/dim]\n")
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[yellow]Proxy stopped.[/yellow]")
            self.server.shutdown()

    @staticmethod
    def replay(request_id: str):
        """Replay a captured request by ID."""
        import requests
        try:
            from storage.db import get_history_conn
            with get_history_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM proxy_captures WHERE id=?", (request_id,)
                ).fetchone()
        except Exception:
            row = None

        if not row:
            console.print(f"[red]Capture '{request_id}' not found.[/red]")
            return

        row = dict(row)
        headers = json.loads(row["request_headers"])
        console.print(f"[cyan]↻ Replaying:[/cyan] {row['method']} {row['url']}")

        resp = requests.request(
            row["method"], row["url"],
            headers=headers,
            data=row.get("request_body","").encode(),
            timeout=15,
            verify=False,
        )
        console.print(f"  Status: {resp.status_code}  Size: {len(resp.content)}b")
