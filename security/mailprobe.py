"""
security/mailprobe.py — Mail Protocol Prober
=============================================
Probes POP3, IMAP, SMTP endpoints via TCP.
Sends protocol-native commands and reads banners/capabilities.
Useful for testing mail API gateways, telecom email bridges, ISP services.

Detects:
  POP3  (port 110 / 995 TLS) — CAPA, USER, APOP
  IMAP  (port 143 / 993 TLS) — CAPABILITY, LOGIN
  SMTP  (port 25 / 587 / 465) — EHLO, STARTTLS support
"""

import socket
import ssl
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

PROTOCOL_PORTS = {
    "pop3":  [110, 995],
    "imap":  [143, 993],
    "smtp":  [25, 587, 465],
}


@dataclass
class MailProbeResult:
    host:       str
    protocols:  list[dict] = field(default_factory=list)
    # Each dict: {protocol, port, tls, banner, capabilities, auth_methods, open}


class MailProber:

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def probe(self, host: str, port: int | None = None) -> MailProbeResult:
        result = MailProbeResult(host=host)
        console.print(f"\n[cyan]📬 Mail probe:[/cyan] {host}\n")

        if port:
            # Single port — auto-detect protocol
            proto = self._guess_protocol(port)
            findings = self._probe_port(host, port, proto)
            if findings:
                result.protocols.append(findings)
        else:
            # Probe all common mail ports
            for proto, ports in PROTOCOL_PORTS.items():
                for p in ports:
                    console.print(f"  [dim]Probing {proto.upper()} on port {p}…[/dim]")
                    findings = self._probe_port(host, p, proto)
                    if findings:
                        result.protocols.append(findings)

        return result

    def _probe_port(self, host: str, port: int, proto: str) -> dict | None:
        use_tls = port in (995, 993, 465)
        try:
            raw_sock = socket.create_connection((host, port), timeout=self.timeout)
            if use_tls:
                ctx  = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            else:
                sock = raw_sock

            info: dict = {
                "protocol": proto.upper(),
                "port":     port,
                "tls":      use_tls,
                "open":     True,
                "banner":   "",
                "capabilities": [],
                "auth_methods": [],
            }

            # Read banner
            banner = sock.recv(1024).decode(errors="replace").strip()
            info["banner"] = banner
            console.print(f"    [green]✓ {proto.upper()}:{port}[/green]  {banner[:80]}")

            # Send capability command
            if proto == "pop3":
                sock.sendall(b"CAPA\r\n")
                caps = sock.recv(2048).decode(errors="replace")
                info["capabilities"] = [l.strip() for l in caps.splitlines() if l.strip() and not l.startswith(("+","-","."))]
                # Auth methods
                sock.sendall(b"AUTH\r\n")
                auth_resp = sock.recv(512).decode(errors="replace")
                info["auth_methods"] = [l.strip() for l in auth_resp.splitlines() if l.strip() and not l.startswith(("+","-","."))]

            elif proto == "imap":
                sock.sendall(b"A001 CAPABILITY\r\n")
                caps = sock.recv(2048).decode(errors="replace")
                info["capabilities"] = caps.split()

            elif proto == "smtp":
                sock.sendall(f"EHLO papister-probe\r\n".encode())
                ehlo = sock.recv(2048).decode(errors="replace")
                info["capabilities"] = [l[4:].strip() for l in ehlo.splitlines() if l.startswith("250-") or l.startswith("250 ")]
                info["starttls"] = "STARTTLS" in ehlo.upper()

            sock.close()
            return info

        except (ConnectionRefusedError, socket.timeout, OSError):
            return None
        except Exception as e:
            console.print(f"    [dim]Port {port} error: {e}[/dim]")
            return None

    def _guess_protocol(self, port: int) -> str:
        for proto, ports in PROTOCOL_PORTS.items():
            if port in ports:
                return proto
        return "unknown"

    def print_result(self, result: MailProbeResult):
        if not result.protocols:
            console.print(f"\n[green]✓ No open mail ports found on {result.host}[/green]")
            return

        console.print(f"\n[bold yellow]📬 {len(result.protocols)} mail service(s) found on {result.host}:[/bold yellow]\n")
        for p in result.protocols:
            tls_tag = "[green]TLS[/green]" if p["tls"] else "[yellow]PLAIN[/yellow]"
            console.print(f"  [bold]{p['protocol']}[/bold] :{p['port']}  {tls_tag}")
            console.print(f"    Banner : {p.get('banner','')[:100]}")
            if p.get("capabilities"):
                console.print(f"    Caps   : {', '.join(p['capabilities'][:8])}")
            if p.get("auth_methods"):
                console.print(f"    Auth   : {', '.join(p['auth_methods'])}")
            console.print()
