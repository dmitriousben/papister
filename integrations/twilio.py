"""integrations/twilio.py — Twilio Integration"""
from integrations.__base__ import BaseIntegration
from core import reporter


class TwilioIntegration(BaseIntegration):
    NAME            = "twilio"
    SANDBOX_BASE    = "https://api.twilio.com/2010-04-01"
    PRODUCTION_BASE = "https://api.twilio.com/2010-04-01"

    def run(self):
        mode_label = "SANDBOX" if self.mode == "S" else "PRODUCTION"
        reporter.console.print(
            f"\n[cyan]🔌 Twilio — {mode_label}[/cyan]  {self.base_url}\n"
        )
        reporter.console.print(
            "  [dim]Stub integration — add your endpoint tests below.[/dim]\n"
        )
        reporter.console.print(
            "  Example:\n"
            "  [dim]r = self._get('/v1/user')\n"
            "  from core.detector import classify\n"
            "  classify(r)\n"
            "  reporter.print_result(r)[/dim]"
        )
