"""integrations/stripe.py — Stripe Integration"""
from integrations.__base__ import BaseIntegration
from core import reporter


class StripeIntegration(BaseIntegration):
    NAME            = "stripe"
    SANDBOX_BASE    = "https://api.stripe.com/v1"
    PRODUCTION_BASE = "https://api.stripe.com/v1"

    def run(self):
        mode_label = "SANDBOX" if self.mode == "S" else "PRODUCTION"
        reporter.console.print(
            f"\n[cyan]🔌 Stripe — {mode_label}[/cyan]  {self.base_url}\n"
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
