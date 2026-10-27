"""Registration of Relay's passive diagnostics with the native proxy engine."""

from pathlib import Path

from mitmproxy import ctx

from relay_inspector.har_import import observed_hosts
from relay_inspector.observer import PassiveObserver


class RelayAddon(PassiveObserver):
    def __init__(self) -> None:
        super().__init__(baseline_hosts=observed_hosts)

    def load(self, loader) -> None:
        loader.add_option(
            "relay_report_path",
            str,
            "",
            "Optional local JSONL report with redacted path templates and observation codes.",
        )

    def configure(self, updated: set[str]) -> None:
        if "relay_report_path" in updated:
            value = ctx.options.relay_report_path
            self.report_path = Path(value).expanduser() if value else None


addons = [RelayAddon()]
