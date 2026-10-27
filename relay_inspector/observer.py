"""Passive observations; only flow metadata, comments and opt-in reports change.

Reports deliberately replace *every* nonempty URL path segment. An opaque
identifier can look like an ordinary route name, so heuristics cannot guarantee
that arbitrary routes are free of credentials. Inspect full URLs in mitmweb or
in the original private capture instead.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from collections.abc import Callable, Collection
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit

from mitmproxy import http


logger = logging.getLogger(__name__)

_CREDENTIAL_QUERY_NAMES = frozenset(
    {
        "token", "accesstoken", "refreshtoken", "idtoken", "session", "sid",
        "sessionid", "sessiontoken", "auth", "authorization", "password",
        "passwd", "pwd", "apikey", "apiaccesskey", "secret", "clientsecret",
        "credential", "credentials", "jwt", "bearer", "csrftoken", "xsrftoken",
        "authkey", "authcode", "securitytoken", "hashsecret", "signature", "sig",
        "cookie", "cookies",
    }
)


def _normalized_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _path_template(path: str) -> str:
    """Retain bounded route structure, with no literal segment or query values."""
    path_only = path.partition("?")[0].partition("#")[0]
    segments = [segment for segment in path_only.split("/") if segment]
    template = "/" + "/".join("<segment>" for _ in segments[:12])
    if len(segments) > 12:
        template += "/<more>"
    return template


def _has_credential_query(path: str) -> bool:
    query = path.partition("?")[2].partition("#")[0]
    for parameter in query.split("&"):
        name = unquote_plus(parameter.partition("=")[0])
        normalized = re.sub(r"[^a-z0-9]", "", name.casefold())
        if normalized in _CREDENTIAL_QUERY_NAMES:
            return True
    return False


def _duration_ms(flow: http.HTTPFlow) -> float | None:
    start = flow.request.timestamp_start
    end = flow.response.timestamp_end if flow.response is not None else None
    if end is None and flow.error is not None:
        end = flow.error.timestamp
    if start is None or end is None:
        return None
    if not math.isfinite(start) or not math.isfinite(end) or end < start:
        return None
    return (end - start) * 1000


def summarize_flow(
    flow: http.HTTPFlow, baseline_hosts: Collection[str] = ()
) -> dict:
    """Return an allowlisted summary without touching any HTTP wire fields.

    Codes describe observable conditions. They do not establish an attack or
    make an authorization decision, and the baseline never restricts traffic.
    """
    request = flow.request
    response = flow.response
    host = _normalized_host(request.host)
    status = response.status_code if response is not None else None
    duration_ms = _duration_ms(flow)
    codes = []
    if status == 401:
        codes.append("HTTP_UNAUTHORIZED")
    elif status == 403:
        codes.append("HTTP_FORBIDDEN")
    elif status is not None and 500 <= status <= 599:
        codes.append("HTTP_SERVER_ERROR")
    if request.scheme.casefold() == "http":
        codes.append("CLEARTEXT_HTTP")
    if _has_credential_query(request.path):
        codes.append("CREDENTIAL_QUERY")
    baseline = {_normalized_host(candidate) for candidate in baseline_hosts}
    if baseline and host not in baseline:
        codes.append("HOST_OUTSIDE_BASELINE")
    if response is not None and 300 <= status <= 399:
        for location in response.headers.get_all("location"):
            try:
                destination_host = urlsplit(location).hostname
            except ValueError:
                continue
            if destination_host and _normalized_host(destination_host) != host:
                codes.append("EXTERNAL_REDIRECT")
                break
    if duration_ms is not None and duration_ms > 5000:
        codes.append("SLOW_RESPONSE")
    if flow.error is not None:
        codes.append("TRANSPORT_ERROR")
    return {
        "method": request.method,
        "host": host,
        "path": _path_template(request.path),
        "status": status,
        "duration_ms": round(duration_ms, 3) if duration_ms is not None else None,
        "codes": codes,
    }


class PassiveObserver:
    """mitmproxy-compatible hooks with no interception, filtering or rewriting."""

    def __init__(
        self,
        *,
        baseline_hosts: Callable[[], Collection[str]] = lambda: (),
        report_path: str | Path | None = None,
    ) -> None:
        self.baseline_hosts = baseline_hosts
        self.report_path = Path(report_path) if report_path else None

    def request(self, flow: http.HTTPFlow) -> None:
        self._observe(flow, completed=False)

    def response(self, flow: http.HTTPFlow) -> None:
        self._observe(flow, completed=True)

    def error(self, flow: http.HTTPFlow) -> None:
        self._observe(flow, completed=True)

    @staticmethod
    def _annotate(flow: http.HTTPFlow, codes: list[str]) -> dict:
        previous = flow.metadata.get("relay_inspector")
        metadata = previous if isinstance(previous, dict) else {}
        comment = flow.comment or ""
        previous_suffix = metadata.get("comment_suffix", "")
        if previous_suffix and comment.endswith(previous_suffix):
            comment = comment[: -len(previous_suffix)]
        suffix = ""
        if codes:
            suffix = ("\n" if comment else "") + f"[relay: {', '.join(codes)}]"
        flow.comment = comment + suffix
        metadata["codes"] = list(codes)
        metadata["comment_suffix"] = suffix
        flow.metadata["relay_inspector"] = metadata
        return metadata

    def _observe(self, flow: http.HTTPFlow, *, completed: bool) -> None:
        summary = summarize_flow(flow, self.baseline_hosts())
        metadata = self._annotate(flow, summary["codes"])
        if not completed or self.report_path is None:
            return
        completion = [
            flow.request.timestamp_start,
            flow.response.timestamp_end if flow.response is not None else None,
            flow.error.timestamp if flow.error is not None else None,
            summary["status"],
        ]
        if metadata.get("reported_completion") == completion:
            return
        try:
            self._append_report(summary)
        except OSError:
            # Neither exception messages nor paths are safe report/log inputs.
            logger.warning("Relay could not write its local observation report.")
            summary["codes"].append("REPORT_WRITE_FAILED")
            self._annotate(flow, summary["codes"])
        else:
            metadata["reported_completion"] = completion

    def _append_report(self, summary: dict) -> None:
        line = json.dumps(summary, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        descriptor = os.open(
            self.report_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        with os.fdopen(descriptor, "ab") as report:
            report.write(line.encode("utf-8") + b"\n")
