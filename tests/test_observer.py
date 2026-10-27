"""Behavioral checks for diagnostics that must never rewrite traffic."""

import copy
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from mitmproxy import flow as flow_module, http
from mitmproxy.test import tflow

from relay_inspector.observer import PassiveObserver, summarize_flow


def make_flow(url="https://ganamos.example/api/play", status=200):
    request = http.Request.make("POST", url, b"\x00request\xff")
    request.timestamp_start = 10.0
    response = http.Response.make(status, b"\x00response\xfe")
    response.timestamp_end = 11.0
    return tflow.tflow(req=request, resp=response)


class ObserverTests(unittest.TestCase):
    def test_report_and_annotations_preserve_wire_fields(self):
        """Removing any redaction or rewriting a wire field breaks this contract."""
        flow = make_flow(
            "http://ganamos.example/api/private-path-secret/play"
            "?access_token=query-secret&amount=75#fragment-secret",
            403,
        )
        flow.request.headers = http.Headers(
            [
                (b"Authorization", b"Bearer auth-secret"),
                (b"Cookie", b"session=cookie-secret"),
                (b"X-Duplicate", b"one"),
                (b"X-Duplicate", b"two"),
            ]
        )
        flow.request.raw_content = b"\x00body-secret\xff"
        flow.response.headers = http.Headers(
            [
                (b"Set-Cookie", b"a=response-cookie-secret"),
                (b"Set-Cookie", b"b=other-response-cookie"),
                (b"Content-Encoding", b"gzip"),
            ]
        )
        flow.response.raw_content = gzip.compress(b"response-body-secret", mtime=0)
        flow.response.timestamp_end = 16.25
        flow.comment = "HAR imported: request body retained."
        flow.metadata["harimport"] = {"warnings": ["original warning"]}
        original_request = copy.deepcopy(flow.request.get_state())
        original_response = copy.deepcopy(flow.response.get_state())
        original_import = copy.deepcopy(flow.metadata["harimport"])

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.jsonl"
            observer = PassiveObserver(
                baseline_hosts=lambda: {"ganamos.example"}, report_path=report
            )
            observer.response(flow)
            text = report.read_text(encoding="utf-8")
            row = json.loads(text)

        self.assertEqual(flow.request.get_state(), original_request)
        self.assertEqual(flow.response.get_state(), original_response)
        self.assertEqual(flow.metadata["harimport"], original_import)
        self.assertIn("HAR imported: request body retained.", flow.comment)
        self.assertIn("HTTP_FORBIDDEN", flow.comment)
        self.assertEqual(
            set(row), {"method", "host", "path", "status", "duration_ms", "codes"}
        )
        self.assertEqual(row["method"], "POST")
        self.assertEqual(row["host"], "ganamos.example")
        self.assertEqual(row["path"], "/<segment>/<segment>/<segment>")
        self.assertEqual(row["status"], 403)
        self.assertEqual(row["duration_ms"], 6250.0)
        self.assertEqual(
            set(row["codes"]),
            {"HTTP_FORBIDDEN", "CLEARTEXT_HTTP", "CREDENTIAL_QUERY", "SLOW_RESPONSE"},
        )
        for secret in (
            "private-path-secret", "query-secret", "fragment-secret", "auth-secret",
            "cookie-secret", "body-secret", "response-cookie-secret", "amount=75",
        ):
            self.assertNotIn(secret, text)

    def test_http_statuses_have_specific_observation_codes(self):
        for status, expected in (
            (200, set()), (400, set()), (401, {"HTTP_UNAUTHORIZED"}),
            (403, {"HTTP_FORBIDDEN"}), (500, {"HTTP_SERVER_ERROR"}),
            (599, {"HTTP_SERVER_ERROR"}),
        ):
            with self.subTest(status=status):
                self.assertEqual(set(summarize_flow(make_flow(status=status))["codes"]), expected)

    def test_baseline_is_dynamic_and_empty_baseline_is_not_an_alarm(self):
        baseline = set()
        observer = PassiveObserver(baseline_hosts=lambda: baseline)
        first = make_flow()
        observer.request(first)
        self.assertNotIn("HOST_OUTSIDE_BASELINE", first.comment)
        baseline.add("OTHER.example.")
        second = make_flow()
        observer.request(second)
        self.assertIn("HOST_OUTSIDE_BASELINE", second.comment)
        third = make_flow("https://other.example/play")
        observer.request(third)
        self.assertNotIn("HOST_OUTSIDE_BASELINE", third.comment)

    def test_query_names_are_checked_without_recording_names_or_values(self):
        for key in ("token", "access-token", "sessionId", "api_key", "Password", "jwt"):
            with self.subTest(key=key):
                summary = summarize_flow(make_flow(f"https://ganamos.example/?{key}=hidden"))
                self.assertIn("CREDENTIAL_QUERY", summary["codes"])
                self.assertNotIn("hidden", json.dumps(summary))
        self.assertNotIn(
            "CREDENTIAL_QUERY",
            summarize_flow(make_flow("https://ganamos.example/?amount=75"))["codes"],
        )

    def test_redirects_compare_destination_hosts_and_ignore_relative_locations(self):
        for status, location, expected in (
            (302, "https://external.example/callback?token=secret", True),
            (307, "//external.example/callback", True),
            (301, "https://GANAMOS.example.:444/new", False),
            (302, "/new?session=secret", False),
            (200, "https://external.example/", False),
            (302, "https://[invalid", False),
        ):
            with self.subTest(status=status, location=location):
                flow = make_flow(status=status)
                flow.response.headers["Location"] = location
                self.assertEqual(
                    "EXTERNAL_REDIRECT" in summarize_flow(flow)["codes"], expected
                )

    def test_slow_response_threshold_and_missing_or_invalid_timestamps(self):
        for end, expected_ms, slow in (
            (15.0, 5000.0, False), (15.001, 5001.0, True),
            (15.0000001, 5000.0, True),
            (None, None, False), (9.0, None, False), (float("inf"), None, False),
        ):
            with self.subTest(end=end):
                flow = make_flow()
                flow.response.timestamp_end = end
                summary = summarize_flow(flow)
                self.assertEqual(summary["duration_ms"], expected_ms)
                self.assertEqual("SLOW_RESPONSE" in summary["codes"], slow)

    def test_error_messages_never_enter_the_report(self):
        flow = make_flow("https://ganamos.example/session/path-secret?token=query-secret")
        flow.response = None
        flow.error = flow_module.Error(
            "Authorization: Bearer auth-secret https://ganamos.example/?token=query-secret",
            timestamp=16.0,
        )
        request_before = copy.deepcopy(flow.request.get_state())
        error_before = copy.deepcopy(flow.error.get_state())
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "observations.jsonl"
            PassiveObserver(report_path=report).error(flow)
            text = report.read_text(encoding="utf-8")
        self.assertIn("TRANSPORT_ERROR", json.loads(text)["codes"])
        self.assertEqual(json.loads(text)["duration_ms"], 6000.0)
        self.assertEqual(flow.request.get_state(), request_before)
        self.assertEqual(flow.error.get_state(), error_before)
        for secret in ("auth-secret", "path-secret", "query-secret", "Authorization"):
            self.assertNotIn(secret, text)

    def test_report_is_opt_in_and_comment_annotations_are_idempotent(self):
        flow = make_flow(status=401)
        flow.comment = "Existing imported comment."
        with tempfile.TemporaryDirectory() as directory:
            observer = PassiveObserver()
            observer.response(flow)
            observer.response(flow)
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(flow.comment.count("[relay:"), 1)
        self.assertIn("Existing imported comment.", flow.comment)
        flow.response.status_code = 200
        observer.response(flow)
        self.assertEqual(flow.comment, "Existing imported comment.")

    def test_same_completion_is_written_once_but_new_completion_is_reported(self):
        flow = make_flow(status=401)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "observations.jsonl"
            observer = PassiveObserver(report_path=report)
            observer.response(flow)
            observer.response(flow)
            flow.request.timestamp_start = 20.0
            flow.response.timestamp_end = 21.0
            observer.response(flow)
            self.assertEqual(len(report.read_text(encoding="utf-8").splitlines()), 2)

    def test_report_write_failure_does_not_block_or_expose_the_private_path(self):
        flow = make_flow()
        request_before = copy.deepcopy(flow.request.get_state())
        with tempfile.TemporaryDirectory() as directory:
            impossible = Path(directory) / "credential-secret"
            impossible.mkdir()
            observer = PassiveObserver(report_path=impossible)
            with self.assertLogs("relay_inspector.observer", level="WARNING") as logs:
                observer.response(flow)
        self.assertEqual(flow.request.get_state(), request_before)
        self.assertIn("REPORT_WRITE_FAILED", flow.comment)
        self.assertNotIn("credential-secret", " ".join(logs.output))

    def test_registered_addon_option_enables_and_disables_the_report(self):
        from mitmproxy.test import taddons
        from relay_inspector.addon import RelayAddon

        addon = RelayAddon()
        with tempfile.TemporaryDirectory() as directory, taddons.context(addon) as context:
            report = Path(directory) / "configured.jsonl"
            self.assertEqual(context.options.relay_report_path, "")
            context.configure(addon, relay_report_path=str(report))
            addon.response(make_flow(status=403))
            rows = report.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(rows), 1)
            self.assertIn("HTTP_FORBIDDEN", json.loads(rows[0])["codes"])
            context.configure(addon, relay_report_path="")
            addon.response(make_flow(status=500))
            self.assertEqual(report.read_text(encoding="utf-8").splitlines(), rows)


if __name__ == "__main__":
    unittest.main()
