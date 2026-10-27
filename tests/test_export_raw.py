"""Offline export contracts: compressed bytes, duplicates and missing bodies."""

import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import PropertyMock, patch

from mitmproxy import http, io as flow_io
from mitmproxy.test import tflow

from relay_inspector.export_raw import export_capture, main


def captured_flow():
    request = http.Request.make(
        "POST", "https://ganamos.example/play?token=local-secret", b"\x00\xffrequest"
    )
    request.headers = http.Headers(
        [(b"Cookie", b"a=one"), (b"Cookie", b"b=two"), (b"X-Raw", b"\xff")]
    )
    response = http.Response.make(200)
    response.headers = http.Headers(
        [(b"Content-Encoding", b"gzip"), (b"Set-Cookie", b"a=one"), (b"Set-Cookie", b"b=two")]
    )
    response.raw_content = gzip.compress(b"{\"binary\":\"body\"}", mtime=0)
    return tflow.tflow(req=request, resp=response)


def write_capture(path, flows):
    with path.open("wb") as output:
        writer = flow_io.FlowWriter(output)
        for flow in flows:
            writer.add(flow)


def decode_headers(header_records):
    return [
        (base64.b64decode(record["name_base64"]), base64.b64decode(record["value_base64"]))
        for record in header_records
    ]


class RawExportTests(unittest.TestCase):
    def test_export_selected_id_retains_binary_and_gzip_without_decoding(self):
        first = captured_flow()
        selected = captured_flow()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "traffic.mitm"
            destination = root / "selected"
            write_capture(capture, [first, selected])
            with patch.object(http.Message, "content", new_callable=PropertyMock) as decoded:
                decoded.side_effect = AssertionError("Export must not access decoded content")
                manifest_path = export_capture(capture, destination, flow_id=selected.id)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual((destination / "request.bin").read_bytes(), b"\x00\xffrequest")
            self.assertEqual((destination / "response.bin").read_bytes(), selected.response.raw_content)
            self.assertEqual(manifest["flow_id"], selected.id)
            self.assertEqual(manifest["capture_index"], 1)
            self.assertEqual(manifest["request"]["method"], "POST")
            self.assertEqual(manifest["request"]["url"], "https://ganamos.example/play?token=local-secret")
            self.assertEqual(manifest["response"]["status_code"], 200)
            self.assertEqual(decode_headers(manifest["request"]["headers"]), list(selected.request.headers.fields))
            self.assertEqual(decode_headers(manifest["response"]["headers"]), list(selected.response.headers.fields))
            self.assertEqual(
                manifest["response"]["body"]["sha256"],
                hashlib.sha256(selected.response.raw_content).hexdigest(),
            )
            self.assertEqual(manifest["response"]["body"]["length"], len(selected.response.raw_content))
            if os.name != "nt":
                for name in ("request.bin", "response.bin", "manifest.json"):
                    self.assertEqual((destination / name).stat().st_mode & 0o777, 0o600)

    def test_index_is_zero_based_and_selects_one_flow(self):
        first, second = captured_flow(), captured_flow()
        second.request.raw_content = b"second"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_capture(root / "traffic.mitm", [first, second])
            manifest_path = export_capture(root / "traffic.mitm", root / "export", index=1)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["flow_id"], second.id)
            self.assertEqual((root / "export" / "request.bin").read_bytes(), b"second")

    def test_unavailable_bodies_are_distinct_from_empty_bodies(self):
        flow = captured_flow()
        flow.request.raw_content = None
        flow.response.raw_content = b""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_capture(root / "traffic.mitm", [flow])
            manifest = json.loads(
                export_capture(root / "traffic.mitm", root / "export", index=0).read_text()
            )
            self.assertFalse((root / "export" / "request.bin").exists())
            self.assertEqual((root / "export" / "response.bin").read_bytes(), b"")
            self.assertFalse(manifest["request"]["body"]["available"])
            self.assertIsNone(manifest["request"]["body"]["sha256"])
            self.assertTrue(manifest["response"]["body"]["available"])
            self.assertEqual(
                manifest["response"]["body"]["sha256"],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )

    def test_missing_response_is_reported_without_inventing_a_body(self):
        flow = captured_flow()
        flow.response = None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_capture(root / "traffic.mitm", [flow])
            manifest = json.loads(
                export_capture(root / "traffic.mitm", root / "export", index=0).read_text()
            )
            self.assertIsNone(manifest["response"])
            self.assertFalse((root / "export" / "response.bin").exists())

    def test_existing_export_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_capture(root / "traffic.mitm", [captured_flow()])
            destination = root / "export"
            destination.mkdir()
            (destination / "request.bin").write_bytes(b"previous export")
            with self.assertRaises(FileExistsError):
                export_capture(root / "traffic.mitm", destination, index=0)
            self.assertEqual((destination / "request.bin").read_bytes(), b"previous export")
            self.assertEqual({path.name for path in destination.iterdir()}, {"request.bin"})

    def test_cli_exports_offline_without_printing_private_url(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_capture(root / "traffic.mitm", [captured_flow()])
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = main([str(root / "traffic.mitm"), "--index", "0", "--output", str(root / "export")])
            self.assertEqual(result, 0)
            self.assertTrue((root / "export" / "manifest.json").exists())
            self.assertNotIn("local-secret", stdout.getvalue() + stderr.getvalue())

    def test_invalid_capture_errors_do_not_disclose_capture_data(self):
        for payload in (
            b"private-auth-token:broken-capture",
            b'{"log":{"entries":[]},"secret":"private-auth-token"}',
        ):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "capture.mitm").write_bytes(payload)
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = main([str(root / "capture.mitm"), "--index", "0", "--output", str(root / "export")])
                self.assertEqual(result, 2)
                self.assertNotIn("private-auth-token", stdout.getvalue() + stderr.getvalue())
                self.assertFalse((root / "export").exists())

    def test_missing_selection_and_non_http_selection_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_capture(root / "traffic.mitm", [tflow.ttcpflow()])
            with self.assertRaises(ValueError):
                export_capture(root / "traffic.mitm", root / "missing", index=5)
            with self.assertRaises(ValueError):
                export_capture(root / "traffic.mitm", root / "tcp", index=0)
            self.assertFalse((root / "missing").exists())
            self.assertFalse((root / "tcp").exists())


if __name__ == "__main__":
    unittest.main()
