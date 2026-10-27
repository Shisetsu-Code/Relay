"""Offline tests for the HAR compatibility adapter and native reader boundary."""

from __future__ import annotations

import json
import unittest
from io import BytesIO

import h11
from mitmproxy import io as mitm_io
from mitmproxy.addons.clientplayback import ClientPlayback
from mitmproxy.io import har as native_har
from mitmproxy.io import io as native_io
from mitmproxy.options import Options
from mitmproxy.proxy import commands
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.http._events import RequestData, RequestHeaders
from mitmproxy.proxy.layers.http._http1 import Http1Client

from relay_inspector import har_import


def entry() -> dict:
    return {
        "startedDateTime": "2026-10-27T12:00:00.000Z",
        "time": 25,
        "request": {
            "method": "GET",
            "url": "https://example.test/resource",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "bodySize": 0,
        },
        "response": {
            "status": 200,
            "statusText": "OK",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Length", "value": "2"}],
            "bodySize": 2,
            "content": {"size": 2, "mimeType": "text/plain", "text": "OK"},
        },
    }


def header(name: str, value: str) -> dict:
    return {"name": name, "value": value}


class HarImportTests(unittest.TestCase):
    def setUp(self) -> None:
        har_import.clear_observed_hosts()
        self.native_stream = native_io.FlowReader.stream

    def tearDown(self) -> None:
        har_import.clear_observed_hosts()
        native_io.FlowReader.stream = self.native_stream

    def assert_missing_request(self, source: dict) -> None:
        flow = har_import.request_to_flow(source)
        self.assertIsNone(flow.request.raw_content)
        self.assertIn("replay", flow.comment.lower())
        self.assertIsNotNone(ClientPlayback().check(flow))
        self.assertIn("harimport", flow.metadata)

    def test_binary_request_keeps_duplicate_header_order_and_encoded_query(self) -> None:
        source = entry()
        source["request"].update(
            method="PATCH",
            url="https://example.test:8443/p%2Fq?a=2&a=1&x=%2B&empty=&flag",
            bodySize=4,
            headers=[
                header("X-Trace", "first"),
                header("x-trace", "second"),
                header("Content-Type", "application/octet-stream"),
                header("Content-Length", "4"),
            ],
            postData={"mimeType": "application/octet-stream", "text": "AP8mCg==", "encoding": "base64"},
        )
        flow = har_import.request_to_flow(source)
        self.assertEqual(flow.request.raw_content, b"\x00\xff&\n")
        self.assertEqual(flow.request.path, "/p%2Fq?a=2&a=1&x=%2B&empty=&flag")
        self.assertEqual(flow.request.url, "https://example.test:8443/p%2Fq?a=2&a=1&x=%2B&empty=&flag")
        self.assertEqual(flow.request.method, "PATCH")
        self.assertEqual(
            flow.request.headers.fields,
            (
                (b"X-Trace", b"first"),
                (b"x-trace", b"second"),
                (b"Content-Type", b"application/octet-stream"),
                (b"Content-Length", b"4"),
            ),
        )
        self.assertIsNone(ClientPlayback().check(flow))

    def test_text_request_respects_declared_charset(self) -> None:
        source = entry()
        source["request"].update(
            method="POST", bodySize=4,
            headers=[header("Content-Type", 'text/plain; charset="iso-8859-1"'), header("Content-Length", "4")],
            postData={"mimeType": "text/plain", "text": "caf\u00e9"},
        )
        flow = har_import.request_to_flow(source)
        self.assertEqual(flow.request.raw_content, b"caf\xe9")
        self.assertEqual(flow.request.headers["Content-Type"], 'text/plain; charset="iso-8859-1"')

    def test_http2_pseudoheaders_use_native_fields_without_duplicate_emission(self) -> None:
        source = entry()
        source["request"].update(httpVersion="h2", headers=[
            header(":method", "GET"), header(":scheme", "https"),
            header(":authority", "example.test"), header(":path", "/resource"),
            header("x-trace", "one"), header("x-trace", "two"),
        ])
        flow = har_import.request_to_flow(source)
        self.assertTrue(flow.request.is_http2)
        self.assertEqual(flow.request.authority, "example.test")
        self.assertEqual(flow.request.headers.fields, ((b"x-trace", b"one"), (b"x-trace", b"two")))
        self.assertIsNone(ClientPlayback().check(flow))
        source["request"]["headers"][3]["value"] = "/different"
        self.assert_missing_request(source)

    def test_http2_binary_post_without_framing_gets_explicit_imported_length(self) -> None:
        source = entry()
        source["request"].update(
            method="POST", httpVersion="h2", bodySize=4,
            headers=[header("x-trace", "first"), header("x-trace", "second")],
            postData={"mimeType": "application/octet-stream", "text": "AP8mCg==", "encoding": "base64"},
        )
        flow = har_import.request_to_flow(source)
        self.assertTrue(flow.request.is_http2)
        self.assertEqual(flow.request.raw_content, b"\x00\xff&\n")
        self.assertEqual(flow.request.headers.fields, ((b"x-trace", b"first"), (b"x-trace", b"second"), (b"Content-Length", b"4")))
        self.assertIn("REQUEST_CONTENT_LENGTH_ADDED", flow.metadata["harimport"]["warnings"])

        # Exercise the pinned engine's real H2-to-H1 serializer and an
        # independent HTTP parser. Missing framing would produce EndOfMessage
        # instead of the expected binary Data event.
        context = Context(flow.client_conn, Options())
        context.server = flow.server_conn
        serializer = Http1Client(context)
        emitted = [
            *serializer.send(RequestHeaders(1, flow.request, end_stream=False)),
            *serializer.send(RequestData(1, flow.request.raw_content)),
        ]
        wire = b"".join(command.data for command in emitted if isinstance(command, commands.SendData))
        parser = h11.Connection(h11.SERVER)
        parser.receive_data(wire)
        request_event = parser.next_event()
        self.assertIsInstance(request_event, h11.Request)
        self.assertEqual(request_event.http_version, b"1.1")
        data_event = parser.next_event()
        self.assertIsInstance(data_event, h11.Data)
        self.assertEqual(data_event.data, b"\x00\xff&\n")

    def test_http_versions_match_native_message_protocol_properties(self) -> None:
        for version, attribute in [("HTTP/2", "is_http2"), ("HTTP/2.0", "is_http2"), ("h2", "is_http2"), ("HTTP/3", "is_http3"), ("HTTP/3.0", "is_http3"), ("h3", "is_http3")]:
            with self.subTest(version=version):
                source = entry()
                source["request"]["httpVersion"] = version
                source["response"]["httpVersion"] = version
                flow = har_import.request_to_flow(source)
                self.assertTrue(getattr(flow.request, attribute))
                self.assertTrue(getattr(flow.response, attribute))

    def test_trailing_empty_query_delimiter_is_preserved(self) -> None:
        source = entry()
        source["request"]["url"] = "https://example.test/resource?"
        self.assertEqual(har_import.request_to_flow(source).request.path, "/resource?")

    def test_text_defaults_to_utf8_and_uses_postdata_charset_when_header_absent(self) -> None:
        for mime, expected, size in [("text/plain", b"caf\xc3\xa9", 5), ("text/plain; charset=iso-8859-1", b"caf\xe9", 4)]:
            with self.subTest(mime=mime):
                source = entry()
                source["request"].update(method="POST", bodySize=size, postData={"mimeType": mime, "text": "caf\u00e9"})
                self.assertEqual(har_import.request_to_flow(source).request.raw_content, expected)

    def test_missing_nonempty_request_does_not_become_replayable_empty_body(self) -> None:
        source = entry()
        source["request"].update(method="POST", bodySize=14)
        self.assert_missing_request(source)

    def test_unknown_body_size_requires_evidence_before_assuming_empty(self) -> None:
        source = entry()
        source["request"].update(method="POST", bodySize=-1)
        self.assert_missing_request(source)
        source["request"]["headers"] = [header("Content-Length", "0")]
        self.assertEqual(har_import.request_to_flow(source).request.raw_content, b"")
        source["request"]["headers"].append(header("Transfer-Encoding", "chunked"))
        self.assert_missing_request(source)

    def test_parameter_only_postdata_does_not_reconstruct_form_or_file_bytes(self) -> None:
        for mime in ["application/x-www-form-urlencoded", "multipart/form-data; boundary=x"]:
            with self.subTest(mime=mime):
                source = entry()
                source["request"].update(method="POST", bodySize=6, postData={"mimeType": mime, "params": [{"name": "a", "value": "one two"}]})
                self.assert_missing_request(source)

    def test_incomplete_multipart_is_blocked_but_complete_body_is_preserved(self) -> None:
        source = entry()
        source["request"].update(
            method="POST", bodySize=-1,
            headers=[header("Content-Type", "multipart/form-data; boundary=x")],
            postData={"mimeType": "multipart/form-data", "text": '--x\r\nContent-Disposition: form-data; name="a"\r\n\r\nvalue\r\n'},
        )
        self.assert_missing_request(source)
        source["request"]["postData"]["text"] += "--x--\r\n"
        flow = har_import.request_to_flow(source)
        self.assertEqual(flow.request.raw_content, b'--x\r\nContent-Disposition: form-data; name="a"\r\n\r\nvalue\r\n--x--\r\n')
        self.assertIsNone(ClientPlayback().check(flow))

    def test_compressed_request_is_not_guessed_or_decompressed(self) -> None:
        source = entry()
        source["request"].update(method="POST", bodySize=-1, headers=[header("Content-Encoding", "gzip")], postData={"mimeType": "text/plain", "text": "decoded text"})
        self.assert_missing_request(source)
        flow = har_import.request_to_flow(source)
        self.assertEqual(flow.request.headers["Content-Encoding"], "gzip")

    def test_invalid_body_encodings_are_not_replayed_as_text(self) -> None:
        for postdata in [
            {"mimeType": "application/octet-stream", "text": "%%%", "encoding": "base64"},
            {"mimeType": "text/plain", "text": "abc", "encoding": "rot13"},
            {"mimeType": "text/plain; charset=not-a-charset", "text": "abc"},
            {"mimeType": "text/plain; charset=ascii", "text": "\u00e9"},
        ]:
            with self.subTest(postdata=postdata):
                source = entry()
                source["request"].update(method="POST", bodySize=-1, postData=postdata)
                self.assert_missing_request(source)

    def test_truncated_and_conflicting_request_lengths_block_replay(self) -> None:
        for body_size, headers in [
            (8, []),
            (-1, [header("Content-Length", "8")]),
            (-1, [header("Content-Length", "3"), header("Content-Length", "4")]),
        ]:
            with self.subTest(body_size=body_size, headers=headers):
                source = entry()
                source["request"].update(method="POST", bodySize=body_size, headers=headers, postData={"mimeType": "text/plain", "text": "abc"})
                self.assert_missing_request(source)

    def test_historical_decoded_response_is_labelled_and_framed_consistently(self) -> None:
        source = entry()
        source["response"].update(
            headers=[header("Content-Encoding", "gzip"), header("Content-Length", "30"), header("Set-Cookie", "a=1"), header("Set-Cookie", "b=2")],
            bodySize=30,
            content={"size": 3, "mimeType": "text/plain", "text": "h\u00e9"},
        )
        flow = har_import.request_to_flow(source)
        self.assertEqual(flow.response.raw_content, b"h\xc3\xa9")
        self.assertNotIn("Content-Encoding", flow.response.headers)
        self.assertEqual(flow.response.headers["Content-Length"], "3")
        self.assertEqual(flow.response.headers.get_all("Set-Cookie"), ["a=1", "b=2"])
        self.assertTrue(flow.metadata["harimport"]["warnings"])

    def test_binary_response_decodes_base64_without_text_roundtrip(self) -> None:
        source = entry()
        source["response"].update(headers=[], bodySize=4, content={"size": 4, "mimeType": "application/octet-stream", "text": "AP8mCg==", "encoding": "base64"})
        self.assertEqual(har_import.request_to_flow(source).response.raw_content, b"\x00\xff&\n")

    def test_omitted_response_content_is_distinct_from_empty_content(self) -> None:
        source = entry()
        source["response"]["content"] = {"size": 20, "mimeType": "image/png"}
        self.assertIsNone(har_import.request_to_flow(source).response.raw_content)
        source["response"]["content"] = {"size": 0, "mimeType": "text/plain", "text": ""}
        source["response"]["headers"] = []
        self.assertEqual(har_import.request_to_flow(source).response.raw_content, b"")

    def test_absent_response_text_with_positive_length_is_not_an_empty_body(self) -> None:
        source = entry()
        source["response"]["content"] = {"size": 0, "mimeType": "image/png"}
        self.assertIsNone(har_import.request_to_flow(source).response.raw_content)

    def test_websocket_har_entries_are_inspectable_without_replaying_handshake(self) -> None:
        source = entry()
        source["request"]["url"] = "wss://example.test/socket?x=%2B"
        source["response"].update(status=101, statusText="Switching Protocols", headers=[], content={"size": 0})
        flow = har_import.request_to_flow(source)
        self.assertEqual(flow.request.scheme, "wss")
        self.assertEqual(flow.request.port, 443)
        self.assertEqual(flow.request.path, "/socket?x=%2B")
        self.assertIsNone(flow.request.raw_content)
        self.assertIsNotNone(ClientPlayback().check(flow))
        self.assertEqual(flow.response.status_code, 101)

    def test_status_zero_and_missing_response_do_not_invent_success(self) -> None:
        for response in [{"status": 0, "statusText": "", "headers": [], "content": {}}, None]:
            with self.subTest(response=response):
                source = entry()
                source["response"] = response
                flow = har_import.request_to_flow(source)
                self.assertIsNone(flow.response)
                self.assertIsNotNone(flow.error)

    def test_minimal_incomplete_har_entry_remains_inspectable(self) -> None:
        flow = har_import.request_to_flow({"request": {"method": "POST", "url": "https://example.test/incomplete", "bodySize": 9}})
        self.assertEqual(flow.request.path, "/incomplete")
        self.assertIsNone(flow.request.raw_content)
        self.assertIsNone(flow.response)
        self.assertTrue(flow.metadata["harimport"]["warnings"])

    def test_only_imported_hosts_populate_normalized_baseline(self) -> None:
        self.assertEqual(har_import.observed_hosts(), frozenset())
        source = entry()
        source["request"]["url"] = "https://EXAMPLE.test.:8443/resource"
        har_import.request_to_flow(source)
        source["request"]["url"] = "https://second.test/resource"
        har_import.request_to_flow(source)
        self.assertEqual(har_import.observed_hosts(), frozenset({"example.test", "second.test"}))
        har_import.clear_observed_hosts()
        self.assertEqual(har_import.observed_hosts(), frozenset())

    def test_native_reader_uses_adapter_after_repeated_installation(self) -> None:
        old_har = native_har.request_to_flow
        old_io = native_io.request_to_flow
        try:
            har_import.install_har_reader()
            har_import.install_har_reader()
            source = entry()
            source["request"].update(method="POST", bodySize=4, postData={"mimeType": "application/octet-stream", "text": "AP8mCg==", "encoding": "base64"})
            raw = json.dumps({"log": {"version": "1.2", "entries": [source]}}).encode("utf-8")
            flows = list(mitm_io.FlowReader(BytesIO(raw)).stream())
            self.assertEqual(len(flows), 1)
            self.assertEqual(flows[0].request.raw_content, b"\x00\xff&\n")
            self.assertEqual(native_har.request_to_flow(source).request.raw_content, b"\x00\xff&\n")
            self.assertEqual(har_import.observed_hosts(), frozenset({"example.test"}))
        finally:
            native_har.request_to_flow = old_har
            native_io.request_to_flow = old_io

    def test_reader_skips_only_known_non_network_schemes_and_reports_safe_counts(self) -> None:
        old_har, old_io = native_har.request_to_flow, native_io.request_to_flow
        try:
            sources = [entry()]
            for url in [
                "data:text/plain,PRIVATE_EMBEDDED_VALUE",
                "blob:https://example.test/PRIVATE_BLOB_ID",
                "file:///PRIVATE_LOCAL_PATH",
                "about:blank",
            ]:
                source = entry()
                source["request"]["url"] = url
                sources.append(source)
            final = entry()
            final["request"]["url"] = "https://second.test/after"
            sources.append(final)
            har_import.install_har_reader()
            har_import.install_har_reader()
            raw = json.dumps({"log": {"entries": sources}}).encode()
            with self.assertLogs("relay_inspector.har_import", level="WARNING") as captured:
                flows = list(mitm_io.FlowReader(BytesIO(raw)).stream())
            self.assertEqual([flow.request.host for flow in flows], ["example.test", "second.test"])
            self.assertEqual(har_import.observed_hosts(), frozenset({"example.test", "second.test"}))
            self.assertEqual(har_import.last_import_summary(), {
                "entries": 6, "imported": 2, "skipped": {"data": 1, "blob": 1, "file": 1, "about": 1},
            })
            self.assertNotIn("PRIVATE_", " ".join(captured.output))
            self.assertNotIn("example.test", " ".join(captured.output))
        finally:
            native_har.request_to_flow, native_io.request_to_flow = old_har, old_io

    def test_native_mitm_dump_is_not_treated_as_har_or_rewritten(self) -> None:
        old_har, old_io = native_har.request_to_flow, native_io.request_to_flow
        try:
            source = entry()
            original = har_import.request_to_flow(source)
            original.metadata.clear()
            original.comment = "original comment"
            original.request.headers.add("X-Trace", "first")
            original.request.headers.add("X-Trace", "second")
            buffer = BytesIO()
            mitm_io.FlowWriter(buffer).add(original)
            har_import.clear_observed_hosts()
            har_import.install_har_reader()
            recovered = list(mitm_io.FlowReader(BytesIO(buffer.getvalue())).stream())
            self.assertEqual(len(recovered), 1)
            self.assertEqual(recovered[0].get_state(), original.get_state())
            self.assertEqual(har_import.observed_hosts(), frozenset())
        finally:
            native_har.request_to_flow, native_io.request_to_flow = old_har, old_io


if __name__ == "__main__":
    unittest.main()
