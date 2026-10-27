"""Conservative, offline HAR import for mitmproxy 12.3.1.

HAR stores application messages, not wire captures. Missing request bytes remain
``None``, which mitmproxy's native client replay rejects. This adapter is used
only by file readers; it never changes a live request or opens a connection.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import math
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from email.message import Message
from urllib.parse import urlsplit

from mitmproxy import connection, exceptions, flow as flow_module, http, version
from mitmproxy.io import io as native_io

logger = logging.getLogger(__name__)
_observed_hosts: set[str] = set()
_METHOD = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_NON_NETWORK_SCHEMES = frozenset({"data", "blob", "file", "about"})
_native_flow_reader_stream = native_io.FlowReader.stream
_last_import_summary: dict = {"entries": 0, "imported": 0, "skipped": {}}


def observed_hosts() -> frozenset[str]:
    """Hosts observed in imported HAR entries, never learned from live traffic."""
    return frozenset(_observed_hosts)


def clear_observed_hosts() -> None:
    """Start a fresh HAR baseline, including between independent test sessions."""
    _observed_hosts.clear()


def last_import_summary() -> dict:
    """Return counts for the latest HAR read, without URLs, headers or bodies.

    Non-network data/blob/file/about resources remain in the original HAR.
    They cannot be represented as native HTTP flows without inventing a server.
    Native .mitm reads leave this HAR-specific summary unchanged.
    """
    return {
        "entries": _last_import_summary["entries"],
        "imported": _last_import_summary["imported"],
        "skipped": dict(_last_import_summary["skipped"]),
    }


def _warn(warnings: list[str], code: str) -> None:
    if code not in warnings:
        warnings.append(code)


def _headers(values: object) -> http.Headers:
    if values is None:
        return http.Headers()
    if not isinstance(values, list):
        raise ValueError("HAR headers must be a list of name/value pairs")
    fields: list[tuple[bytes, bytes]] = []
    for item in values:
        if isinstance(item, dict):
            name, value = item.get("name"), item.get("value")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            name, value = item
        else:
            raise ValueError("HAR header is not a name/value pair")
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("HAR header names and values must be text")
        if not name or any(c in name + value for c in "\r\n\x00"):
            raise ValueError("HAR header contains invalid characters")
        fields.append(
            (
                name.encode("utf-8", "surrogateescape"),
                value.encode("utf-8", "surrogateescape"),
            )
        )
    return http.Headers(fields)


def _separate_pseudoheaders(
    headers: http.Headers, warnings: list[str]
) -> tuple[dict[bytes, bytes], http.Headers]:
    pseudo: dict[bytes, bytes] = {}
    regular: list[tuple[bytes, bytes]] = []
    for name, value in headers.fields:
        if name.startswith(b":"):
            key = name.lower()
            if key in pseudo:
                _warn(warnings, "DUPLICATE_PSEUDOHEADER")
            pseudo[key] = value
        else:
            regular.append((name, value))
    if pseudo:
        _warn(warnings, "PSEUDOHEADERS_MAPPED_TO_MESSAGE_FIELDS")
    return pseudo, http.Headers(regular)


def _http_version(value: object, warnings: list[str]) -> bytes:
    versions = {
        "HTTP/1.0": b"HTTP/1.0",
        "HTTP/1.1": b"HTTP/1.1",
        "HTTP/2": b"HTTP/2.0",
        "HTTP/2.0": b"HTTP/2.0",
        "H2": b"HTTP/2.0",
        "HTTP/3": b"HTTP/3",
        "HTTP/3.0": b"HTTP/3",
        "H3": b"HTTP/3",
    }
    result = versions.get(value.upper() if isinstance(value, str) else "")
    if result is None:
        _warn(warnings, "HTTP_VERSION_UNAVAILABLE_ASSUMED_HTTP1")
        return b"HTTP/1.1"
    return result


def _timestamps(entry: dict, warnings: list[str]) -> tuple[float, float | None]:
    try:
        started = datetime.fromisoformat(entry["startedDateTime"].replace("Z", "+00:00"))
        if started.tzinfo is None:
            raise ValueError("Missing timezone")
        start = started.timestamp()
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        # A deterministic placeholder is needed by HTTPFlow; it is not evidence
        # of a request made at this time.
        start = datetime(1970, 1, 1, tzinfo=timezone.utc).timestamp()
        _warn(warnings, "TIMESTAMP_UNAVAILABLE")
    duration = entry.get("time")
    if (
        isinstance(duration, (int, float))
        and not isinstance(duration, bool)
        and math.isfinite(duration)
        and duration >= 0
    ):
        return start, start + duration / 1000
    _warn(warnings, "DURATION_UNAVAILABLE")
    return start, None


def _size(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _content_length(headers: http.Headers) -> tuple[int | None, bool]:
    values = [
        part.strip()
        for value in headers.get_all("content-length")
        for part in value.split(",")
    ]
    if not values:
        return None, True
    if any(not value.isascii() or not value.isdecimal() for value in values):
        return None, False
    lengths = {int(value) for value in values}
    return (next(iter(lengths)), True) if len(lengths) == 1 else (None, False)


def _mime(headers: http.Headers, record: dict) -> Message:
    message = Message()
    value = headers.get("content-type") or record.get("mimeType") or ""
    message["content-type"] = value if isinstance(value, str) else ""
    return message


def _decode_record(record: dict, mime: Message) -> tuple[bytes | None, str]:
    text = record.get("text")
    if not isinstance(text, str):
        return None, "MISSING"
    encoding = record.get("encoding")
    try:
        if encoding == "base64":
            return base64.b64decode(text.encode("ascii"), validate=True), "base64"
        if encoding not in (None, ""):
            return None, "UNKNOWN_ENCODING"
        return (
            text.encode(mime.get_content_charset() or "utf-8", errors="strict"),
            "text",
        )
    except (ValueError, LookupError, UnicodeError, binascii.Error):
        return None, "INVALID_ENCODING"


def _has_content_encoding(headers: http.Headers) -> bool:
    return any(
        token.strip().lower() not in ("", "identity")
        for value in headers.get_all("content-encoding")
        for token in value.split(",")
    )


def _complete_multipart(body: bytes, mime: Message) -> bool:
    boundary = mime.get_param("boundary")
    if not isinstance(boundary, str) or not boundary:
        return False
    try:
        delimiter = b"--" + boundary.encode("ascii")
    except UnicodeError:
        return False
    return bool(
        re.search(rb"(?:^|\r?\n)" + re.escape(delimiter) + rb"--(?:\r?\n|$)", body)
    )


def _request_body(
    request: dict, headers: http.Headers, warnings: list[str]
) -> tuple[bytes | None, str]:
    record = request.get("postData")
    content_length, valid_length = _content_length(headers)
    size = _size(request.get("bodySize"))
    if not valid_length or ("transfer-encoding" in headers and content_length is not None):
        _warn(warnings, "REQUEST_LENGTH_CONFLICT")
        return None, "missing"
    if _has_content_encoding(headers):
        # postData.encoding only describes the JSON representation. It does not
        # establish whether a recorder captured the content-encoded wire body.
        _warn(warnings, "REQUEST_CONTENT_ENCODING_UNPROVEN")
        return None, "missing"
    if record is None:
        if (
            "transfer-encoding" not in headers
            and (size == 0 or content_length == 0)
            and size in (None, 0)
            and content_length in (None, 0)
        ):
            return b"", "empty"
        _warn(warnings, "REQUEST_BODY_MISSING")
        return None, "missing"
    if not isinstance(record, dict):
        _warn(warnings, "REQUEST_BODY_INVALID")
        return None, "missing"
    mime = _mime(headers, record)
    body, state = _decode_record(record, mime)
    if body is None:
        _warn(warnings, f"REQUEST_BODY_{state}")
        return None, "missing"
    if any(length is not None and length != len(body) for length in (size, content_length)):
        _warn(warnings, "REQUEST_LENGTH_MISMATCH")
        return None, "missing"
    if mime.get_content_maintype() == "multipart" and not _complete_multipart(
        body, mime
    ):
        _warn(warnings, "REQUEST_MULTIPART_INCOMPLETE")
        return None, "missing"
    return body, state


def _response(
    response: dict,
    method: str,
    start: float,
    end: float | None,
    warnings: list[str],
) -> tuple[http.Response | None, str]:
    status = response.get("status")
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        _warn(warnings, "RESPONSE_NOT_CAPTURED")
        return None, "missing"
    pseudo, headers = _separate_pseudoheaders(_headers(response.get("headers")), warnings)
    if any(
        key != b":status" or value != str(status).encode()
        for key, value in pseudo.items()
    ):
        _warn(warnings, "RESPONSE_PSEUDOHEADER_CONFLICT")
    record = response.get("content")
    record = record if isinstance(record, dict) else {}
    body, state = _decode_record(record, _mime(headers, record))
    if body is None:
        if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
            body, state = b"", "empty"
        elif (
            _size(record.get("size")) == 0
            and "text" not in record
            and _size(response.get("bodySize")) in (None, 0)
            and _content_length(headers) in ((None, True), (0, True))
        ):
            body, state = b"", "empty"
        else:
            _warn(warnings, f"RESPONSE_BODY_{state}")
            state = "missing"
    if body is not None and _has_content_encoding(headers):
        # HAR response.content is decoded application content. Keep that
        # content, rather than fabricating a new compressed wire representation.
        headers.pop("content-encoding", None)
        headers.pop("transfer-encoding", None)
        headers["content-length"] = str(len(body))
        _warn(warnings, "RESPONSE_DECODED_CONTENT_HEADERS_ADJUSTED")
    elif (
        body is not None
        and method != "HEAD"
        and status not in (204, 304)
        and status >= 200
    ):
        declared, valid = _content_length(headers)
        if not valid or (declared is not None and declared != len(body)):
            headers.pop("transfer-encoding", None)
            headers["content-length"] = str(len(body))
            _warn(warnings, "RESPONSE_CONTENT_LENGTH_ADJUSTED")
    reason = response.get("statusText", "")
    reason = reason if isinstance(reason, str) else ""
    message = http.Response(
        _http_version(response.get("httpVersion"), warnings),
        status,
        reason.encode("utf-8", "surrogateescape"),
        headers,
        body,
        None,
        start,
        end,
    )
    return message, state


def request_to_flow(entry: dict) -> http.HTTPFlow:
    """Read one HAR entry without sending it or guessing missing request bytes."""
    if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
        raise ValueError("HAR entry requires a request object")
    source = entry["request"]
    method, original_url = source.get("method"), source.get("url")
    if not isinstance(method, str) or not _METHOD.fullmatch(method):
        raise ValueError("HAR request has an invalid HTTP method")
    if not isinstance(original_url, str) or any(
        c in original_url for c in "\r\n\t\x00"
    ):
        raise ValueError("HAR request requires a valid absolute URL")
    try:
        parsed = urlsplit(original_url)
        if parsed.scheme not in ("http", "https", "ws", "wss") or not parsed.hostname:
            raise ValueError("Unsupported URL")
        host = parsed.hostname.encode("idna").decode("ascii")
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme in ("https", "wss") else 80
        if not 1 <= port <= 65535:
            raise ValueError("Invalid port")
        path = parsed.path or "/"
        if "?" in original_url.split("#", 1)[0]:
            path += "?" + parsed.query
        path_bytes = path.encode("ascii")
    except (ValueError, UnicodeError):
        raise ValueError(
            "HAR request requires a valid absolute HTTP(S) or WS(S) URL"
        ) from None

    warnings: list[str] = []
    start, end = _timestamps(entry, warnings)
    pseudo, headers = _separate_pseudoheaders(_headers(source.get("headers")), warnings)
    body, body_state = _request_body(source, headers, warnings)
    authority = f"[{host}]" if ":" in host else host
    if parsed.port is not None:
        authority += f":{port}"
    expected_pseudo = {
        b":method": method.encode("ascii"),
        b":scheme": parsed.scheme.encode("ascii"),
        b":authority": authority.encode("ascii"),
        b":path": path_bytes,
    }
    if "DUPLICATE_PSEUDOHEADER" in warnings or any(
        key not in expected_pseudo or value != expected_pseudo[key]
        for key, value in pseudo.items()
    ):
        _warn(warnings, "REQUEST_PSEUDOHEADER_CONFLICT")
        body, body_state = None, "missing"
    if parsed.username is not None or parsed.fragment:
        _warn(warnings, "REQUEST_URL_COMPONENT_NOT_TRANSMITTABLE")
        body, body_state = None, "missing"
    if parsed.scheme in ("ws", "wss") or "websocket" in headers.get(
        "upgrade", ""
    ).lower():
        _warn(warnings, "HAR_WEBSOCKET_NOT_REPLAYABLE")
        body, body_state = None, "missing"
    if body and "content-length" not in headers and "transfer-encoding" not in headers:
        # A HAR may describe an H2 body without framing headers. Native replay
        # may negotiate H1, which needs a length to transmit these known bytes.
        # Append only when absent; retain all existing header order/duplicates.
        headers.add("Content-Length", str(len(body)))
        _warn(warnings, "REQUEST_CONTENT_LENGTH_ADDED")
    http_version = _http_version(source.get("httpVersion"), warnings)
    request = http.Request(
        host,
        port,
        method.encode("ascii"),
        parsed.scheme.encode("ascii"),
        authority.encode("ascii")
        if http_version in (b"HTTP/2.0", b"HTTP/3") or pseudo
        else b"",
        path_bytes,
        http_version,
        headers,
        body,
        None,
        start,
        end,
    )
    imported = http.HTTPFlow(
        connection.Client(
            peername=("127.0.0.1", 0),
            sockname=("127.0.0.1", 0),
            timestamp_start=start,
        ),
        connection.Server(address=(host, port)),
    )
    imported.timestamp_created = start
    imported.request = request
    response_source = entry.get("response")
    imported.response, response_state = _response(
        response_source if isinstance(response_source, dict) else {},
        method,
        start,
        end,
        warnings,
    )
    if imported.response is None:
        imported.error = flow_module.Error(
            "HAR contains no captured HTTP response", timestamp=start
        )
    imported.metadata["harimport"] = {
        "request_body": body_state,
        "response_body": response_state,
        "warnings": warnings,
    }
    imported.comment = "HAR import: reconstructed application messages; not original wire bytes."
    if body is None:
        imported.comment += (
            " Replay disabled: the original request body or request fields"
            " cannot be reconstructed reliably."
        )
    if "RESPONSE_DECODED_CONTENT_HEADERS_ADJUSTED" in warnings:
        imported.comment += (
            " Historical response body is decoded; compression/framing headers"
            " were adjusted only in this imported copy."
        )
    if "HAR_WEBSOCKET_NOT_REPLAYABLE" in warnings:
        imported.comment += (
            " WebSocket messages are not reconstructed from HAR;"
            " capture live traffic to inspect them."
        )
    if "REQUEST_CONTENT_LENGTH_ADDED" in warnings:
        imported.comment += (
            " Content-Length was added only to this imported copy"
            " to frame the known request body during HTTP/1 replay."
        )
    if warnings:
        imported.comment += " Warnings: " + ", ".join(warnings) + "."
    _observed_hosts.add(host.lower().rstrip("."))
    return imported


def _flow_reader_stream(reader: native_io.FlowReader) -> Iterable[flow_module.Flow]:
    """Handle HAR resources explicitly; leave native binary dumps untouched."""
    global _last_import_summary
    if reader.peek(4).startswith(b"\xef\xbb\xbf{"):
        reader.fo.read(3)
    if not reader.peek(1).startswith(b"{"):
        yield from _native_flow_reader_stream(reader)
        return

    summary: dict = {"entries": 0, "imported": 0, "skipped": {}}
    _last_import_summary = summary
    try:
        document = json.loads(reader.fo.read().decode("utf-8"))
        entries = document["log"]["entries"]
        if not isinstance(entries, list):
            raise ValueError("Entries must be a list")
    except (ValueError, TypeError, KeyError):
        raise exceptions.FlowReadException(
            "Unable to read HAR file: expected log.entries as a JSON array"
        ) from None

    summary["entries"] = len(entries)
    try:
        for index, entry in enumerate(entries):
            source = entry.get("request") if isinstance(entry, dict) else None
            original_url = source.get("url") if isinstance(source, dict) else None
            scheme = ""
            if isinstance(original_url, str):
                colon = original_url.find(":")
                if colon > 0:
                    scheme = original_url[:colon].lower()
            if scheme in _NON_NETWORK_SCHEMES:
                skipped = summary["skipped"]
                skipped[scheme] = skipped.get(scheme, 0) + 1
                continue
            try:
                imported = request_to_flow(entry)
            except (ValueError, TypeError, KeyError, OverflowError):
                raise exceptions.FlowReadException(
                    f"Unable to import HAR network entry {index}: invalid message fields"
                ) from None
            summary["imported"] += 1
            yield imported
    finally:
        skipped = summary["skipped"]
        if skipped:
            counts = ", ".join(f"{scheme}={count}" for scheme, count in sorted(skipped.items()))
            logger.warning(
                "HAR import skipped %d non-network resources (%s). "
                "These embedded/local resources remain in the original HAR.",
                sum(skipped.values()), counts,
            )


def install_har_reader() -> None:
    """Install the adapter in both native reader references, idempotently."""
    if version.VERSION != "12.3.1":
        raise RuntimeError("Relay HAR integration requires mitmproxy 12.3.1")
    from mitmproxy.io import har as native_har
    native_har.request_to_flow = request_to_flow
    # FlowReader imports this callable by value, not through the har module.
    native_io.request_to_flow = request_to_flow
    native_io.FlowReader.stream = _flow_reader_stream
