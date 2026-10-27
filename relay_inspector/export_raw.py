"""Export captured HTTP body bytes without decompression or content execution.

The manifest contains original URLs and headers, including credentials. Keep it
private. Bodies are stored as .bin files regardless of Content-Type. A native
.mitm capture is required; HAR bodies may already have been decoded by their
original exporter and are not evidence of the original encoded body bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from mitmproxy import exceptions, http, io


def _select_flow(
    capture: Path, *, flow_id: str | None, index: int | None
) -> tuple[int, http.HTTPFlow]:
    if (flow_id is None) == (index is None):
        raise ValueError("Select exactly one flow ID or zero-based index.")
    if index is not None and index < 0:
        raise ValueError("The capture index cannot be negative.")
    with capture.open("rb") as source:
        prefix = source.read(1)
        source.seek(0)
        if not prefix or not b"0" <= prefix <= b"9":
            raise ValueError("Raw export requires a native .mitm capture.")
        for position, flow in enumerate(io.FlowReader(source).stream()):
            if (flow_id is not None and flow.id == flow_id) or position == index:
                if not isinstance(flow, http.HTTPFlow):
                    raise ValueError("The selected flow does not contain an HTTP exchange.")
                return position, flow
    raise ValueError("The selected flow was not found in the capture.")


def _headers(message: http.Message) -> list[dict[str, str]]:
    return [
        {
            "name_base64": base64.b64encode(name).decode("ascii"),
            "value_base64": base64.b64encode(value).decode("ascii"),
        }
        for name, value in message.headers.fields
    ]


def _body_metadata(body: bytes | None, filename: str) -> dict:
    return {
        "available": body is not None,
        "file": filename if body is not None else None,
        "length": len(body) if body is not None else None,
        "sha256": hashlib.sha256(body).hexdigest() if body is not None else None,
    }


def _write_private_file(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def export_capture(
    capture: str | Path,
    output: str | Path,
    *,
    flow_id: str | None = None,
    index: int | None = None,
) -> Path:
    """Export one HTTP flow; never overwrite existing export files.

    ``index`` is zero based over all native capture records, including non-HTTP
    flows. Headers use ordered base64 byte pairs, preserving duplicates and
    non-UTF-8 octets. ``raw_content=None`` remains unavailable, not empty.
    """
    position, flow = _select_flow(Path(capture), flow_id=flow_id, index=index)
    destination = Path(output)
    for name in ("request.bin", "response.bin", "manifest.json"):
        if (destination / name).exists() or (destination / name).is_symlink():
            raise FileExistsError("An export file already exists in the destination.")

    request_body = flow.request.raw_content
    response_body = flow.response.raw_content if flow.response is not None else None
    manifest = {
        "format": "relay-raw-export-v1",
        "flow_id": flow.id,
        "capture_index": position,
        "header_encoding": "base64; ordered byte pairs; duplicates retained",
        "body_semantics": "mitmproxy raw_content; content encoding retained; transport framing excluded",
        "request": {
            "method": flow.request.method,
            "url": flow.request.url,
            "http_version": flow.request.http_version,
            "headers": _headers(flow.request),
            "body": _body_metadata(request_body, "request.bin"),
        },
        "response": None,
    }
    if flow.response is not None:
        manifest["response"] = {
            "status_code": flow.response.status_code,
            "http_version": flow.response.http_version,
            "headers": _headers(flow.response),
            "body": _body_metadata(response_body, "response.bin"),
        }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    if request_body is not None:
        _write_private_file(destination / "request.bin", request_body)
    if response_body is not None:
        _write_private_file(destination / "response.bin", response_body)
    manifest_path = destination / "manifest.json"
    _write_private_file(manifest_path, manifest_bytes)
    return manifest_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export private raw HTTP body bytes from a native .mitm capture."
    )
    parser.add_argument("capture", type=Path, help="Native .mitm capture (not HAR)")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--flow-id", help="Native mitmproxy flow ID")
    selection.add_argument("--index", type=int, help="Zero-based index over all capture records")
    parser.add_argument("--output", type=Path, required=True, help="Private local output directory")
    args = parser.parse_args(argv)
    try:
        export_capture(args.capture, args.output, flow_id=args.flow_id, index=args.index)
    except (OSError, ValueError, exceptions.FlowReadException):
        # Native reader exceptions may include captured data; never print them.
        print(
            "Raw export failed. Check the native capture, HTTP flow selection, "
            "and an output directory without previous export files.",
            file=sys.stderr,
        )
        return 2
    print("Raw export saved. The manifest includes private URLs and headers; keep the export private.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
