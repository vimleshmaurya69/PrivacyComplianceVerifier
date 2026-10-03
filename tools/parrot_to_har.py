"""Convert TShark-decrypted HTTP/1.x traffic from a PARROT PCAP to HAR 1.2.

This is an experiment utility. It does not import or alter the production
PrivacyComplianceVerifier pipeline. Only requests actually decoded by TShark
are emitted; incomplete request/response pairs are reported, not fabricated.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit


COMMON_REQUEST_HEADERS = {
    "http.host": "Host",
    "http.user_agent": "User-Agent",
    "http.content_type": "Content-Type",
    "http.connection": "Connection",
    "http.accept_encoding": "Accept-Encoding",
    "http.content_length_header": "Content-Length",
    "http.authorization": "Authorization",
    "http.cookie": "Cookie",
}

COMMON_RESPONSE_HEADERS = {
    "http.content_type": "Content-Type",
    "http.cache_control": "Cache-Control",
    "http.date": "Date",
    "http.connection": "Connection",
    "http.content_length_header": "Content-Length",
    "http.set_cookie": "Set-Cookie",
}


def _scalar(value: Any) -> str | None:
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    return str(value)


def _find_field(layer: dict[str, Any], name: str) -> Any:
    if name in layer:
        return layer[name]
    for value in layer.values():
        if isinstance(value, dict) and name in value:
            return value[name]
    return None


def _values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _hex_bytes(value: Any) -> bytes:
    text = _scalar(value)
    if not text:
        return b""
    try:
        return bytes.fromhex(text.replace(":", ""))
    except ValueError:
        return b""


def _decode_text(data: bytes, content_type: str) -> str:
    charset = "utf-8"
    for parameter in content_type.split(";")[1:]:
        key, separator, value = parameter.partition("=")
        if separator and key.strip().lower() == "charset":
            declared = value.strip().strip('"').lower()
            if declared in {"utf-8", "utf8", "iso-8859-1", "latin-1"}:
                charset = declared
            break
    try:
        return data.decode(charset)
    except (LookupError, UnicodeDecodeError):
        return data.decode("utf-8", errors="replace")


def _headers(http: dict[str, Any], mapping: dict[str, str]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for field, name in mapping.items():
        for value in _values(_find_field(http, field)):
            result.append({"name": name, "value": value})
    return result


def _header_value(headers: list[dict[str, str]], name: str) -> str:
    lowered = name.lower()
    for header in headers:
        if header["name"].lower() == lowered:
            return header["value"]
    return ""


def _cookies(headers: list[dict[str, str]], response: bool = False) -> list[dict[str, str]]:
    cookie_header = "set-cookie" if response else "cookie"
    cookies: list[dict[str, str]] = []
    for header in headers:
        if header["name"].lower() != cookie_header:
            continue
        chunks = [header["value"]] if response else header["value"].split(";")
        for chunk in chunks:
            pair = chunk.split(";", 1)[0] if response else chunk
            name, separator, value = pair.strip().partition("=")
            if separator and name:
                cookies.append({"name": name, "value": value})
    return cookies


def _iso_timestamp(epoch: str | None) -> str:
    raw = epoch or "0"
    try:
        instant = dt.datetime.fromtimestamp(float(raw), tz=dt.timezone.utc)
    except ValueError:
        instant = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _run_tshark(tshark: Path, pcap: Path, keylog: Path) -> list[dict[str, Any]]:
    command = [
        str(tshark),
        "-r",
        str(pcap),
        "-o",
        f"tls.keylog_file:{keylog}",
        "-Y",
        "http.request or http.response",
        "-T",
        "json",
    ]
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return json.loads(completed.stdout)


def convert(
    tshark: Path,
    pcap: Path,
    keylog: Path,
    output: Path,
    host_suffix: str | None,
) -> dict[str, int]:
    packets = _run_tshark(tshark, pcap, keylog)
    requests: dict[str, dict[str, Any]] = {}
    responses: dict[str, dict[str, Any]] = {}

    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        http = layers.get("http", {})
        frame_number = _scalar(frame.get("frame.number"))
        if not frame_number or not isinstance(http, dict):
            continue
        if _find_field(http, "http.request.method") is not None:
            requests[frame_number] = layers
        if _find_field(http, "http.response.code") is not None:
            request_number = _scalar(_find_field(http, "http.request_in"))
            if request_number:
                responses[request_number] = layers

    entries: list[dict[str, Any]] = []
    incomplete = 0
    skipped_host = 0
    for request_number, layers in requests.items():
        http = layers["http"]
        frame = layers.get("frame", {})
        tcp = layers.get("tcp", {})
        ip = layers.get("ip", {})
        method = _scalar(_find_field(http, "http.request.method")) or ""
        url = _scalar(_find_field(http, "http.request.full_uri")) or ""
        version = _scalar(_find_field(http, "http.request.version")) or "HTTP/1.1"
        if not method or not url:
            incomplete += 1
            continue
        hostname = (urlsplit(url).hostname or "").lower()
        if host_suffix and not (
            hostname == host_suffix.lower() or hostname.endswith("." + host_suffix.lower())
        ):
            skipped_host += 1
            continue

        request_headers = _headers(http, COMMON_REQUEST_HEADERS)
        request_body = _hex_bytes(_find_field(http, "http.file_data"))
        request_mime = _header_value(request_headers, "Content-Type")
        request: dict[str, Any] = {
            "method": method,
            "url": url,
            "httpVersion": version,
            "headers": request_headers,
            "queryString": [
                {"name": name, "value": value}
                for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
            ],
            "cookies": _cookies(request_headers),
            "headersSize": -1,
            "bodySize": len(request_body),
        }
        if request_body:
            request["postData"] = {
                "mimeType": request_mime or "application/octet-stream",
                "text": _decode_text(request_body, request_mime),
            }

        response_layers = responses.get(request_number)
        elapsed_ms = 0.0
        if response_layers:
            response_http = response_layers["http"]
            status = int(_scalar(_find_field(response_http, "http.response.code")) or 0)
            status_text = _scalar(_find_field(response_http, "http.response.phrase")) or ""
            response_version = (
                _scalar(_find_field(response_http, "http.response.version")) or version
            )
            response_headers = _headers(response_http, COMMON_RESPONSE_HEADERS)
            response_body = _hex_bytes(_find_field(response_http, "http.file_data"))
            response_mime = _header_value(response_headers, "Content-Type")
            original_encoding = _scalar(_find_field(response_http, "http.content_encoding"))
            # TShark's http.file_data is already content-decoded. Do not retain a
            # Content-Encoding header that could make HAR consumers decode twice.
            response_headers = [
                header
                for header in response_headers
                if header["name"].lower() not in {"content-encoding", "content-length"}
            ]
            if response_body:
                response_headers.append({"name": "Content-Length", "value": str(len(response_body))})
            elapsed_ms = 1000.0 * float(
                _scalar(_find_field(response_http, "http.time")) or 0
            )
            content: dict[str, Any] = {
                "size": len(response_body),
                "mimeType": response_mime or "application/octet-stream",
            }
            if response_body:
                content["text"] = _decode_text(response_body, response_mime)
            response: dict[str, Any] = {
                "status": status,
                "statusText": status_text,
                "httpVersion": response_version,
                "headers": response_headers,
                "cookies": _cookies(response_headers, response=True),
                "content": content,
                "redirectURL": _header_value(response_headers, "Location"),
                "headersSize": -1,
                "bodySize": len(response_body),
            }
            if original_encoding:
                response["_parrot_originalContentEncoding"] = original_encoding
        else:
            incomplete += 1
            response = {
                "status": 0,
                "statusText": "",
                "httpVersion": "",
                "headers": [],
                "cookies": [],
                "content": {"size": 0, "mimeType": "application/octet-stream"},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": 0,
                "_parrot_incomplete": True,
            }

        entries.append(
            {
                "startedDateTime": _iso_timestamp(_scalar(frame.get("frame.time_epoch"))),
                "time": elapsed_ms,
                "request": request,
                "response": response,
                "cache": {},
                "timings": {"send": 0, "wait": elapsed_ms, "receive": 0},
                "serverIPAddress": _scalar(ip.get("ip.dst")) or "",
                "connection": _scalar(tcp.get("tcp.stream")) or "",
                "_parrot_requestFrame": int(request_number),
            }
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "PARROT TShark converter", "version": "1.0"},
                    "entries": entries,
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {
        "decoded_http_packets": len(packets),
        "decoded_requests": len(requests),
        "har_entries": len(entries),
        "incomplete_entries": incomplete,
        "skipped_by_host_filter": skipped_host,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tshark", required=True, type=Path)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--keylog", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--host-suffix")
    args = parser.parse_args()
    stats = convert(args.tshark, args.pcap, args.keylog, args.output, args.host_suffix)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
