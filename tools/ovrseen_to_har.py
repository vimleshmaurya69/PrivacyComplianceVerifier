"""Convert one OVRseen application's decrypted PCAPNG traffic to HAR 1.2.

This experiment-only utility deliberately has no dependency on the production
PrivacyComplianceVerifier package.  It reads the nested per-app archive from
OVRseen's PCAPs.zip, reassembles contiguous TCP payloads, parses HTTP/1.x
messages, and writes only requests that were actually reconstructed.

Dependency: dpkt 1.9.8 (kept outside the framework requirements).
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import re
import socket
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterable, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

try:
    import dpkt
except ImportError as exc:  # pragma: no cover - exercised by CLI environments
    raise SystemExit(
        "This experiment requires dpkt==1.9.8. Install it in an isolated "
        "environment; do not add it to the framework requirements."
    ) from exc


MAX_MESSAGE_BYTES = 32 * 1024 * 1024
REQUEST_LINE = re.compile(
    rb"([A-Z][A-Z0-9_-]{1,19}) ([^\r\n ]+) "
    rb"(HTTP/1\.[01])\r\n"
)
REQUEST_START = re.compile(
    rb"(?m)(?:^|\r\n)([A-Z][A-Z0-9_-]{1,19}) ([^\r\n ]+) "
    rb"(HTTP/1\.[01])\r\n"
)
RESPONSE_LINE = re.compile(
    rb"(HTTP/1\.[01]) ([0-9]{3})(?: ([^\r\n]*))?\r\n"
)
RESPONSE_START = re.compile(
    rb"(?m)(?:^|\r\n)(HTTP/1\.[01]) ([0-9]{3})(?: ([^\r\n]*))?\r\n"
)
HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
CHARSET = re.compile(r"(?i)(?:^|;)\s*charset\s*=\s*['\"]?([^;'\"\s]+)")


@dataclass(frozen=True)
class ConnectionKey:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int

    def label(self) -> str:
        return (
            f"{self.client_ip}:{self.client_port}-"
            f"{self.server_ip}:{self.server_port}"
        )


@dataclass
class Segment:
    sequence: int
    timestamp: float
    payload: bytes


@dataclass
class StreamChunk:
    data: bytes
    spans: list[tuple[int, int, float]]

    def timestamp_at(self, offset: int) -> float:
        for start, end, timestamp in self.spans:
            if start <= offset < end:
                return timestamp
        return self.spans[0][2] if self.spans else 0.0


@dataclass
class HttpMessage:
    timestamp: float
    version: str
    headers: list[tuple[str, str]]
    body: bytes
    complete: bool = True
    method: str = ""
    target: str = ""
    status: int = 0
    reason: str = ""


@dataclass
class ParseStats:
    packets: int = 0
    tcp_payload_packets: int = 0
    tcp_connections: int = 0
    reassembly_gaps: int = 0
    requests_parsed: int = 0
    responses_parsed: int = 0
    informational_responses: int = 0
    incomplete_messages: int = 0
    skipped_requests: int = 0
    unmatched_responses: int = 0
    notes: list[str] = field(default_factory=list)


def _ip_text(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6 if len(raw) == 16 else socket.AF_INET, raw)


def _decode_packet(linktype: int, packet: bytes):
    if linktype in {dpkt.pcap.DLT_RAW, 101}:
        version = packet[0] >> 4 if packet else 0
        if version == 4:
            return dpkt.ip.IP(packet)
        if version == 6:
            return dpkt.ip6.IP6(packet)
        raise ValueError("unsupported raw-IP version")
    if linktype == dpkt.pcap.DLT_EN10MB:
        return dpkt.ethernet.Ethernet(packet).data
    raise ValueError(f"unsupported PCAPNG link type: {linktype}")


def read_tcp_segments(
    capture: BinaryIO,
    *,
    outbound: bool,
    stats: ParseStats,
) -> dict[ConnectionKey, list[Segment]]:
    reader = dpkt.pcapng.Reader(capture)
    linktype = reader.datalink()
    streams: dict[ConnectionKey, list[Segment]] = defaultdict(list)

    for timestamp, packet in reader:
        stats.packets += 1
        try:
            ip = _decode_packet(linktype, packet)
        except (ValueError, dpkt.UnpackError):
            continue
        tcp = getattr(ip, "data", None)
        if not isinstance(tcp, dpkt.tcp.TCP) or not tcp.data:
            continue
        stats.tcp_payload_packets += 1
        source_ip = _ip_text(ip.src)
        destination_ip = _ip_text(ip.dst)
        if outbound:
            key = ConnectionKey(source_ip, tcp.sport, destination_ip, tcp.dport)
        else:
            key = ConnectionKey(destination_ip, tcp.dport, source_ip, tcp.sport)
        streams[key].append(Segment(tcp.seq, float(timestamp), bytes(tcp.data)))

    stats.tcp_connections = len(streams)
    return streams


def reassemble_contiguous(
    segments: Iterable[Segment], stats: ParseStats
) -> list[StreamChunk]:
    segment_list = list(segments)
    if not segment_list:
        return []
    base_sequence = min(segment_list, key=lambda item: item.timestamp).sequence

    def relative_sequence(item: Segment) -> int:
        delta = (item.sequence - base_sequence) & 0xFFFFFFFF
        return delta - 0x100000000 if delta >= 0x80000000 else delta

    ordered = sorted(segment_list, key=lambda item: (relative_sequence(item), item.timestamp))
    chunks: list[StreamChunk] = []
    data = bytearray()
    spans: list[tuple[int, int, float]] = []
    current_start = relative_sequence(ordered[0])
    current_end = current_start

    for segment in ordered:
        start = relative_sequence(segment)
        payload = segment.payload
        end = start + len(payload)
        if end <= current_end:
            continue  # Complete retransmission.
        if start > current_end:
            if data:
                chunks.append(StreamChunk(bytes(data), spans))
            stats.reassembly_gaps += 1
            data = bytearray()
            spans = []
            current_start = start
            current_end = start
        overlap = max(0, current_end - start)
        new_payload = payload[overlap:]
        if not new_payload:
            continue
        output_start = len(data)
        data.extend(new_payload)
        spans.append((output_start, len(data), segment.timestamp))
        current_end = end

    if data:
        chunks.append(StreamChunk(bytes(data), spans))
    return chunks


def _parse_headers(block: bytes) -> Optional[list[tuple[str, str]]]:
    headers: list[tuple[str, str]] = []
    for raw_line in block.split(b"\r\n"):
        if not raw_line:
            continue
        if raw_line[:1] in {b" ", b"\t"} and headers:
            name, old_value = headers[-1]
            headers[-1] = (name, f"{old_value} {raw_line.strip().decode('latin-1')}")
            continue
        if b":" not in raw_line:
            return None
        raw_name, raw_value = raw_line.split(b":", 1)
        if not HEADER_NAME.fullmatch(raw_name):
            return None
        headers.append(
            (raw_name.decode("ascii"), raw_value.strip().decode("latin-1"))
        )
    return headers


def _header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    lowered = name.lower()
    return [value for key, value in headers if key.lower() == lowered]


def _parse_chunked(data: bytes, start: int) -> Optional[tuple[bytes, int]]:
    position = start
    decoded = bytearray()
    while True:
        line_end = data.find(b"\r\n", position)
        if line_end < 0 or line_end - position > 128:
            return None
        size_text = data[position:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return None
        position = line_end + 2
        if size < 0 or len(decoded) + size > MAX_MESSAGE_BYTES:
            return None
        if len(data) < position + size + 2:
            return None
        decoded.extend(data[position : position + size])
        position += size
        if data[position : position + 2] != b"\r\n":
            return None
        position += 2
        if size == 0:
            trailer_end = data.find(b"\r\n\r\n", position)
            if trailer_end >= 0:
                position = trailer_end + 4
            elif data[position : position + 2] == b"\r\n":
                position += 2
            return bytes(decoded), position


def _body_extent(
    data: bytes,
    start: int,
    headers: list[tuple[str, str]],
    *,
    response_status: int = 0,
) -> Optional[tuple[bytes, int]]:
    transfer_encoding = ",".join(_header_values(headers, "transfer-encoding")).lower()
    if "chunked" in transfer_encoding:
        return _parse_chunked(data, start)

    content_lengths = _header_values(headers, "content-length")
    if content_lengths:
        try:
            length = int(content_lengths[-1].strip())
        except ValueError:
            return None
        if length < 0 or length > MAX_MESSAGE_BYTES or len(data) < start + length:
            return None
        return data[start : start + length], start + length

    if response_status and (100 <= response_status < 200 or response_status in {204, 304}):
        return b"", start
    return b"", start


def parse_requests(chunk: StreamChunk, stats: ParseStats) -> list[HttpMessage]:
    messages: list[HttpMessage] = []
    position = 0
    while position < len(chunk.data):
        start = position
        while chunk.data[start : start + 2] == b"\r\n":
            start += 2
        match = REQUEST_LINE.match(chunk.data, start)
        if not match:
            scanned = REQUEST_START.search(chunk.data, start)
            if not scanned:
                break
            start = scanned.start()
            if chunk.data[start : start + 2] == b"\r\n":
                start += 2
            match = REQUEST_LINE.match(chunk.data, start)
            if not match:
                position = scanned.end()
                continue
        header_end = chunk.data.find(b"\r\n\r\n", match.end())
        if header_end < 0 or header_end - start > MAX_MESSAGE_BYTES:
            stats.incomplete_messages += 1
            break
        headers = _parse_headers(chunk.data[match.end() : header_end])
        if headers is None:
            position = match.end()
            continue
        body_info = _body_extent(chunk.data, header_end + 4, headers)
        if body_info is None:
            stats.incomplete_messages += 1
            position = match.end()
            continue
        body, end = body_info
        messages.append(
            HttpMessage(
                timestamp=chunk.timestamp_at(start),
                version=match.group(3).decode("ascii"),
                headers=headers,
                body=body,
                method=match.group(1).decode("ascii"),
                target=match.group(2).decode("latin-1"),
            )
        )
        position = max(end, match.end())
    stats.requests_parsed += len(messages)
    return messages


def parse_responses(chunk: StreamChunk, stats: ParseStats) -> list[HttpMessage]:
    messages: list[HttpMessage] = []
    position = 0
    while position < len(chunk.data):
        start = position
        while chunk.data[start : start + 2] == b"\r\n":
            start += 2
        match = RESPONSE_LINE.match(chunk.data, start)
        if not match:
            scanned = RESPONSE_START.search(chunk.data, start)
            if not scanned:
                break
            start = scanned.start()
            if chunk.data[start : start + 2] == b"\r\n":
                start += 2
            match = RESPONSE_LINE.match(chunk.data, start)
            if not match:
                position = scanned.end()
                continue
        header_end = chunk.data.find(b"\r\n\r\n", match.end())
        if header_end < 0 or header_end - start > MAX_MESSAGE_BYTES:
            stats.incomplete_messages += 1
            break
        headers = _parse_headers(chunk.data[match.end() : header_end])
        if headers is None:
            position = match.end()
            continue
        status = int(match.group(2))
        body_info = _body_extent(
            chunk.data, header_end + 4, headers, response_status=status
        )
        if body_info is None:
            stats.incomplete_messages += 1
            position = match.end()
            continue
        body, end = body_info
        message = HttpMessage(
            timestamp=chunk.timestamp_at(start),
            version=match.group(1).decode("ascii"),
            headers=headers,
            body=body,
            status=status,
            reason=(match.group(3) or b"").decode("latin-1"),
        )
        if 100 <= status < 200 and status != 101:
            stats.informational_responses += 1
        else:
            messages.append(message)
        position = max(end, match.end())
    stats.responses_parsed += len(messages)
    return messages


def _cookies_from_request(headers: list[tuple[str, str]]) -> list[dict[str, str]]:
    cookies: list[dict[str, str]] = []
    for value in _header_values(headers, "cookie"):
        for pair in value.split(";"):
            if "=" not in pair:
                continue
            name, cookie_value = pair.split("=", 1)
            if name.strip():
                cookies.append({"name": name.strip(), "value": cookie_value.strip()})
    return cookies


def _cookies_from_response(headers: list[tuple[str, str]]) -> list[dict[str, str]]:
    cookies: list[dict[str, str]] = []
    for value in _header_values(headers, "set-cookie"):
        first = value.split(";", 1)[0]
        if "=" not in first:
            continue
        name, cookie_value = first.split("=", 1)
        if name.strip():
            cookies.append({"name": name.strip(), "value": cookie_value.strip()})
    return cookies


def _content_type(headers: list[tuple[str, str]]) -> str:
    values = _header_values(headers, "content-type")
    return values[-1] if values else ""


def _body_text(body: bytes, content_type: str) -> tuple[str, Optional[str]]:
    if not body:
        return "", None
    encodings: list[str] = []
    charset_match = CHARSET.search(content_type)
    if charset_match:
        declared = charset_match.group(1).lower()
        if declared in {"utf-8", "utf8", "iso-8859-1", "latin-1", "us-ascii"}:
            encodings.append(declared)
    encodings.extend(["utf-8", "latin-1"])
    for encoding in dict.fromkeys(encodings):
        try:
            text = body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
        printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
        if text and printable / len(text) >= 0.85:
            return text, None
    return base64.b64encode(body).decode("ascii"), "base64"


def _request_url(request: HttpMessage, key: ConnectionKey) -> Optional[str]:
    target_parts = urlsplit(request.target)
    if target_parts.scheme and target_parts.netloc:
        return request.target
    hosts = _header_values(request.headers, "host")
    if not hosts:
        return None
    if key.server_port == 443:
        scheme = "https"
    elif key.server_port == 80:
        scheme = "http"
    else:
        return None
    path = request.target if request.target.startswith("/") else f"/{request.target}"
    split_path = urlsplit(path)
    return urlunsplit((scheme, hosts[-1], split_path.path or "/", split_path.query, ""))


def _har_headers(headers: list[tuple[str, str]]) -> list[dict[str, str]]:
    return [{"name": name, "value": value} for name, value in headers]


def _iso_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_har_entry(
    app_id: str,
    key: ConnectionKey,
    request: HttpMessage,
    response: Optional[HttpMessage],
    stats: ParseStats,
) -> Optional[dict]:
    url = _request_url(request, key)
    if not url:
        stats.skipped_requests += 1
        return None
    request_content_type = _content_type(request.headers)
    request_text, request_encoding = _body_text(request.body, request_content_type)
    split_url = urlsplit(url)
    request_object: dict = {
        "method": request.method,
        "url": url,
        "httpVersion": request.version,
        "headers": _har_headers(request.headers),
        "queryString": [
            {"name": name, "value": value}
            for name, value in parse_qsl(split_url.query, keep_blank_values=True)
        ],
        "cookies": _cookies_from_request(request.headers),
        "headersSize": -1,
        "bodySize": len(request.body),
    }
    if request.body:
        post_data = {"mimeType": request_content_type, "text": request_text}
        if request_encoding:
            post_data["encoding"] = request_encoding
        request_object["postData"] = post_data

    if response:
        response_content_type = _content_type(response.headers)
        response_text, response_encoding = _body_text(response.body, response_content_type)
        content = {
            "size": len(response.body),
            "mimeType": response_content_type,
            "text": response_text,
        }
        if response_encoding:
            content["encoding"] = response_encoding
        response_object = {
            "status": response.status,
            "statusText": response.reason,
            "httpVersion": response.version,
            "headers": _har_headers(response.headers),
            "cookies": _cookies_from_response(response.headers),
            "content": content,
            "redirectURL": (_header_values(response.headers, "location") or [""])[-1],
            "headersSize": -1,
            "bodySize": len(response.body),
        }
        elapsed = max(0.0, (response.timestamp - request.timestamp) * 1000)
    else:
        response_object = {
            "status": 0,
            "statusText": "",
            "httpVersion": "",
            "headers": [],
            "cookies": [],
            "content": {"size": 0, "mimeType": "", "text": ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": 0,
            "_ovrseen_incomplete": True,
        }
        elapsed = 0.0

    return {
        "startedDateTime": _iso_timestamp(request.timestamp),
        "time": elapsed,
        "request": request_object,
        "response": response_object,
        "cache": {},
        "timings": {"send": -1, "wait": elapsed if response else -1, "receive": -1},
        "serverIPAddress": key.server_ip,
        "connection": key.label(),
        "_ovrseen": {
            "app_id": app_id,
            "client_ip": key.client_ip,
            "client_port": key.client_port,
            "server_ip": key.server_ip,
            "server_port": key.server_port,
            "response_reconstructed": response is not None,
        },
    }


def _select_capture(inner: zipfile.ZipFile, direction: str) -> zipfile.ZipInfo:
    suffix = f"{direction}.pcapng"
    matches = [
        entry
        for entry in inner.infolist()
        if "COMPLETED_DECRYPTED_" in entry.filename and entry.filename.endswith(suffix)
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected one decrypted {direction} capture, found {len(matches)}"
        )
    return matches[0]


def convert_app(
    pcaps_zip: Path,
    store: str,
    app_id: str,
    output_path: Path,
) -> dict:
    archive_name = f"PCAPs/{store}/{app_id}.zip"
    stats = ParseStats()
    with zipfile.ZipFile(pcaps_zip) as outer:
        try:
            nested_bytes = outer.read(archive_name)
        except KeyError as exc:
            raise FileNotFoundError(f"app archive not found: {archive_name}") from exc
    with zipfile.ZipFile(io.BytesIO(nested_bytes)) as inner:
        outbound_entry = _select_capture(inner, "out")
        inbound_entry = _select_capture(inner, "inc")
        outbound_bytes = inner.read(outbound_entry)
        inbound_bytes = inner.read(inbound_entry)

    outbound_streams = read_tcp_segments(
        io.BytesIO(outbound_bytes), outbound=True, stats=stats
    )
    inbound_stats = ParseStats()
    inbound_streams = read_tcp_segments(
        io.BytesIO(inbound_bytes), outbound=False, stats=inbound_stats
    )
    stats.packets += inbound_stats.packets
    stats.tcp_payload_packets += inbound_stats.tcp_payload_packets
    stats.tcp_connections = len(set(outbound_streams) | set(inbound_streams))

    entries: list[dict] = []
    response_count = 0
    for key, segments in sorted(outbound_streams.items(), key=lambda item: item[0].label()):
        requests: list[HttpMessage] = []
        for chunk in reassemble_contiguous(segments, stats):
            requests.extend(parse_requests(chunk, stats))
        responses: list[HttpMessage] = []
        for chunk in reassemble_contiguous(inbound_streams.get(key, []), stats):
            responses.extend(parse_responses(chunk, stats))
        response_count += len(responses)
        for index, request in enumerate(requests):
            response = responses[index] if index < len(responses) else None
            entry = build_har_entry(app_id, key, request, response, stats)
            if entry:
                entries.append(entry)
        if len(responses) > len(requests):
            stats.unmatched_responses += len(responses) - len(requests)

    har = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "OVRseen PCAPNG to HAR experiment adapter",
                "version": "1.0",
            },
            "entries": sorted(entries, key=lambda entry: entry["startedDateTime"]),
            "_ovrseen": {
                "app_id": app_id,
                "source_archive": archive_name,
                "outbound_capture": outbound_entry.filename,
                "inbound_capture": inbound_entry.filename,
            },
        }
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(har, indent=2), encoding="utf-8")

    report = {
        "app_id": app_id,
        "store": store,
        "source_archive": archive_name,
        "outbound_capture": outbound_entry.filename,
        "inbound_capture": inbound_entry.filename,
        "packets_read": stats.packets,
        "tcp_payload_packets": stats.tcp_payload_packets,
        "tcp_connections": stats.tcp_connections,
        "reassembly_gaps": stats.reassembly_gaps,
        "http_requests_reconstructed": stats.requests_parsed,
        "http_responses_reconstructed": stats.responses_parsed,
        "informational_responses_ignored_for_pairing": stats.informational_responses,
        "har_entries": len(entries),
        "har_entries_with_response": sum(
            1 for entry in entries if entry["response"]["status"] > 0
        ),
        "incomplete_messages": stats.incomplete_messages,
        "requests_skipped_without_verifiable_url": stats.skipped_requests,
        "unmatched_responses": stats.unmatched_responses,
        "output": str(output_path),
    }
    report_path = output_path.with_suffix(".conversion.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert one OVRseen app's decrypted PCAPNG traffic to HAR 1.2"
    )
    parser.add_argument("--pcaps-zip", type=Path, required=True)
    parser.add_argument("--store", choices=["Oculus-Free", "Oculus-Paid", "SideQuest"], required=True)
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = convert_app(args.pcaps_zip, args.store, args.app_id, args.output)
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
