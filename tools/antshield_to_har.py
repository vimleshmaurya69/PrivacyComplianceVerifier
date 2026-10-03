"""Convert selected AntShield/AntMonitor request records to HAR 1.2.

The AntShield release stores decoded request metadata as JSON dictionaries but
does not include HTTP responses. This experimental converter preserves the
available request evidence and marks every response as incomplete. It does not
import or modify PrivacyComplianceVerifier production code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit


SUPPORTED_PROTOCOLS = {"HTTP", "HTTPS"}


def _header_pairs(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, dict):
        return []
    pairs = []
    for name, value in raw.items():
        values = value if isinstance(value, list) else [value]
        for item in values:
            if item is not None:
                pairs.append({"name": str(name), "value": str(item)})
    return pairs


def _header_value(headers: list[dict[str, str]], name: str) -> str:
    expected = name.lower()
    for header in headers:
        if header["name"].lower() == expected:
            return header["value"]
    return ""


def _cookies(headers: list[dict[str, str]]) -> list[dict[str, str]]:
    result = []
    for header in headers:
        if header["name"].lower() != "cookie":
            continue
        for chunk in header["value"].split(";"):
            name, separator, value = chunk.strip().partition("=")
            if separator and name:
                result.append({"name": name, "value": value})
    return result


def _timestamp(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    if number > 10_000_000_000:
        number /= 1000.0
    instant = dt.datetime.fromtimestamp(number, tz=dt.timezone.utc)
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _build_url(protocol: str, host: str, uri: str) -> str:
    parsed = urlsplit(uri)
    if parsed.scheme and parsed.netloc:
        return uri
    path = uri if uri.startswith("/") else "/" + uri
    return f"{protocol.lower()}://{host}{path}"


def _pii_labels(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, dict):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def convert(raw_root: Path, package: str, output: Path) -> dict[str, Any]:
    records = []
    skipped = {
        "non_http_protocol": 0,
        "missing_request_fields": 0,
        "invalid_record": 0,
    }

    for source in sorted(raw_root.rglob(f"{package}.json")):
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            skipped["invalid_record"] += 1
            continue
        for record_id, record in payload.items():
            if not isinstance(record, dict):
                skipped["invalid_record"] += 1
                continue
            protocol = str(record.get("protocol") or "").upper()
            if protocol not in SUPPORTED_PROTOCOLS:
                skipped["non_http_protocol"] += 1
                continue
            method = str(record.get("method") or "").upper()
            host = str(record.get("host") or "").strip()
            uri = str(record.get("uri") or "").strip()
            if not method or not host or not uri:
                skipped["missing_request_fields"] += 1
                continue
            records.append((record, str(record_id), source, protocol, method, host, uri))

    records.sort(key=lambda item: (str(item[0].get("ts") or ""), item[1]))
    entries = []
    labelled_entries = 0
    labels: dict[str, int] = {}

    for record, record_id, source, protocol, method, host, uri in records:
        url = _build_url(protocol, host, uri)
        headers = _header_pairs(record.get("headers"))
        body = record.get("post_body")
        body_text = "" if body is None else str(body)
        mime_type = _header_value(headers, "Content-Type")
        request: dict[str, Any] = {
            "method": method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "cookies": _cookies(headers),
            "headers": headers,
            "queryString": [
                {"name": name, "value": value}
                for name, value in parse_qsl(
                    urlsplit(url).query, keep_blank_values=True
                )
            ],
            "headersSize": -1,
            "bodySize": len(body_text.encode("utf-8")) if body_text else 0,
        }
        if body_text:
            request["postData"] = {
                # An empty value preserves the source's missing Content-Type
                # rather than inventing a structured representation.
                "mimeType": mime_type,
                "text": body_text,
            }

        record_labels = _pii_labels(record.get("pii_types"))
        if record_labels:
            labelled_entries += 1
            for label in record_labels:
                labels[label] = labels.get(label, 0) + 1

        entries.append({
            "startedDateTime": _timestamp(record.get("ts")),
            "time": 0,
            "request": request,
            "response": {
                "status": 0,
                "statusText": "",
                "httpVersion": "",
                "cookies": [],
                "headers": [],
                "content": {"size": 0, "mimeType": ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": 0,
                "_antshield_incomplete": True,
            },
            "cache": {},
            "timings": {"send": 0, "wait": 0, "receive": 0},
            "serverIPAddress": str(record.get("dst_ip") or ""),
            "connection": str(record.get("scr_port") or ""),
            "_antshield": {
                "package_name": package,
                "source_file": str(source.relative_to(raw_root)),
                "record_id": record_id,
                "protocol": protocol,
                "is_foreground": record.get("is_foreground"),
                "pii_types": record_labels,
            },
        })

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "log": {
            "version": "1.2",
            "creator": {
                "name": "AntShield request-record converter",
                "version": "1.0",
            },
            "entries": entries,
        }
    }, indent=2), encoding="utf-8")

    return {
        "package": package,
        "source_files": len(list(raw_root.rglob(f"{package}.json"))),
        "har_entries": len(entries),
        "labelled_entries": labelled_entries,
        "label_counts": dict(sorted(labels.items())),
        "skipped": skipped,
        "response_limitation": "AntShield records contain no HTTP responses",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-root", type=Path, default=Path("raw_data"))
    parser.add_argument("--package", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(
        convert(args.raw_root, args.package, args.output), indent=2
    ))


if __name__ == "__main__":
    main()
