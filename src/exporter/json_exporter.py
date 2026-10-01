import json
import os
import re
from dataclasses import asdict
from typing import List, Dict
from urllib.parse import urlsplit, urlunsplit

from src.models.request import Request


class JSONExporter:
    """
    Exports framework results to JSON files.
    """

    def __init__(self, output_directory: str):

        self.output_directory = output_directory

        os.makedirs(self.output_directory, exist_ok=True)

    @staticmethod
    def _safe_metadata_key(key):
        if key is None:
            return None
        text = str(key)
        if len(text) > 256 or re.search(
            r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}",
            text,
        ):
            return "[REDACTED_DYNAMIC_KEY]"
        phone = re.search(
            r"(?<!\d)(\+?\d[\d .()\-]{8,14}\d)(?!\d)", text
        )
        if phone:
            digits = re.sub(r"\D", "", phone.group(1))
            if 10 <= len(digits) <= 15:
                return "[REDACTED_DYNAMIC_KEY]"
        try:
            parsed = urlsplit(text)
            if parsed.scheme and (parsed.username is not None or parsed.password is not None):
                return "[REDACTED_DYNAMIC_KEY]"
        except ValueError:
            return "[REDACTED_DYNAMIC_KEY]"
        return key

    def _redact_mapping(self, mapping):
        if not isinstance(mapping, dict):
            return mapping
        return {
            self._safe_metadata_key(key): (
                "[REDACTED]" if value not in (None, "") else value
            )
            for key, value in mapping.items()
        }

    def _redact_pairs(self, pairs):
        if not isinstance(pairs, list):
            return pairs
        return [
            [self._safe_metadata_key(key),
             "[REDACTED]" if value not in (None, "") else value]
            for key, value in pairs
        ]

    def _redact_query_values(self, values):
        if not isinstance(values, dict):
            return values
        return {
            self._safe_metadata_key(key): [
                "[REDACTED]" if value not in (None, "") else value
                for value in items
            ]
            for key, items in values.items()
        }

    @staticmethod
    def _safe_url(url):
        """Retain only the origin; paths, queries, and fragments may hold PII."""
        try:
            parts = urlsplit(str(url or ""))
            if not parts.scheme or not parts.netloc:
                return "[REDACTED]" if url else ""
            host = parts.hostname
            if not host:
                return "[REDACTED]" if url else ""
            authority = f"[{host}]" if ":" in host else host
            if parts.port is not None:
                authority = f"{authority}:{parts.port}"
            return urlunsplit((parts.scheme, authority, "/", "", ""))
        except (TypeError, ValueError):
            return "[REDACTED]" if url else ""

    def _sanitize_evidence_document(self, value, parent_key=None):
        """Copy an exported result while sanitizing value-shaped key metadata."""
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == "key":
                    result[key] = self._safe_metadata_key(item)
                elif key == "keys" and isinstance(item, list):
                    result[key] = [self._safe_metadata_key(part) for part in item]
                else:
                    result[key] = self._sanitize_evidence_document(item, key)
            return result
        if isinstance(value, list):
            return [
                self._sanitize_evidence_document(item, parent_key)
                for item in value
            ]
        return value

    def sanitize_evidence_document(self, value):
        """Return an export-safe copy of an evidence-bearing document."""
        return self._sanitize_evidence_document(value)

    def _safe_request(self, request):
        item = asdict(request)
        item["url"] = self._safe_url(item.get("url"))

        for field in (
            "headers", "query_params", "cookies",
            "response_headers", "response_cookies",
        ):
            item[field] = self._redact_mapping(item.get(field))

        for field in (
            "header_pairs", "query_param_pairs", "body_param_pairs",
            "cookie_pairs", "response_header_pairs", "response_cookie_pairs",
        ):
            item[field] = self._redact_pairs(item.get(field))

        item["query_param_values"] = self._redact_query_values(
            item.get("query_param_values")
        )
        item["sensitive_data"] = self._sanitize_evidence_document(
            item.get("sensitive_data", [])
        )

        for field in ("body", "response_body"):
            if item.get(field) not in (None, ""):
                item[field] = "[REDACTED]"

        item["raw_fields_redacted"] = True
        return item

    def export_requests(self, requests: List[Request]):

        output = []

        for request in requests:
            output.append(self._safe_request(request))

        file_path = os.path.join(
            self.output_directory,
            "classified_requests.json"
        )

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(output, file, indent=4)

        print("[OK] classified_requests.json exported")

    def export_statistics(self, statistics: Dict):

        file_path = os.path.join(
            self.output_directory,
            "statistics.json"
        )

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(statistics, file, indent=4)

        print("[OK] statistics.json exported")

    def export_privacy_inventory(self, inventory: Dict):

        file_path = os.path.join(
            self.output_directory,
            "privacy_inventory.json"
        )

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(self._sanitize_evidence_document(inventory), file, indent=4)

        print("[OK] privacy_inventory.json exported")

    def export_sensitive_artifacts(self, artifacts: List[dict]):

        file_path = os.path.join(
            self.output_directory,
            "sensitive_artifacts.json"
        )

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(self._sanitize_evidence_document(artifacts), file, indent=4)

        print("[OK] sensitive_artifacts.json exported")
