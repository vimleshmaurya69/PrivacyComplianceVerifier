import base64
import gzip
import hashlib
import json
import re
import zlib

from typing import Any, Dict, List
from urllib.parse import parse_qsl, unquote, urlsplit

from src.models.request import Request
from src.utils.protobuf_scanner import ProtobufScanner


class Requests:
    """Concrete request container used to manage the Request objects under analysis."""

    def __init__(self, requests: List[Request] | None = None):
        self._requests: List[Request] = list(requests or [])

    def __iter__(self):
        return iter(self._requests)

    def __len__(self):
        return len(self._requests)

    def __getitem__(self, index):
        return self._requests[index]

    def __contains__(self, item):
        return item in self._requests

    def append(self, request: Request) -> None:
        self._requests.append(request)

    def extend(self, requests) -> None:
        self._requests.extend(list(requests or []))

    def clear(self) -> None:
        self._requests.clear()

    def get(self, index: int, default=None):
        try:
            return self._requests[index]
        except IndexError:
            return default

    def find_by_url(self, url: str):
        for request in self._requests:
            if getattr(request, "url", None) == url:
                return request
        return None

    def to_list(self) -> List[Request]:
        return list(self._requests)


class SensitiveDataDetector:

    def __init__(self, requests: List[Request]):
        self.requests = requests

        # Request/response findings remain attached to each Request.
        # A separate index aggregates repeated observations of the
        # same sensitive artifact.
        self._unique_findings: Dict[tuple, dict] = {}

    # --------------------------------------------------
    # Redact sensitive values
    # --------------------------------------------------

    def redact_value(self, value):

        if value is None:
            return None

        value = str(value)

        if not value:
            return ""

        # Never export the complete sensitive value.
        if len(value) <= 4:
            return "****"

        return value[:2] + "..." + value[-2:]

    # --------------------------------------------------
    # Create finding
    # --------------------------------------------------

    def create_finding(self, finding_type, source, key, value, direction=None):

        return {
            "type": finding_type,
            "source": source,
            "direction": direction,
            "key": key,
            "value_redacted": self.redact_value(value),
            "_raw_value": value,
        }

    # --------------------------------------------------
    # Unique artifact aggregation
    # --------------------------------------------------

    def _fingerprint(self, value) -> str:
        """
        Create a stable internal fingerprint without storing
        the raw sensitive value.
        """

        normalized_value = "" if value is None else str(value)

        return hashlib.sha256(
            normalized_value.encode("utf-8", errors="replace")
        ).hexdigest()

    # --------------------------------------------------
    # Unique artifact aggregation
    # --------------------------------------------------

    def _record_unique_finding(
        self,
        finding: dict,
        request: Request,
        request_index: int,
    ) -> None:
        """
        Aggregate observations by sensitive type + value.

        The same sensitive value is considered one unique artifact
        even when it appears:
        - in different request/response sources
        - under different JSON keys
        - across different domains
        - across multiple requests
        """

        value = finding.get("_raw_value")

        fingerprint = self._fingerprint(value)

        # IMPORTANT:
        # Source and key are deliberately NOT part of the
        # unique-artifact identity.
        #
        # Example:
        #
        # Request Body -> email
        # Request Body -> personalData.onlineIds.email
        # Response Body -> email
        #
        # If the underlying value is identical, these are
        # observations of the same unique artifact.
        key = (
            finding.get("type", ""),
            fingerprint,
        )

        if key not in self._unique_findings:

            self._unique_findings[key] = {
                "type": finding.get("type", ""),
                "value_redacted": finding.get("value_redacted"),
                "occurrences": 0,
                "request_indices": set(),
                "domains": set(),
                "traffic_types": set(),
                "sources": set(),
                "directions": set(),
                "keys": set(),
            }

        aggregate = self._unique_findings[key]

        aggregate["occurrences"] += 1

        aggregate["request_indices"].add(request_index)

        if request.domain:

            aggregate["domains"].add(request.domain)

        if request.traffic_type:

            aggregate["traffic_types"].add(request.traffic_type)

        # Preserve every location where this artifact
        # was observed.
        if finding.get("source"):

            aggregate["sources"].add(finding.get("source"))

        if finding.get("direction"):

            aggregate["directions"].add(finding.get("direction"))

        if finding.get("key"):

            aggregate["keys"].add(str(finding.get("key")))

    def get_unique_findings(self) -> List[dict]:

        unique_findings = []

        for aggregate in self._unique_findings.values():

            unique_findings.append(
                {
                    "type": aggregate["type"],
                    "value_redacted": aggregate["value_redacted"],
                    "occurrences": aggregate["occurrences"],
                    "request_count": len(aggregate["request_indices"]),
                    "domains": sorted(aggregate["domains"]),
                    "traffic_types": sorted(aggregate["traffic_types"]),
                    "sources": sorted(aggregate["sources"]),
                    "directions": sorted(aggregate["directions"]),
                    "keys": sorted(aggregate["keys"]),
                }
            )

        return sorted(
            unique_findings,
            key=lambda item: (
                item["type"],
                item["value_redacted"] or "",
            ),
        )

    # --------------------------------------------------
    # Generic helpers
    # --------------------------------------------------

    def _normalize_key(self, key: Any) -> str:
        """
        Normalize parameter names so variations such as:

            user_email
            userEmail
            USER-EMAIL

        can be compared consistently.
        """

        key = str(key)

        # Convert camelCase to snake_case.
        key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)

        # Replace separators with underscores.
        key = re.sub(r"[^a-zA-Z0-9]+", "_", key)

        return key.lower().strip("_")

    def _is_email(self, value: Any) -> bool:

        if value is None:
            return False

        value = str(value).strip()

        pattern = r"^[A-Za-z0-9._%+-]+" r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

        return bool(re.fullmatch(pattern, value))

    def _find_emails(self, value: Any) -> List[str]:

        if value is None:
            return []

        value = str(value)

        pattern = r"[A-Za-z0-9._%+-]+" r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

        return re.findall(pattern, value)

    def _is_phone_number(self, value: Any) -> bool:

        if value is None:
            return False

        value = str(value).strip()

        # Remove common phone-number formatting.
        digits = re.sub(r"[^\d]", "", value)

        # Plausible international phone range.
        if len(digits) < 10 or len(digits) > 15:
            return False

        # Reject values containing alphabetic characters.
        if re.search(r"[A-Za-z]", value):
            return False

        return True

    def _looks_like_api_key(self, key: str, value: Any) -> bool:

        normalized_key = self._normalize_key(key)

        api_key_names = {
            "api_key",
            "apikey",
            "api_token",
            "apitoken",
            "access_key",
            "accesskey",
            "secret_key",
            "secretkey",
            "client_secret",
            "clientsecret",
        }

        if normalized_key not in api_key_names:
            return False

        if value is None:
            return False

        value = str(value).strip()

        if not value:
            return False

        if len(value) < 8:
            return False

        return True

    # --------------------------------------------------
    # Key-based classification
    # --------------------------------------------------

    def _classify_key_value(self, key, value):

        normalized_key = self._normalize_key(key)

        # Email
        email_keys = {
            "email", "email_address", "user_email", "useremail", "mail",
        }
        if normalized_key in email_keys or self._is_email(value):
            return "Email"

        # Phone/contact fields.  Plain numeric values require explicit field
        # context; international + numbers are handled by text scanning.
        phone_keys = {
            "phone", "phone_number", "phonenumber", "mobile",
            "mobile_number", "mobilenumber", "telephone",
            "telephone_number", "contact_number", "contactnumber",
            "contact_point", "contactpoint", "msisdn", "caller",
            "caller_number", "recipient", "recipient_number",
        }
        if normalized_key in phone_keys and self._is_phone_number(value):
            return "Phone"

        # Facebook/other platform user identifiers. These are identifiers of
        # an account/person, not phone numbers and should not be conflated.
        user_id_keys = {
            "user_id", "userid", "user_identifier", "useridentifier",
            "user", "c_user", "i_user", "account_id", "accountid",
        }
        if normalized_key in user_id_keys:
            text = str(value).strip() if value is not None else ""
            if text and len(text) <= 128:
                return "User ID"

        # Location
        if normalized_key in {"lat", "latitude"}:
            return "Latitude"
        if normalized_key in {"lon", "lng", "longitude"}:
            return "Longitude"

        if self._looks_like_api_key(key, value):
            return "API Key"

        # Authentication tokens. Keep Authorization Token taxonomy intact.
        auth_keys = {
            "authorization", "auth_token", "authtoken", "access_token",
            "accesstoken", "refresh_token", "refreshtoken",
            "bearer_token", "bearertoken", "token", "token_v2",
        }
        if normalized_key in auth_keys:
            return "Authorization Token"

        # CSRF/security tokens are distinct from authentication credentials.
        csrf_keys = {
            "csrf_token", "csrftoken", "csrf", "fb_dtsg", "dtsg",
            "xsrf_token", "xsrftoken", "xsrf",
        }
        if normalized_key in csrf_keys:
            return "CSRF Token"

        # Device identifiers
        device_id_keys = {
            "device_id", "deviceid", "android_id", "androidid",
            "advertising_id", "advertisingid", "ad_id", "adid",
        }
        if normalized_key in device_id_keys:
            return "Device ID"

        return None

    # --------------------------------------------------
    # URL / text signal helpers
    # --------------------------------------------------

    def _iter_url_query_pairs(self, url: Any):
        """Return every query occurrence, preserving duplicate keys."""
        if not url:
            return []
        try:
            return parse_qsl(urlsplit(str(url)).query, keep_blank_values=True)
        except Exception:
            return []

    def _get_url_path(self, url: Any) -> str:
        if not url:
            return ""
        try:
            return unquote(urlsplit(str(url)).path or "")
        except Exception:
            return ""

    def _looks_like_base64(self, value: Any) -> bool:
        if value is None:
            return False
        value = str(value).strip()
        if len(value) < 16 or len(value) > 65536 or len(value) % 4 != 0:
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value))

    def _decode_base64_candidates(self, value: Any) -> List[str]:
        if not self._looks_like_base64(value):
            return []
        raw = str(value).strip()
        candidates = [raw]
        # URL-safe base64 is common in query/form payloads.
        if "-" in raw or "_" in raw:
            candidates.append(raw.replace("-", "+").replace("_", "/"))
        results = []
        seen = set()
        for candidate in candidates:
            try:
                decoded = base64.b64decode(candidate, validate=True)
                if not decoded or len(decoded) > 1024 * 1024:
                    continue
                text = decoded.decode("utf-8", errors="ignore").strip()
                if not text or text in seen:
                    continue
                printable = sum(ch.isprintable() or ch.isspace() for ch in text)
                if printable / max(len(text), 1) < 0.85:
                    continue
                seen.add(text)
                results.append(text)
            except Exception:
                continue
        return results

    def _phone_context(self, key: Any) -> bool:
        normalized = self._normalize_key(key)
        return (
            len(normalized) <= 80
            and bool(re.fullmatch(r"[a-z0-9_.\[\]-]+", normalized))
            and bool(re.search(
                r"(?:phone|mobile|telephone|tel|contact|msisdn|caller|recipient|number)",
                normalized,
            ))
        )

    def _analyze_text_signals(self, value: Any, findings, source, key,
                              allow_phone=True, allow_base64=True):
        """Detect high-confidence artifacts without treating arbitrary JS as phone data."""
        if value is None:
            return
        text = str(value)

        for email in self._find_emails(text):
            findings.append(self.create_finding("Email", source, key, email))

        phone_context = self._phone_context(key)

        # International phone numbers have a strong lexical signal. Plain
        # 10-15 digit numbers are accepted only when the field is contextual.
        if allow_phone:
            international_candidates = re.findall(r"\+\d[\d .()\-]{8,14}\d", text)
            plain_candidates = (
                re.findall(r"(?<!\d)\d{10,15}(?!\d)", text)
                if phone_context else []
            )
            for candidate in international_candidates + plain_candidates:
                if self._is_phone_number(candidate):
                    findings.append(self.create_finding("Phone", source, key, candidate))

        if not allow_base64:
            return

        for decoded in self._decode_base64_candidates(text):
            # Base64 email detection is allowed because emails have a strong
            # pattern. Phone detection requires structured/contextual data.
            for email in self._find_emails(decoded):
                findings.append(self.create_finding(
                    "Email", source, f"{key}.__base64__", email
                ))

            try:
                decoded_json = json.loads(decoded)
            except (json.JSONDecodeError, TypeError, ValueError):
                decoded_json = None

            if isinstance(decoded_json, (dict, list)):
                for decoded_key, decoded_value in self._extract_json_pairs(decoded_json):
                    if not self._phone_context(decoded_key):
                        continue
                    if self._is_phone_number(decoded_value):
                        findings.append(self.create_finding(
                            "Phone", source,
                            f"{key}.__base64__.{decoded_key}", decoded_value
                        ))
                    for phone in re.findall(r"\+\d[\d .()\-]{8,14}\d", str(decoded_value)):
                        if self._is_phone_number(phone):
                            findings.append(self.create_finding(
                                "Phone", source,
                                f"{key}.__base64__.{decoded_key}", phone
                            ))

    # --------------------------------------------------
    # Body decoding / extraction
    # --------------------------------------------------

    def _decode_body(self, body, content_type=None, content_encoding=None):
        """Decode common HAR body encodings while preserving plain text fallback."""
        if body is None:
            return None
        if isinstance(body, bytes):
            raw = body
        else:
            text = str(body)
            # Most HAR bodies are already textual. latin-1 preserves byte values
            # when a compressed/binary body was decoded into a string.
            raw = text.encode("latin-1", errors="replace")

        encoding = (content_encoding or "").lower()
        encodings = [e.strip() for e in encoding.split(",") if e.strip()]
        candidates = [raw]

        for enc in reversed(encodings):
            current = candidates[-1]
            try:
                if enc in {"gzip", "x-gzip"}:
                    candidates.append(gzip.decompress(current))
                elif enc == "deflate":
                    try:
                        candidates.append(zlib.decompress(current))
                    except zlib.error:
                        candidates.append(zlib.decompress(current, -zlib.MAX_WBITS))
            except Exception:
                break

        decoded = candidates[-1]
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return decoded.decode("latin-1")
            except Exception:
                return None

    def _extract_json_pairs(self, data, parent_key="", depth=0, max_depth=32,
                            max_pairs=10000):
        if depth > max_depth:
            return []
        pairs = []
        if isinstance(data, dict):
            for key, value in data.items():
                if len(pairs) >= max_pairs:
                    break
                current_key = f"{parent_key}.{key}" if parent_key else str(key)
                if isinstance(value, (dict, list)):
                    pairs.extend(self._extract_json_pairs(
                        value, current_key, depth + 1, max_depth, max_pairs - len(pairs)
                    ))
                else:
                    pairs.append((current_key, value))
        elif isinstance(data, list):
            for index, value in enumerate(data):
                if len(pairs) >= max_pairs:
                    break
                current_key = f"{parent_key}[{index}]" if parent_key else str(index)
                if isinstance(value, (dict, list)):
                    pairs.extend(self._extract_json_pairs(
                        value, current_key, depth + 1, max_depth, max_pairs - len(pairs)
                    ))
                else:
                    pairs.append((current_key, value))
        return pairs

    # --------------------------------------------------
    # Structured body extraction
    # --------------------------------------------------

    def _extract_multipart_pairs(self, body, content_type):
        """Extract text fields from a multipart/form-data body."""
        if not body or not content_type:
            return []

        match = re.search(
            r'boundary=(?:"([^"]+)"|([^;]+))',
            content_type,
            re.IGNORECASE
        )

        if not match:
            return []

        boundary = match.group(1) or match.group(2)
        boundary = boundary.strip()

        if not boundary:
            return []

        delimiter = "--" + boundary
        parts = str(body).split(delimiter)

        pairs = []

        for part in parts:
            part = part.strip()

            if not part or part == "--":
                continue

            # Remove the final multipart terminator.
            if part.endswith("--"):
                part = part[:-2].rstrip()

            # Headers and content are separated by a blank line.
            if "\r\n\r\n" in part:
                headers_text, value = part.split("\r\n\r\n", 1)
            elif "\n\n" in part:
                headers_text, value = part.split("\n\n", 1)
            else:
                continue

            name_match = re.search(
                r'(?:^|;\s*)name="([^"]+)"',
                headers_text,
                re.IGNORECASE
            )

            if not name_match:
                name_match = re.search(
                    r'(?:^|;\s*)name=([^;\r\n]+)',
                    headers_text,
                    re.IGNORECASE
                )

            if not name_match:
                continue

            field_name = name_match.group(1).strip()
            value = value.strip("\r\n")

            # Avoid treating binary file uploads as text.
            filename_match = re.search(
                r'filename="[^"]*"',
                headers_text,
                re.IGNORECASE
            )

            if filename_match:
                part_content_type = re.search(
                    r'Content-Type:\s*([^\r\n]+)',
                    headers_text,
                    re.IGNORECASE
                )

                if (
                    not part_content_type
                    or not (
                        "text/" in part_content_type.group(1).lower()
                        or "json" in part_content_type.group(1).lower()
                    )
                ):
                    continue

            pairs.append((field_name, value))

        return pairs

    def _extract_body_pairs(self, body, body_type=None, content_type=None):
        if not body:
            return []
        if body_type == "multipart" or (content_type and "multipart/form-data" in content_type.lower()):
            return self._extract_multipart_pairs(body, content_type)

        try:
            parsed = json.loads(body)
            if isinstance(parsed, (dict, list)):
                return self._extract_json_pairs(parsed)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        try:
            parsed_pairs = parse_qsl(str(body), keep_blank_values=True)
            if parsed_pairs:
                return parsed_pairs
        except Exception:
            pass
        return []

    # --------------------------------------------------
    # gRPC / protobuf analysis
    # --------------------------------------------------

    def _analyze_grpc_body(self, body, findings, source="gRPC Body"):

        if not body:
            return

        # HAR normally gives us a string.
        # Convert it back to bytes without altering
        # the byte values represented by the string.
        if isinstance(body, str):

            body_bytes = body.encode("latin-1", errors="replace")

        elif isinstance(body, bytes):

            body_bytes = body

        else:

            return

        strings = ProtobufScanner.extract_strings(body_bytes)

        for value in strings:

            # --------------------------------------
            # Email
            # --------------------------------------

            emails = self._find_emails(value)

            for email in emails:

                findings.append(
                    self.create_finding("Email", source, "protobuf_string", email)
                )

            # --------------------------------------
            # Phone
            # --------------------------------------

            # Do not classify arbitrary numeric protobuf strings as phones.
            # Only accept explicitly formatted international numbers here.
            for phone in re.findall(r"\+\d[\d .()\-]{8,14}\d", str(value)):
                if self._is_phone_number(phone):
                    findings.append(
                        self.create_finding(
                            "Phone",
                            source,
                            "protobuf_string",
                            phone,
                        )
                    )

    # --------------------------------------------------
    # Body analysis
    # --------------------------------------------------

    def _analyze_body(self, body, findings, body_type=None, source="Request Body", content_type=None, content_encoding=None):
        if not body:
            return

        # Avoid pathological payloads while still allowing normal HAR bodies.
        try:
            body_length = len(body)
        except Exception:
            body_length = 0
        if body_length > 8 * 1024 * 1024:
            return

        decoded_body = self._decode_body(body, content_type, content_encoding)
        if decoded_body is None:
            return

        if body_type == "grpc":
            self._analyze_grpc_body(decoded_body, findings,
                                    "gRPC Body" if source == "Request Body" else "Response gRPC Body")
            return

        body_pairs = self._extract_body_pairs(decoded_body, body_type, content_type)
        for key, value in body_pairs:
            finding_type = self._classify_key_value(key, value)
            if finding_type:
                findings.append(self.create_finding(finding_type, source, key, value))

            signal_findings = []
            self._analyze_text_signals(
                value, signal_findings, source, key,
                allow_phone=True, allow_base64=True
            )
            findings.extend(signal_findings)

            # JSON embedded in a form/multipart field.
            if isinstance(value, str) and len(value) <= 1024 * 1024:
                try:
                    nested = json.loads(value)
                except (json.JSONDecodeError, TypeError, ValueError):
                    nested = None
                if isinstance(nested, (dict, list)):
                    for nested_key, nested_value in self._extract_json_pairs(nested, str(key)):
                        nested_type = self._classify_key_value(nested_key, nested_value)
                        if nested_type:
                            findings.append(self.create_finding(
                                nested_type, source, nested_key, nested_value
                            ))
                        nested_signals = []
                        self._analyze_text_signals(
                            nested_value, nested_signals, source, nested_key
                        )
                        findings.extend(nested_signals)

        # Free-form response/request text: retain strong email detection, but
        # do not scan arbitrary 10-digit sequences as phone numbers.
        if len(decoded_body) <= 2 * 1024 * 1024:
            for email in self._find_emails(decoded_body):
                findings.append(self.create_finding("Email", source, "email", email))

    # --------------------------------------------------
    # Analyze Requests + Responses

    # --------------------------------------------------

    def _header_value(self, headers, name):
        target = str(name).lower()
        for key, value in (headers or {}).items():
            if str(key).lower() == target:
                return value
        return None

    def analyze(self) -> List[Request]:
        self._unique_findings.clear()

        session_cookie_keys = {
            "session", "session_id", "sessionid", "session_token",
            "sessiontoken", "reddit_session", "seeker_session",
            "session_tracker",
        }

        for request_index, request in enumerate(self.requests):
            findings = []
            finding_signatures = set()

            def add_finding(finding_type, source, key, value, direction):
                signature = (
                    finding_type, source, str(key).lower(), self._fingerprint(value)
                )
                if signature in finding_signatures:
                    return
                finding_signatures.add(signature)
                findings.append(self.create_finding(
                    finding_type, source, key, value, direction=direction
                ))

            try:
                # URL path: scan emails and explicitly formatted international
                # phones, but never arbitrary 10-digit path segments.
                url_path = self._get_url_path(getattr(request, "url", ""))
                if url_path:
                    path_findings = []
                    self._analyze_text_signals(
                        url_path, path_findings, "URL Path", "path",
                        allow_phone=True, allow_base64=False
                    )
                    for f in path_findings:
                        add_finding(f.get("type"), "URL Path", f.get("key"),
                                    f.get("_raw_value"), "outbound")

                # Query parameters: preserve duplicates and analyze each value.
                query_pairs = list(getattr(request, "query_param_pairs", []) or [])
                if not query_pairs:
                    query_pairs = list(self._iter_url_query_pairs(getattr(request, "url", "")))
                query_pairs.extend(list((getattr(request, "query_params", {}) or {}).items()))
                for key, value in query_pairs:
                    finding_type = self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(finding_type, "Query Parameter", key, value, "outbound")
                    signals = []
                    self._analyze_text_signals(value, signals, "Query Parameter", key)
                    for f in signals:
                        add_finding(f.get("type"), "Query Parameter", f.get("key"),
                                    f.get("_raw_value"), "outbound")

                # Headers: all header names, not only Authorization.
                for key, value in (getattr(request, "headers", {}) or {}).items():
                    finding_type = self._classify_key_value(key, value)
                    if self._normalize_key(key) == "authorization":
                        finding_type = "Authorization Token"
                    if finding_type:
                        add_finding(finding_type, "Header", key, value, "outbound")
                    signals = []
                    self._analyze_text_signals(value, signals, "Header", key)
                    for f in signals:
                        add_finding(f.get("type"), "Header", f.get("key"),
                                    f.get("_raw_value"), "outbound")

                # Cookies: all cookie names plus session-cookie heuristic.
                for key, value in (getattr(request, "cookies", {}) or {}).items():
                    normalized = self._normalize_key(key)
                    finding_type = "Session Cookie" if (
                        normalized in session_cookie_keys or "session" in normalized
                    ) else self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(finding_type, "Cookie", key, value, "outbound")
                    signals = []
                    self._analyze_text_signals(value, signals, "Cookie", key)
                    for f in signals:
                        add_finding(f.get("type"), "Cookie", f.get("key"),
                                    f.get("_raw_value"), "outbound")

                # Request body
                body_findings = []
                self._analyze_body(
                    getattr(request, "body", None), body_findings,
                    getattr(request, "body_type", None), "Request Body",
                    getattr(request, "content_type", None),
                    self._header_value(getattr(request, "headers", {}), "content-encoding")
                )
                for f in body_findings:
                    add_finding(f.get("type"), f.get("source"), f.get("key"),
                                f.get("_raw_value"), "outbound")

                # Response headers
                for key, value in (getattr(request, "response_headers", {}) or {}).items():
                    finding_type = self._classify_key_value(key, value)
                    if self._normalize_key(key) == "authorization":
                        finding_type = "Authorization Token"
                    if finding_type:
                        add_finding(finding_type, "Response Header", key, value, "inbound")
                    signals = []
                    self._analyze_text_signals(value, signals, "Response Header", key)
                    for f in signals:
                        add_finding(f.get("type"), "Response Header", f.get("key"),
                                    f.get("_raw_value"), "inbound")

                # Response cookies
                for key, value in (getattr(request, "response_cookies", {}) or {}).items():
                    normalized = self._normalize_key(key)
                    finding_type = "Session Cookie" if (
                        normalized in session_cookie_keys or "session" in normalized
                    ) else self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(finding_type, "Response Cookie", key, value, "inbound")
                    signals = []
                    self._analyze_text_signals(value, signals, "Response Cookie", key)
                    for f in signals:
                        add_finding(f.get("type"), "Response Cookie", f.get("key"),
                                    f.get("_raw_value"), "inbound")

                # Response body
                response_findings = []
                self._analyze_body(
                    getattr(request, "response_body", None), response_findings,
                    getattr(request, "response_body_type", None), "Response Body",
                    getattr(request, "response_content_type", None),
                    self._header_value(getattr(request, "response_headers", {}), "content-encoding")
                )
                for f in response_findings:
                    add_finding(f.get("type"), f.get("source"), f.get("key"),
                                f.get("_raw_value"), "inbound")

            except Exception:
                # One malformed request/body must never abort the entire HAR.
                # Keep all successfully collected findings for this request.
                pass

            for finding in findings:
                self._record_unique_finding(finding, request, request_index)
                finding.pop("_raw_value", None)
            request.sensitive_data = findings

        return self.requests

