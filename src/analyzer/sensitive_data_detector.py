import base64
import gzip
import hashlib
import io
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

    _MAX_DECODED_BODY_BYTES = 8 * 1024 * 1024
    _MAX_STRUCTURED_JSON_RECURSION = 4
    _FREE_TEXT_CHUNK_SIZE = 512 * 1024
    _FREE_TEXT_CHUNK_OVERLAP = 512

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

    def create_finding(self, finding_type, source, key, value, direction=None,
                       occurrence_id=None):

        return {
            "type": finding_type,
            "source": source,
            "direction": direction,
            "key": key,
            "value_redacted": self.redact_value(value),
            "_raw_value": value,
            "_occurrence_id": occurrence_id,
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
        """Return email occurrences using bounded work per '@' marker."""
        if value is None:
            return []
        return [
            email
            for _, _, email in self._find_email_matches(str(value))
        ]

    @staticmethod
    def _find_email_matches(text):
        """Return bounded ``(start, end, value)`` email candidates."""
        local_characters = frozenset(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-"
        )
        domain_characters = frozenset(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
        )
        ascii_letters = frozenset(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        )
        matches = []
        marker = text.find("@")

        while marker >= 0:
            local_start = marker
            while (
                local_start > 0
                and marker - local_start < 64
                and text[local_start - 1] in local_characters
            ):
                local_start -= 1

            domain_end = marker + 1
            domain_limit = min(len(text), marker + 1 + 320)
            last_valid_end = None
            separator_dot = None
            tld_length = 0

            while (
                domain_end < domain_limit
                and text[domain_end] in domain_characters
            ):
                character = text[domain_end]
                relative_index = domain_end - marker - 1

                if character == ".":
                    separator_dot = relative_index
                    tld_length = 0
                elif separator_dot is not None and character in ascii_letters:
                    tld_length += 1
                    if separator_dot >= 1 and tld_length >= 2:
                        last_valid_end = domain_end + 1
                elif separator_dot is not None:
                    separator_dot = None
                    tld_length = 0

                domain_end += 1

            if local_start < marker and last_valid_end is not None:
                matches.append((
                    local_start,
                    last_valid_end,
                    text[local_start:last_valid_end],
                ))

            marker = text.find("@", marker + 1)

        return matches

    def _find_emails_in_body(self, text: str) -> List[str]:
        """Scan an accepted body with bounded work around each email marker."""
        if not text:
            return []

        emails = []
        seen_spans = set()
        chunk_size = self._FREE_TEXT_CHUNK_SIZE
        overlap = self._FREE_TEXT_CHUNK_OVERLAP

        if len(text) <= 2 * 1024 * 1024:
            chunks = ((0, text),)
        else:
            chunks = (
                (
                    max(0, offset - overlap),
                    text[
                        max(0, offset - overlap):
                        min(len(text), offset + chunk_size)
                    ],
                )
                for offset in range(0, len(text), chunk_size)
            )

        for chunk_start, chunk in chunks:
            for start, end, email in self._find_email_matches(chunk):
                span = (chunk_start + start, chunk_start + end)
                if span not in seen_spans:
                    seen_spans.add(span)
                    emails.append(email)

        return emails

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
        key_candidates = {normalized_key}

        # JSON paths retain useful evidence context (for example,
        # profile.device_id).  Classification must still consider the leaf
        # field name rather than only the complete path.
        raw_key = str(key)
        path_parts = [part for part in re.split(r"[.\[\]]+", raw_key) if part]
        if path_parts:
            key_candidates.add(self._normalize_key(path_parts[-1]))

            # Array paths end in a numeric index (for example,
            # device_id[0]). Preserve the nearest exact field segment without
            # treating arbitrary ancestors or substrings as aliases.
            if self._normalize_key(path_parts[-1]).isdigit():
                for part in reversed(path_parts[:-1]):
                    candidate = self._normalize_key(part)
                    if candidate and not candidate.isdigit():
                        key_candidates.add(candidate)
                        break

        # Common HTTP header aliases prefix an otherwise known field with X-.
        if normalized_key.startswith("x_"):
            key_candidates.add(normalized_key[2:])

        # Email
        # An email-shaped value is strong evidence regardless of its key. A
        # key alias alone must not turn arbitrary status/configuration text
        # into personal information.
        if self._is_email(value):
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
        if key_candidates & phone_keys and self._is_phone_number(value):
            return "Phone"

        # Facebook/other platform user identifiers. These are identifiers of
        # an account/person, not phone numbers and should not be conflated.
        user_id_keys = {
            "user_id", "userid", "user_identifier", "useridentifier",
            "user", "c_user", "i_user", "account_id", "accountid",
        }
        if key_candidates & user_id_keys:
            text = str(value).strip() if value is not None else ""
            if text and len(text) <= 128:
                return "User ID"

        # Location
        if key_candidates & {"lat", "latitude"}:
            return "Latitude"
        if key_candidates & {"lon", "lng", "longitude"}:
            return "Longitude"

        # Explicit personal-name fields are unambiguous enough to recognize at
        # any nesting depth. A bare nested `name` is ambiguous (for example,
        # config.name or error.name), so require person-related path context.
        if key_candidates & {"full_name", "fullname", "first_name", "last_name"}:
            return "Name"

        leaf_key = (
            self._normalize_key(path_parts[-1])
            if path_parts
            else normalized_key
        )
        if leaf_key == "name":
            if len(path_parts) <= 1:
                return "Name"

            personal_contexts = {
                "person", "profile", "user", "customer", "contact",
                "member", "passenger", "attendee", "recipient",
            }
            parent_contexts = {
                self._normalize_key(part)
                for part in path_parts[:-1]
            }
            if parent_contexts & personal_contexts:
                return "Name"

        if key_candidates & {"date_of_birth", "dateofbirth", "dob", "birth_date"}:
            return "Date of Birth"
        if key_candidates & {"address", "street_address", "postal_address"}:
            return "Address"
        if key_candidates & {"ip_address", "ipaddress", "ip"}:
            return "IP Address"

        if any(self._looks_like_api_key(candidate, value) for candidate in key_candidates):
            return "API Key"

        # Authentication tokens. Keep Authorization Token taxonomy intact.
        auth_keys = {
            "authorization", "auth_token", "authtoken", "access_token",
            "accesstoken", "refresh_token", "refreshtoken",
            "bearer_token", "bearertoken", "token", "token_v2",
        }
        if key_candidates & auth_keys:
            return "Authorization Token"

        # CSRF/security tokens are distinct from authentication credentials.
        csrf_keys = {
            "csrf_token", "csrftoken", "csrf", "fb_dtsg", "dtsg",
            "xsrf_token", "xsrftoken", "xsrf",
        }
        if key_candidates & csrf_keys:
            return "CSRF Token"

        # Device identifiers
        device_id_keys = {
            "device_id", "deviceid", "android_id", "androidid",
            "advertising_id", "advertisingid", "ad_id", "adid", "datr",
        }
        if key_candidates & device_id_keys:
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
        if len(value) < 16 or len(value) > 65536:
            return False
        if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", value):
            return False
        unpadded = value.rstrip("=")
        return len(unpadded) % 4 != 1

    def _decode_base64_candidates(self, value: Any) -> List[str]:
        if not self._looks_like_base64(value):
            return []
        raw = str(value).strip()
        results = []
        seen = set()
        padding = "=" * ((4 - len(raw) % 4) % 4)
        try:
            decoded = base64.b64decode(
                (raw + padding).encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
            if not decoded or len(decoded) > 1024 * 1024:
                return []
            text = decoded.decode("utf-8").strip()
            if not text:
                return []
            printable = sum(ch.isprintable() or ch.isspace() for ch in text)
            if printable / max(len(text), 1) < 0.85:
                return []
            if text not in seen:
                seen.add(text)
                results.append(text)
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
            return []
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
                              allow_phone=True, allow_base64=True,
                              _structured_depth=0, _structured_seen=None,
                              _occurrence_id=None):
        """Detect high-confidence artifacts without treating arbitrary JS as phone data."""
        if value is None:
            return
        text = str(value)

        for email in self._find_emails(text):
            findings.append(self.create_finding(
                "Email", source, key, email,
                occurrence_id=_occurrence_id,
            ))

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
                    findings.append(self.create_finding(
                        "Phone", source, key, candidate,
                        occurrence_id=_occurrence_id,
                    ))

        if not allow_base64:
            return

        for decoded in self._decode_base64_candidates(text):
            # Structured decoded JSON owns its nested evidence paths. Fall back
            # to free-text email scanning only when it is not structured JSON.
            structured = self._analyze_structured_json_value(
                decoded,
                findings,
                source,
                f"{key}.__base64__",
                _depth=_structured_depth + 1,
                _seen=_structured_seen,
                _occurrence_id=_occurrence_id,
            )
            if not structured:
                for email in self._find_emails(decoded):
                    findings.append(self.create_finding(
                        "Email", source, f"{key}.__base64__", email,
                        occurrence_id=_occurrence_id,
                    ))

    # --------------------------------------------------
    # Body decoding / extraction
    # --------------------------------------------------

    @staticmethod
    def _declared_charset(content_type):
        """Return a conservative supported codec declared by Content-Type."""
        match = re.search(
            r'(?:^|;)\s*charset\s*=\s*(?:"([^"\r\n]+)"|([^;\s\r\n]+))',
            str(content_type or ""),
            re.IGNORECASE,
        )
        if not match:
            return None

        declared = (match.group(1) or match.group(2) or "").strip().lower()
        aliases = {
            "utf-8": "utf-8",
            "utf8": "utf-8",
            "utf-16": "utf-16",
            "utf16": "utf-16",
            "utf-16le": "utf-16le",
            "utf16le": "utf-16le",
            "utf-16be": "utf-16be",
            "utf16be": "utf-16be",
            "iso-8859-1": "latin-1",
            "latin-1": "latin-1",
            "latin1": "latin-1",
            "us-ascii": "ascii",
            "ascii": "ascii",
        }
        return aliases.get(declared)

    def _decode_text_bytes(self, data, content_type=None):
        codecs = []
        declared = self._declared_charset(content_type)
        if declared:
            codecs.append(declared)
        codecs.extend(["utf-8", "latin-1"])

        seen = set()
        for codec in codecs:
            if codec in seen:
                continue
            seen.add(codec)
            try:
                return data.decode(codec)
            except (UnicodeDecodeError, UnicodeError, LookupError):
                continue
        return None

    def _decompress_limited(self, data, encoding):
        """Decompress known formats without exceeding the body-size limit."""
        limit = self._MAX_DECODED_BODY_BYTES

        if encoding in {"gzip", "x-gzip"}:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                decoded = stream.read(limit + 1)
            if len(decoded) > limit:
                raise ValueError("decompressed body exceeds limit")
            return decoded

        if encoding == "deflate":
            last_error = None
            for window_bits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    decompressor = zlib.decompressobj(window_bits)
                    decoded = decompressor.decompress(data, limit + 1)
                    if len(decoded) > limit or decompressor.unconsumed_tail:
                        raise ValueError("decompressed body exceeds limit")
                    decoded += decompressor.flush(limit + 1 - len(decoded))
                    if len(decoded) > limit or not decompressor.eof:
                        raise ValueError("invalid or oversized deflate body")
                    return decoded
                except (zlib.error, ValueError) as error:
                    last_error = error
            raise last_error or ValueError("invalid deflate body")

        return data

    def _decode_body(self, body, content_type=None, content_encoding=None):
        """Decode common HAR body encodings while preserving plain text fallback."""
        if body is None:
            return None

        encoding = (content_encoding or "").lower()
        encodings = [e.strip() for e in encoding.split(",") if e.strip()]

        if isinstance(body, str):
            recognized_encodings = {
                "base64", "gzip", "x-gzip", "deflate",
            }
            if not any(item in recognized_encodings for item in encodings):
                # HAR content.text is already Unicode. A charset declaration
                # describes the original entity bytes and must not reinterpret
                # the decoded Python string.
                return body

            try:
                raw = body.encode("latin-1")
            except UnicodeEncodeError:
                # A genuine compressed/base64 carrier is byte-representable.
                # Preserve decoded Unicode when a stale HTTP encoding header is
                # retained by the HAR producer.
                return body
            started_as_text = True
        elif isinstance(body, bytes):
            raw = body
            started_as_text = False
        else:
            raw = str(body).encode("latin-1", errors="replace")
            started_as_text = False

        candidates = [raw]

        for enc in reversed(encodings):
            current = candidates[-1]
            try:
                if enc == "base64":
                    decoded = base64.b64decode(current, validate=True)
                elif enc in {"gzip", "x-gzip"}:
                    decoded = self._decompress_limited(current, enc)
                elif enc == "deflate":
                    decoded = self._decompress_limited(current, enc)
                else:
                    continue
                if len(decoded) > self._MAX_DECODED_BODY_BYTES:
                    raise ValueError("decoded body exceeds limit")
                candidates.append(decoded)
            except Exception:
                if started_as_text and len(candidates) == 1:
                    return body
                break

        decoded = candidates[-1]
        return self._decode_text_bytes(decoded, content_type)

    @staticmethod
    def _normalized_media_type(content_type):
        """Return the lower-case MIME type without parameters."""
        return str(content_type or "").split(";", 1)[0].strip().lower()

    def _decode_body_bytes(self, body, content_encoding=None):
        """Decode HAR/HTTP body encodings without converting payload bytes to text."""
        if body is None:
            return None

        encoding = (content_encoding or "").lower()
        encodings = [item.strip() for item in encoding.split(",") if item.strip()]

        try:
            if isinstance(body, bytes):
                decoded = body
            elif "base64" in encodings:
                decoded = str(body).encode("ascii")
            else:
                decoded = str(body).encode("latin-1")
        except (UnicodeEncodeError, TypeError, ValueError):
            return None

        for item in reversed(encodings):
            try:
                if item == "base64":
                    decoded = base64.b64decode(decoded, validate=True)
                elif item in {"gzip", "x-gzip"}:
                    decoded = self._decompress_limited(decoded, item)
                elif item == "deflate":
                    decoded = self._decompress_limited(decoded, item)
                if len(decoded) > self._MAX_DECODED_BODY_BYTES:
                    return None
            except Exception:
                return None

        return decoded

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

    def _analyze_structured_json_value(self, value, findings, source, parent_key,
                                       _depth=0, _seen=None,
                                       _occurrence_id=None):
        """Analyze explicitly JSON-shaped values with bounded string recursion."""
        if _depth >= self._MAX_STRUCTURED_JSON_RECURSION:
            return False
        if not isinstance(value, str) or len(value) > 1024 * 1024:
            return False

        text = value.lstrip()
        if not text.startswith(("{", "[")):
            return False

        marker = (
            str(parent_key),
            hashlib.sha256(text.encode("utf-8", errors="replace")).digest(),
        )
        seen = set(_seen or ())
        if marker in seen:
            return False
        seen.add(marker)

        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
            return False

        if not isinstance(parsed, (dict, list)):
            return False

        for nested_key, nested_value in self._extract_json_pairs(parsed, str(parent_key)):
            nested_type = self._classify_key_value(nested_key, nested_value)
            if nested_type:
                findings.append(self.create_finding(
                    nested_type, source, nested_key, nested_value,
                    occurrence_id=_occurrence_id,
                ))

            nested_structured = self._analyze_structured_json_value(
                nested_value,
                findings,
                source,
                nested_key,
                _depth=_depth + 1,
                _seen=seen,
                _occurrence_id=_occurrence_id,
            )

            if not nested_structured:
                self._analyze_text_signals(
                    nested_value,
                    findings,
                    source,
                    nested_key,
                    _structured_depth=_depth,
                    _structured_seen=seen,
                    _occurrence_id=_occurrence_id,
                )

        return True

    # --------------------------------------------------
    # Structured body extraction
    # --------------------------------------------------

    @staticmethod
    def _extract_multipart_boundary(content_type):
        """Extract an exact, bounded MIME boundary parameter."""
        match = re.search(
            r'(?:^|;)\s*boundary\s*=\s*'
            r'(?:(?:"([^"\r\n]+)")|([^;"\s\r\n]+))\s*(?=;|$)',
            str(content_type or ""),
            re.IGNORECASE,
        )
        if not match:
            return None

        boundary = (match.group(1) or match.group(2) or "").strip()
        if not boundary or len(boundary) > 200:
            return None

        return boundary

    def _extract_multipart_pairs(self, body, content_type):
        """Extract text fields from a multipart/form-data body."""
        if not body or not content_type:
            return []

        pairs = []

        for headers, value in self._extract_multipart_container_parts(
            body, content_type
        ):
            disposition = headers.get("content-disposition", "")
            part_content_type = headers.get("content-type", "")
            part_media_type = self._normalized_media_type(part_content_type)

            name_match = re.search(
                r'(?:^|;\s*)name="([^"]+)"',
                disposition,
                re.IGNORECASE
            )

            if not name_match:
                name_match = re.search(
                    r'(?:^|;\s*)name=([^;\r\n]+)',
                    disposition,
                    re.IGNORECASE
                )

            filename_parameter = re.search(
                r'(?:^|;)\s*filename(?:\*)?\s*(?:=|(?=;|$))',
                disposition,
                re.IGNORECASE
            )

            explicitly_textual = (
                part_media_type.startswith("text/")
                or part_media_type == "application/json"
                or part_media_type.endswith("+json")
                or part_media_type == "application/x-www-form-urlencoded"
            )

            # A declared non-text MIME type is binary regardless of whether
            # Content-Disposition includes filename=. Undeclared named fields
            # retain normal HTML form behavior and are treated as text.
            if part_media_type and not explicitly_textual:
                continue
            if filename_parameter and not explicitly_textual:
                continue

            if name_match:
                field_name = name_match.group(1).strip()
            elif explicitly_textual:
                field_name = "multipart_part"
            else:
                continue

            pairs.append((field_name, value))

        return pairs

    def _extract_multipart_container_parts(self, body, content_type):
        """Return bounded MIME parts for multipart/mixed or multipart/related."""
        if not body or not content_type:
            return []

        boundary = self._extract_multipart_boundary(content_type)
        if not boundary:
            return []

        parts = []
        body_text = str(body)
        boundary_line = re.compile(
            rf"(?m)^--{re.escape(boundary)}(--)?[ \t]*(?:\r?\n|$)"
        )
        boundaries = boundary_line.finditer(body_text)

        try:
            current_boundary = next(boundaries)
        except StopIteration:
            return []

        if current_boundary.group(1):
            return []

        # The complete body is already capped by _analyze_body. Bound part
        # count and header size independently to avoid pathological MIME data.
        processed_parts = 0
        while processed_parts < 256:
            try:
                next_boundary = next(boundaries)
                raw_part = body_text[current_boundary.end():next_boundary.start()]
            except StopIteration:
                # Preserve best-effort handling of a final truncated part.
                next_boundary = None
                raw_part = body_text[current_boundary.end():]

            processed_parts += 1
            final_part = next_boundary is None or bool(next_boundary.group(1))
            if not final_part:
                current_boundary = next_boundary

            part = raw_part.lstrip("\r\n")
            part = part.rstrip("\r\n")

            if "\r\n\r\n" in part:
                header_text, payload = part.split("\r\n\r\n", 1)
            elif "\n\n" in part:
                header_text, payload = part.split("\n\n", 1)
            else:
                if final_part:
                    break
                continue

            if len(header_text) > 64 * 1024:
                if final_part:
                    break
                continue

            headers = {}
            for line in header_text.splitlines():
                name, separator, header_value = line.partition(":")
                if separator and name.strip():
                    headers[name.strip().lower()] = header_value.strip()

            parts.append((headers, payload.rstrip("\r\n")))

            if final_part:
                break

        return parts

    @staticmethod
    def _extract_embedded_http_body(part_body):
        """Extract only an embedded HTTP entity body and its entity headers."""
        if "\r\n\r\n" in part_body:
            header_text, body = part_body.split("\r\n\r\n", 1)
        elif "\n\n" in part_body:
            header_text, body = part_body.split("\n\n", 1)
        else:
            return None, None, None

        headers = {}
        for line in header_text.splitlines()[1:]:
            name, separator, value = line.partition(":")
            if separator and name.strip():
                headers[name.strip().lower()] = value.strip()

        return body, headers.get("content-type"), headers.get("content-encoding")

    def _multipart_part_body_type(self, content_type):
        media_type = self._normalized_media_type(content_type)
        if media_type == "application/grpc":
            return "grpc"
        if media_type == "application/x-protobuf":
            return "binary"
        if media_type == "application/x-www-form-urlencoded":
            return "form"
        if media_type in {"multipart/form-data", "multipart/mixed", "multipart/related"}:
            return "multipart"
        if media_type == "application/json" or media_type.endswith("+json"):
            return "json"
        if media_type.startswith("text/"):
            return "text"
        return None

    def _analyze_multipart_container(self, body, findings, source, content_type,
                                     multipart_depth):
        if multipart_depth >= 4:
            return

        for headers, part_body in self._extract_multipart_container_parts(
            body, content_type
        ):
            part_content_type = headers.get("content-type", "")
            part_encoding = headers.get("content-encoding")

            if self._normalized_media_type(part_content_type) == "application/http":
                part_body, part_content_type, part_encoding = (
                    self._extract_embedded_http_body(part_body)
                )
                if part_body is None or not part_content_type:
                    continue

            part_body_type = self._multipart_part_body_type(part_content_type)
            if part_body_type is None:
                # Unknown/binary MIME parts are deliberately not scanned.
                continue

            self._analyze_body(
                part_body,
                findings,
                part_body_type,
                source,
                part_content_type,
                part_encoding,
                _multipart_depth=multipart_depth + 1,
            )

    def _extract_body_pairs(self, body, body_type=None, content_type=None):
        if not body:
            return []
        if body_type == "multipart" or (content_type and "multipart/form-data" in content_type.lower()):
            return self._extract_multipart_pairs(body, content_type)

        try:
            parsed = json.loads(body)
            if isinstance(parsed, (dict, list)):
                return self._extract_json_pairs(parsed)
        except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
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

    def _iter_grpc_messages(self, body: bytes):
        """Yield every complete protobuf message carried by a gRPC payload."""
        offset = 0
        yielded = False

        while offset + 5 <= len(body):
            compressed = body[offset]
            message_length = int.from_bytes(body[offset + 1:offset + 5], "big")
            end = offset + 5 + message_length

            if compressed not in {0, 1} or end > len(body):
                break

            message = body[offset + 5:end]
            offset = end

            if compressed:
                # gRPC commonly uses gzip.  Some captures label deflate
                # payloads equivalently, so accept either successful decode.
                try:
                    message = self._decompress_limited(message, "gzip")
                except Exception:
                    try:
                        message = self._decompress_limited(message, "deflate")
                    except Exception:
                        continue

            yielded = True
            yield message

        if not yielded:
            # Preserve the existing best-effort behavior for non-framed or
            # malformed protobuf bodies.
            yield body

    def _analyze_grpc_body(self, body, findings, source="gRPC Body"):

        if not body:
            return

        if not isinstance(body, bytes):
            return

        for message in self._iter_grpc_messages(body):
            # ProtobufScanner expects a gRPC envelope; wrap each individual
            # message so every frame is parsed independently.
            frame = b"\x00" + len(message).to_bytes(4, "big") + message
            strings = ProtobufScanner.extract_strings(frame)

            self._analyze_protobuf_strings(strings, findings, source)

    def _analyze_raw_protobuf_body(self, body, findings, source="Protobuf Body"):
        if not body:
            return

        strings = ProtobufScanner.extract_raw_strings(body)
        self._analyze_protobuf_strings(strings, findings, source)

    def _analyze_protobuf_strings(self, strings, findings, source):
        """Detect only strong string signals exposed by the protobuf scanner."""

        for value in strings:
            occurrence_id = object()

            # --------------------------------------
            # Email
            # --------------------------------------

            emails = self._find_emails(value)

            for email in emails:

                findings.append(
                    self.create_finding(
                        "Email", source, "protobuf_string", email,
                        occurrence_id=occurrence_id,
                    )
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
                            occurrence_id=occurrence_id,
                        )
                    )

    # --------------------------------------------------
    # Body analysis
    # --------------------------------------------------

    def _analyze_body(self, body, findings, body_type=None, source="Request Body", content_type=None,
                      content_encoding=None, body_param_pairs=None,
                      body_param_pairs_reconciled=False, _multipart_depth=0):
        body_param_pairs = list(body_param_pairs or [])
        if not body and not body_param_pairs:
            return

        # Avoid pathological payloads while still allowing normal HAR bodies.
        try:
            body_length = len(body)
        except Exception:
            body_length = 0
        if body_length > 8 * 1024 * 1024:
            return

        media_type = self._normalized_media_type(content_type)

        if media_type == "application/x-protobuf":
            protobuf_body = self._decode_body_bytes(body, content_encoding)
            if protobuf_body is None:
                return
            self._analyze_raw_protobuf_body(
                protobuf_body,
                findings,
                "Protobuf Body" if source == "Request Body" else "Response Protobuf Body",
            )
            return

        if body_type == "grpc" or media_type == "application/grpc":
            grpc_body = self._decode_body_bytes(body, content_encoding)
            if grpc_body is None:
                return
            self._analyze_grpc_body(
                grpc_body,
                findings,
                "gRPC Body" if source == "Request Body" else "Response gRPC Body",
            )
            return

        decoded_body = ""
        if body:
            decoded_body = self._decode_body(body, content_type, content_encoding)
            if decoded_body is None:
                return

        if media_type in {"multipart/mixed", "multipart/related"}:
            self._analyze_multipart_container(
                decoded_body, findings, source, content_type, _multipart_depth
            )
            return

        parsed_body_pairs = self._extract_body_pairs(
            decoded_body, body_type, content_type
        )

        # Merge exact pair occurrences rather than concatenating two parser
        # representations of the same body. Distinct repeated occurrences and
        # params-only values remain represented independently.
        body_pairs = list(parsed_body_pairs)
        if body_param_pairs_reconciled:
            body_pairs.extend(body_param_pairs)
        else:
            represented_pairs = {}
            for pair in parsed_body_pairs:
                represented_pairs[pair] = represented_pairs.get(pair, 0) + 1
            for pair in body_param_pairs:
                if represented_pairs.get(pair, 0):
                    represented_pairs[pair] -= 1
                else:
                    body_pairs.append(pair)

        body_findings_start = len(findings)
        for key, value in body_pairs:
            occurrence_id = object()
            finding_type = self._classify_key_value(key, value)
            if finding_type:
                findings.append(self.create_finding(
                    finding_type, source, key, value,
                    occurrence_id=occurrence_id,
                ))

            # Structured carriers own their nested evidence. Text scanning is
            # the safe fallback for ordinary or malformed values.
            structured = self._analyze_structured_json_value(
                value, findings, source, key,
                _occurrence_id=occurrence_id,
            )
            if not structured:
                signal_findings = []
                self._analyze_text_signals(
                    value, signal_findings, source, key,
                    allow_phone=True, allow_base64=True,
                    _occurrence_id=occurrence_id,
                )
                findings.extend(signal_findings)

        # Free-form response/request text: retain strong email detection, but
        # do not scan arbitrary 10-digit sequences as phone numbers.
        if media_type not in {
            "multipart/form-data", "multipart/mixed", "multipart/related"
        }:
            represented_emails = {}
            for finding in findings[body_findings_start:]:
                if finding.get("type") != "Email":
                    continue
                fingerprint = self._fingerprint(finding.get("_raw_value"))
                represented_emails[fingerprint] = (
                    represented_emails.get(fingerprint, 0) + 1
                )

            for email in self._find_emails_in_body(decoded_body):
                fingerprint = self._fingerprint(email)
                if represented_emails.get(fingerprint, 0):
                    represented_emails[fingerprint] -= 1
                    continue
                findings.append(self.create_finding(
                    "Email", source, "email", email,
                    occurrence_id=object(),
                ))

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
            "session_tracker", "xs",
        }

        for request_index, request in enumerate(self.requests):
            findings = []
            finding_signatures = set()

            def add_finding(finding_type, source, key, value, direction,
                            occurrence_id=None):
                signature = (
                    occurrence_id,
                    finding_type,
                    source,
                    str(key).lower(),
                    self._fingerprint(value),
                )
                if signature in finding_signatures:
                    return
                finding_signatures.add(signature)
                findings.append(self.create_finding(
                    finding_type, source, key, value, direction=direction,
                    occurrence_id=occurrence_id,
                ))

            try:
                # URL path: scan emails and explicitly formatted international
                # phones, but never arbitrary 10-digit path segments.
                url_path = self._get_url_path(getattr(request, "url", ""))
                if url_path:
                    occurrence_id = object()
                    path_findings = []
                    self._analyze_text_signals(
                        url_path, path_findings, "URL Path", "path",
                        allow_phone=True, allow_base64=False,
                        _occurrence_id=occurrence_id,
                    )
                    for f in path_findings:
                        add_finding(f.get("type"), "URL Path", f.get("key"),
                                    f.get("_raw_value"), "outbound",
                                    f.get("_occurrence_id"))

                # Query parameters: preserve duplicates and analyze each value.
                query_pairs = list(getattr(request, "query_param_pairs", []) or [])
                if not query_pairs:
                    query_pairs = list(self._iter_url_query_pairs(getattr(request, "url", "")))
                if not query_pairs:
                    query_pairs = list((getattr(request, "query_params", {}) or {}).items())
                for key, value in query_pairs:
                    occurrence_id = object()
                    finding_type = self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(
                            finding_type, "Query Parameter", key, value,
                            "outbound", occurrence_id,
                        )
                    structured = []
                    is_structured = self._analyze_structured_json_value(
                        value, structured, "Query Parameter", key,
                        _occurrence_id=occurrence_id,
                    )
                    for f in structured:
                        add_finding(f.get("type"), "Query Parameter", f.get("key"),
                                    f.get("_raw_value"), "outbound",
                                    f.get("_occurrence_id"))
                    if not is_structured:
                        signals = []
                        self._analyze_text_signals(
                            value, signals, "Query Parameter", key,
                            _occurrence_id=occurrence_id,
                        )
                        for f in signals:
                            add_finding(
                                f.get("type"), "Query Parameter", f.get("key"),
                                f.get("_raw_value"), "outbound",
                                f.get("_occurrence_id"),
                            )

                # Headers: all header names, not only Authorization.
                request_header_pairs = list(
                    getattr(request, "header_pairs", []) or []
                ) or list((getattr(request, "headers", {}) or {}).items())
                for key, value in request_header_pairs:
                    occurrence_id = object()
                    finding_type = self._classify_key_value(key, value)
                    if self._normalize_key(key) == "authorization":
                        finding_type = "Authorization Token"
                    if finding_type:
                        add_finding(
                            finding_type, "Header", key, value,
                            "outbound", occurrence_id,
                        )
                    signals = []
                    self._analyze_text_signals(
                        value, signals, "Header", key,
                        _occurrence_id=occurrence_id,
                    )
                    for f in signals:
                        add_finding(f.get("type"), "Header", f.get("key"),
                                    f.get("_raw_value"), "outbound",
                                    f.get("_occurrence_id"))

                # Cookies: all cookie names plus session-cookie heuristic.
                request_cookie_pairs = list(
                    getattr(request, "cookie_pairs", []) or []
                ) or list((getattr(request, "cookies", {}) or {}).items())
                for key, value in request_cookie_pairs:
                    occurrence_id = object()
                    normalized = self._normalize_key(key)
                    finding_type = "Session Cookie" if (
                        normalized in session_cookie_keys or "session" in normalized
                    ) else self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(
                            finding_type, "Cookie", key, value,
                            "outbound", occurrence_id,
                        )
                    structured = []
                    is_structured = self._analyze_structured_json_value(
                        value, structured, "Cookie", key,
                        _occurrence_id=occurrence_id,
                    )
                    for f in structured:
                        add_finding(f.get("type"), "Cookie", f.get("key"),
                                    f.get("_raw_value"), "outbound",
                                    f.get("_occurrence_id"))
                    if not is_structured:
                        signals = []
                        self._analyze_text_signals(
                            value, signals, "Cookie", key,
                            _occurrence_id=occurrence_id,
                        )
                        for f in signals:
                            add_finding(
                                f.get("type"), "Cookie", f.get("key"),
                                f.get("_raw_value"), "outbound",
                                f.get("_occurrence_id"),
                            )

                # Request body
                body_findings = []
                self._analyze_body(
                    getattr(request, "body", None), body_findings,
                    getattr(request, "body_type", None), "Request Body",
                    getattr(request, "content_type", None),
                    getattr(request, "body_encoding", None)
                    or self._header_value(getattr(request, "headers", {}), "content-encoding"),
                    getattr(request, "body_param_pairs", []),
                    getattr(request, "body_param_pairs_reconciled", False),
                )
                for f in body_findings:
                    add_finding(f.get("type"), f.get("source"), f.get("key"),
                                f.get("_raw_value"), "outbound",
                                f.get("_occurrence_id"))

                # Response headers
                response_header_pairs = list(
                    getattr(request, "response_header_pairs", []) or []
                ) or list((getattr(request, "response_headers", {}) or {}).items())
                for key, value in response_header_pairs:
                    occurrence_id = object()
                    finding_type = self._classify_key_value(key, value)
                    if self._normalize_key(key) == "authorization":
                        finding_type = "Authorization Token"
                    if finding_type:
                        add_finding(
                            finding_type, "Response Header", key, value,
                            "inbound", occurrence_id,
                        )
                    signals = []
                    self._analyze_text_signals(
                        value, signals, "Response Header", key,
                        _occurrence_id=occurrence_id,
                    )
                    for f in signals:
                        add_finding(f.get("type"), "Response Header", f.get("key"),
                                    f.get("_raw_value"), "inbound",
                                    f.get("_occurrence_id"))

                # Response cookies
                response_cookie_pairs = list(
                    getattr(request, "response_cookie_pairs", []) or []
                ) or list((getattr(request, "response_cookies", {}) or {}).items())
                for key, value in response_cookie_pairs:
                    occurrence_id = object()
                    normalized = self._normalize_key(key)
                    finding_type = "Session Cookie" if (
                        normalized in session_cookie_keys or "session" in normalized
                    ) else self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(
                            finding_type, "Response Cookie", key, value,
                            "inbound", occurrence_id,
                        )
                    structured = []
                    is_structured = self._analyze_structured_json_value(
                        value, structured, "Response Cookie", key,
                        _occurrence_id=occurrence_id,
                    )
                    for f in structured:
                        add_finding(f.get("type"), "Response Cookie", f.get("key"),
                                    f.get("_raw_value"), "inbound",
                                    f.get("_occurrence_id"))
                    if not is_structured:
                        signals = []
                        self._analyze_text_signals(
                            value, signals, "Response Cookie", key,
                            _occurrence_id=occurrence_id,
                        )
                        for f in signals:
                            add_finding(
                                f.get("type"), "Response Cookie", f.get("key"),
                                f.get("_raw_value"), "inbound",
                                f.get("_occurrence_id"),
                            )

                # Response body
                response_findings = []
                self._analyze_body(
                    getattr(request, "response_body", None), response_findings,
                    getattr(request, "response_body_type", None), "Response Body",
                    getattr(request, "response_content_type", None),
                    getattr(request, "response_body_encoding", None)
                    or self._header_value(getattr(request, "response_headers", {}), "content-encoding")
                )
                for f in response_findings:
                    add_finding(f.get("type"), f.get("source"), f.get("key"),
                                f.get("_raw_value"), "inbound",
                                f.get("_occurrence_id"))

            except Exception:
                # One malformed request/body must never abort the entire HAR.
                # Keep all successfully collected findings for this request.
                pass

            for finding in findings:
                self._record_unique_finding(finding, request, request_index)
                finding.pop("_raw_value", None)
                finding.pop("_occurrence_id", None)
            request.sensitive_data = findings

        return self.requests

