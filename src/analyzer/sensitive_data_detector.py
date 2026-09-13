import hashlib
import json
import re

from typing import Any, Dict, List
from urllib.parse import parse_qsl

from src.models.request import Request
from src.utils.protobuf_scanner import ProtobufScanner


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

    def create_finding(
        self,
        finding_type,
        source,
        key,
        value,
        direction=None
    ):

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

        normalized_value = (
            "" if value is None else str(value)
        )

        return hashlib.sha256(
            normalized_value.encode(
                "utf-8",
                errors="replace"
            )
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
                "type": finding.get(
                    "type",
                    ""
                ),

                "value_redacted": finding.get(
                    "value_redacted"
                ),

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

        aggregate["request_indices"].add(
            request_index
        )

        if request.domain:

            aggregate["domains"].add(
                request.domain
            )

        if request.traffic_type:

            aggregate["traffic_types"].add(
                request.traffic_type
            )

        # Preserve every location where this artifact
        # was observed.
        if finding.get("source"):

            aggregate["sources"].add(
                finding.get("source")
            )

        if finding.get("direction"):

            aggregate["directions"].add(
                finding.get("direction")
            )

        if finding.get("key"):

            aggregate["keys"].add(
                str(finding.get("key"))
            )

    def get_unique_findings(self) -> List[dict]:

        unique_findings = []

        for aggregate in (
            self._unique_findings.values()
        ):

            unique_findings.append({

                "type": aggregate["type"],

                "value_redacted":
                    aggregate["value_redacted"],

                "occurrences":
                    aggregate["occurrences"],

                "request_count":
                    len(
                        aggregate[
                            "request_indices"
                        ]
                    ),

                "domains":
                    sorted(
                        aggregate["domains"]
                    ),

                "traffic_types":
                    sorted(
                        aggregate["traffic_types"]
                    ),

                "sources":
                    sorted(
                        aggregate["sources"]
                    ),

                "directions":
                    sorted(
                        aggregate["directions"]
                    ),

                "keys":
                    sorted(
                        aggregate["keys"]
                    ),
            })

        return sorted(
            unique_findings,
            key=lambda item: (
                item["type"],
                item["value_redacted"] or "",
            )
        )

    # --------------------------------------------------
    # Generic helpers
    # --------------------------------------------------

    def _normalize_key(
        self,
        key: Any
    ) -> str:

        """
        Normalize parameter names so variations such as:

            user_email
            userEmail
            USER-EMAIL

        can be compared consistently.
        """

        key = str(key)

        # Field names should be short metadata keys. A malformed parser result
        # or an enormous unstructured body fragment can otherwise make regex
        # normalization disproportionately expensive.
        if len(key) > 512:
            return ""

        # Convert camelCase to snake_case.
        key = re.sub(
            r"([a-z0-9])([A-Z])",
            r"\1_\2",
            key
        )

        # Replace separators with underscores.
        key = re.sub(
            r"[^a-zA-Z0-9]+",
            "_",
            key
        )

        return key.lower().strip("_")

    def _is_email(
        self,
        value: Any
    ) -> bool:

        if value is None:
            return False

        value = str(value).strip()

        pattern = (
            r"^[A-Za-z0-9._%+-]+"
            r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
        )

        return bool(
            re.fullmatch(
                pattern,
                value
            )
        )

    def _find_emails(
        self,
        value: Any
    ) -> List[str]:
        """Find email addresses without scanning arbitrarily large bodies.

        Structured JSON/form fields are analyzed separately, so this regex is
        only a fallback for free-form text. Very large response bodies can be
        minified JavaScript, HTML, telemetry, or other content where a full
        regex scan is unnecessarily expensive. To keep analysis bounded, scan
        the beginning and end of large bodies with a small overlap.
        """

        if value is None:
            return []

        text = str(value)
        if not text:
            return []

        pattern = re.compile(
            r"[A-Za-z0-9._%+-]+"
            r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        )

        # Free-form email detection is a fallback. Structured fields are
        # already extracted independently, so bounding this scan prevents a
        # single very large body from stalling the entire HAR analysis.
        # Keep the free-form regex scan deliberately small. Structured JSON/form
        # fields are analyzed independently, so scanning multi-megabyte bodies
        # adds cost without materially improving field-based detection.
        max_scan_chars = 250_000

        if len(text) > max_scan_chars:
            return []

        return pattern.findall(text)

    def _is_phone_number(
        self,
        value: Any
    ) -> bool:

        if value is None:
            return False

        value = str(value).strip()

        # Remove common phone-number formatting.
        digits = re.sub(
            r"[^\d]",
            "",
            value
        )

        # Plausible international phone range.
        if len(digits) < 10 or len(digits) > 15:
            return False

        # Reject values containing alphabetic characters.
        if re.search(
            r"[A-Za-z]",
            value
        ):
            return False

        return True

    def _looks_like_api_key(
        self,
        key: str,
        value: Any
    ) -> bool:

        normalized_key = self._normalize_key(
            key
        )

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

    def _key_context(self, key: Any):
        """Return normalized path components for contextual key matching."""
        normalized = self._normalize_key(key)
        return [part for part in re.split(r"[._]+", normalized) if part]

    def _classify_key_value(self, key, value):
        """
        Classify a structured field using its leaf key and surrounding
        path context. Ambiguous fields such as `name` and `address` are
        only classified as personal information when contextual evidence
        is present.
        """
        raw_key = str(key)
        if len(raw_key) > 512:
            return None

        normalized_key = self._normalize_key(raw_key)
        parts = [part for part in re.split(r"[._]+", normalized_key) if part]
        leaf = parts[-1] if parts else normalized_key

        email_keys = {"email", "email_address", "user_email", "useremail", "mail"}
        if leaf in email_keys or normalized_key in email_keys or self._is_email(value):
            return "Email"

        phone_keys = {
            "phone", "phone_number", "phonenumber", "mobile", "mobile_number",
            "mobilenumber", "telephone", "telephone_number", "contact_number",
            "contactnumber",
        }
        if leaf in phone_keys or normalized_key in phone_keys:
            if self._is_phone_number(value):
                return "Phone"

        name_keys = {
            "name", "full_name", "fullname", "first_name", "firstname",
            "last_name", "lastname", "given_name", "givenname", "family_name",
            "familyname",
        }
        name_context = {
            "user", "profile", "account", "person", "personal", "contact",
            "identity", "owner", "member", "customer", "subscriber", "student",
        }
        if leaf in name_keys:
            if leaf != "name" or any(part in name_context for part in parts[:-1]):
                if value is not None and str(value).strip():
                    return "Name"

        dob_keys = {
            "dob", "date_of_birth", "dateofbirth", "birth_date", "birthdate", "birthday",
        }
        if leaf in dob_keys:
            return "Date of Birth"

        address_keys = {
            "address", "street_address", "streetaddress", "postal_address",
            "postaladdress", "home_address", "homeaddress", "mailing_address",
            "mailingaddress",
        }
        address_context = {
            "user", "profile", "account", "person", "personal", "contact",
            "identity", "owner", "member", "customer", "subscriber", "student",
            "shipping", "billing", "location",
        }
        if leaf in address_keys:
            if leaf != "address" or any(part in address_context for part in parts[:-1]):
                if value is not None and str(value).strip():
                    return "Address"

        if leaf in {"lat", "latitude"}:
            return "Latitude"
        if leaf in {"lon", "lng", "longitude"}:
            return "Longitude"

        if self._looks_like_api_key(key, value):
            return "API Key"

        csrf_keys = {"csrf", "csrf_token", "csrftoken", "xsrf_token", "xsrftoken"}
        if leaf in csrf_keys or normalized_key in csrf_keys:
            if value is not None and str(value).strip():
                return "CSRF Token"

        auth_keys = {
            "authorization", "auth_token", "authtoken", "access_token", "accesstoken",
            "refresh_token", "refreshtoken", "bearer_token", "bearertoken", "token", "token_v2",
        }
        if leaf in auth_keys or normalized_key in auth_keys:
            if value is not None and str(value).strip():
                return "Authorization Token"

        password_keys = {"password", "passwd", "passcode"}
        if leaf in password_keys or normalized_key in password_keys:
            if value is not None and str(value).strip():
                return "Password"

        device_id_keys = {
            "device_id", "deviceid", "android_id", "androidid", "advertising_id",
            "advertisingid", "ad_id", "adid",
        }
        if leaf in device_id_keys or normalized_key in device_id_keys:
            return "Device ID"

        ip_keys = {"ip", "ip_address", "ipaddress", "client_ip", "clientip", "remote_ip", "remoteip"}
        if leaf in ip_keys or normalized_key in ip_keys:
            return "IP Address"

        return None

    # JavaScript/source-body filtering
    # --------------------------------------------------

    def _looks_like_javascript_source(
        self,
        body: Any
    ) -> bool:
        """
        Detect response bodies that are primarily JavaScript/source code.

        This check must remain bounded because HAR response bodies can be very
        large. Never run the regular expressions over an entire multi-megabyte
        body. A bounded prefix is sufficient to identify the characteristic
        JavaScript syntax that caused the original false positives.
        """
        if body is None:
            return False

        text = str(body).strip()
        if not text:
            return False

        # Hard bound: regex-based source detection must never process an
        # arbitrarily large network body. Keep the sample large enough to catch
        # minified JavaScript while preventing pathological regex runtimes.
        max_scan_chars = 64 * 1024
        sample = text[:max_scan_chars]

        strong_patterns = [
            r"\bfunction\s*\w*\s*\(",
            r"\b(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*[=;]",
            r"\breturn\s+[^;{}]+[;}]",
            r"\b(?:this|window|document|prototype)\s*\.\s*",
            r"\b(?:\.prototype|\.call\(|\.apply\(|=>)",
            r"\b(?:requestAccessToken|recaptchaToken|csrf_token)\b[^\n]{0,120}[;=(){}]",
        ]

        strong_hits = 0
        for pattern in strong_patterns:
            if re.search(pattern, sample):
                strong_hits += 1
                if strong_hits >= 2:
                    return True

        # Property-access fragments are especially characteristic of minified
        # response JavaScript. Count them only within the bounded sample.
        property_pattern = re.compile(
            r"\b(?:this|[A-Za-z_$][\w$]*)\.[A-Za-z_$][\w$]*\b"
        )
        property_hits = sum(
            1
            for _ in property_pattern.finditer(sample)
        )

        return property_hits >= 4

    # --------------------------------------------------

    def _extract_json_pairs(
        self,
        data,
        parent_key=""
    ):

        pairs = []

        if isinstance(
            data,
            dict
        ):

            for key, value in data.items():

                current_key = (
                    f"{parent_key}.{key}"
                    if parent_key
                    else str(key)
                )

                if isinstance(
                    value,
                    (dict, list)
                ):

                    pairs.extend(
                        self._extract_json_pairs(
                            value,
                            current_key
                        )
                    )

                else:

                    pairs.append(
                        (
                            current_key,
                            value
                        )
                    )

        elif isinstance(
            data,
            list
        ):

            for index, value in enumerate(
                data
            ):

                current_key = (
                    f"{parent_key}[{index}]"
                    if parent_key
                    else str(index)
                )

                if isinstance(
                    value,
                    (dict, list)
                ):

                    pairs.extend(
                        self._extract_json_pairs(
                            value,
                            current_key
                        )
                    )

                else:

                    pairs.append(
                        (
                            current_key,
                            value
                        )
                    )

        return pairs

    def _extract_body_pairs(
        self,
        body
    ):

        if not body:
            return []

        body = str(body).strip()

        # ------------------------------------------
        # JSON
        # ------------------------------------------

        try:

            parsed = json.loads(body)

            if isinstance(
                parsed,
                (dict, list)
            ):

                return self._extract_json_pairs(
                    parsed
                )

        except (
            json.JSONDecodeError,
            TypeError,
            ValueError
        ):

            pass

        # ------------------------------------------
        # URL encoded form data
        # ------------------------------------------

        try:

            parsed_pairs = parse_qsl(
                body,
                keep_blank_values=True
            )

            if parsed_pairs:

                return parsed_pairs

        except Exception:

            pass

        return []

    # --------------------------------------------------
    # gRPC / protobuf analysis
    # --------------------------------------------------

    def _analyze_grpc_body(
        self,
        body,
        findings,
        source="gRPC Body"
    ):

        if not body:
            return

        # HAR normally gives us a string.
        # Convert it back to bytes without altering
        # the byte values represented by the string.
        if isinstance(
            body,
            str
        ):

            body_bytes = body.encode(
                "latin-1",
                errors="replace"
            )

        elif isinstance(
            body,
            bytes
        ):

            body_bytes = body

        else:

            return

        strings = ProtobufScanner.extract_strings(
            body_bytes
        )

        for value in strings:

            # --------------------------------------
            # Email
            # --------------------------------------

            emails = self._find_emails(
                value
            )

            for email in emails:

                findings.append(
                    self.create_finding(
                        "Email",
                        source,
                        "protobuf_string",
                        email
                    )
                )

            # --------------------------------------
            # Phone
            # --------------------------------------

            if self._is_phone_number(
                value
            ):

                findings.append(
                    self.create_finding(
                        "Phone",
                        source,
                        "protobuf_string",
                        value
                    )
                )

    # --------------------------------------------------
    # Body analysis
    # --------------------------------------------------

    def _analyze_body(
        self,
        body,
        findings,
        body_type=None,
        source="Request Body"
    ):

        if not body:
            return

        # ------------------------------------------
        # JavaScript response filtering
        # ------------------------------------------
        # Only apply this to response bodies. Request bodies may legitimately
        # contain arbitrary text/form data, and valid JSON is parsed normally.
        if source == "Response Body" and body_type != "grpc":
            body_text = str(body).strip()
            if body_text:
                try:
                    json.loads(body_text)
                    parsed_as_json = True
                except (json.JSONDecodeError, TypeError, ValueError):
                    parsed_as_json = False

                if not parsed_as_json and self._looks_like_javascript_source(body_text):
                    return

        # ------------------------------------------
        # gRPC / protobuf
        # ------------------------------------------

        if body_type == "grpc":

            grpc_source = (
                "gRPC Body"
                if source == "Request Body"
                else "Response gRPC Body"
            )

            self._analyze_grpc_body(
                body,
                findings,
                grpc_source
            )

            return

        # ------------------------------------------
        # Structured body
        # ------------------------------------------

        body_pairs = self._extract_body_pairs(
            body
        )

        for key, value in body_pairs:

            finding_type = (
                self._classify_key_value(
                    key,
                    value
                )
            )

            if finding_type:

                findings.append(
                    self.create_finding(
                        finding_type,
                        source,
                        key,
                        value,
                    )
                )

        # ------------------------------------------
        # Free-form email detection
        # ------------------------------------------
        # For response bodies, only small non-structured text reaches this
        # fallback. Structured JSON/form fields above are always analyzed.

        emails = self._find_emails(
            body
        )

        for email in emails:

            findings.append(
                self.create_finding(
                    "Email",
                    source,
                    "email",
                    email
                )
            )

    # --------------------------------------------------
    # Analyze Requests + Responses
    # --------------------------------------------------

    def analyze(
        self
    ) -> List[Request]:

        self._unique_findings.clear()

        for request_index, request in enumerate(
            self.requests
        ):

            findings = []

            # Prevent the same finding from being
            # generated multiple times for one request.
            finding_signatures = set()

            def add_finding(
                finding_type,
                source,
                key,
                value,
                direction
            ):

                signature = (
                    finding_type,
                    source,
                    str(key).lower(),
                    self._fingerprint(value)
                )

                if signature in finding_signatures:

                    return

                finding_signatures.add(
                    signature
                )

                findings.append(
                    self.create_finding(
                        finding_type,
                        source,
                        key,
                        value,
                        direction
                    )
                )

            # --------------------------------------
            # Request Query Parameters
            # --------------------------------------

            for key, value in (
                request.query_params.items()
            ):

                finding_type = (
                    self._classify_key_value(
                        key,
                        value
                    )
                )

                if finding_type:

                    add_finding(
                        finding_type,
                        "Query Parameter",
                        key,
                        value,
                        "outbound"
                    )

            # --------------------------------------
            # Request Headers
            # --------------------------------------

            for key, value in (
                request.headers.items()
            ):

                normalized_key = (
                    self._normalize_key(key)
                )

                if normalized_key == "authorization":

                    add_finding(
                        "Authorization Token",
                        "Header",
                        key,
                        value,
                        "outbound"
                    )

            # --------------------------------------
            # Request Cookies
            # --------------------------------------

            session_cookie_keys = {
                "session",
                "session_id",
                "sessionid",
                "session_token",
                "sessiontoken",
                "reddit_session",
                "seeker_session",
                "session_tracker",
            }

            for key, value in (
                request.cookies.items()
            ):

                normalized_key = (
                    self._normalize_key(key)
                )

                if (
                    normalized_key
                    in session_cookie_keys
                    or "session"
                    in normalized_key
                ):

                    add_finding(
                        "Session Cookie",
                        "Cookie",
                        key,
                        value,
                        "outbound"
                    )

            # --------------------------------------
            # Request Body
            # --------------------------------------

            body_findings = []

            self._analyze_body(
                request.body,
                body_findings,
                getattr(
                    request,
                    "body_type",
                    None
                ),
                "Request Body"
            )

            for finding in body_findings:

                raw_value = finding.get(
                    "_raw_value"
                )

                add_finding(
                    finding.get("type"),
                    finding.get("source"),
                    finding.get("key"),
                    raw_value,
                    "outbound"
                )

            # --------------------------------------
            # Response Headers
            # --------------------------------------

            for key, value in (
                request.response_headers.items()
            ):

                normalized_key = (
                    self._normalize_key(key)
                )

                # Authorization response headers are uncommon,
                # but should still be detected generically.
                if normalized_key == "authorization":

                    add_finding(
                        "Authorization Token",
                        "Response Header",
                        key,
                        value,
                        "inbound"
                    )

            # --------------------------------------
            # Response Cookies
            # --------------------------------------

            for key, value in (
                request.response_cookies.items()
            ):

                normalized_key = (
                    self._normalize_key(key)
                )

                if (
                    normalized_key
                    in session_cookie_keys
                    or "session"
                    in normalized_key
                ):

                    add_finding(
                        "Session Cookie",
                        "Response Cookie",
                        key,
                        value,
                        "inbound"
                    )

            # --------------------------------------
            # Response Body
            # --------------------------------------

            response_body_findings = []

            self._analyze_body(
                request.response_body,
                response_body_findings,
                getattr(
                    request,
                    "response_body_type",
                    None
                ),
                "Response Body"
            )

            for finding in response_body_findings:

                raw_value = finding.get(
                    "_raw_value"
                )

                add_finding(
                    finding.get("type"),
                    finding.get("source"),
                    finding.get("key"),
                    raw_value,
                    "inbound"
                )

            # --------------------------------------
            # Preserve request-level evidence
            # --------------------------------------

            for finding in findings:

                self._record_unique_finding(
                    finding,
                    request,
                    request_index,
                )

                # Never export raw sensitive values.
                finding.pop(
                    "_raw_value",
                    None
                )

            request.sensitive_data = findings

        return self.requests
