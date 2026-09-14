import hashlib
import json
import re

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

        if value is None:
            return []

        value = str(value)

        pattern = (
            r"[A-Za-z0-9._%+-]+"
            r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        )

        return re.findall(
            pattern,
            value
        )

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
    # --------------------------------------------------

    def _classify_key_value(
        self,
        key,
        value
    ):

        normalized_key = self._normalize_key(
            key
        )

        # ------------------------------------------
        # Email
        # ------------------------------------------

        email_keys = {
            "email",
            "email_address",
            "user_email",
            "useremail",
            "mail",
        }

        if (
            normalized_key in email_keys
            or self._is_email(value)
        ):

            return "Email"

        # ------------------------------------------
        # Phone
        # ------------------------------------------

        phone_keys = {
            "phone",
            "phone_number",
            "phonenumber",
            "mobile",
            "mobile_number",
            "mobilenumber",
            "telephone",
            "telephone_number",
            "contact_number",
            "contactnumber",
        }

        if normalized_key in phone_keys:

            if self._is_phone_number(value):

                return "Phone"

        # ------------------------------------------
        # Location
        # ------------------------------------------

        latitude_keys = {
            "lat",
            "latitude",
        }

        longitude_keys = {
            "lon",
            "lng",
            "longitude",
        }

        if normalized_key in latitude_keys:

            return "Latitude"

        if normalized_key in longitude_keys:

            return "Longitude"

        # ------------------------------------------
        # API credentials
        # ------------------------------------------

        if self._looks_like_api_key(
            key,
            value
        ):

            return "API Key"

        # ------------------------------------------
        # Authentication tokens
        # ------------------------------------------

        auth_keys = {
            "authorization",
            "auth_token",
            "authtoken",
            "access_token",
            "accesstoken",
            "refresh_token",
            "refreshtoken",
            "bearer_token",
            "bearertoken",
            "token",
            "token_v2",
            "csrf_token",
        }

        if normalized_key in auth_keys:

            return "Authorization Token"

        # ------------------------------------------
        # Device identifiers
        # ------------------------------------------

        device_id_keys = {
            "device_id",
            "deviceid",
            "android_id",
            "androidid",
            "advertising_id",
            "advertisingid",
            "ad_id",
            "adid",
        }

        if normalized_key in device_id_keys:

            return "Device ID"

        return None

    # --------------------------------------------------
    # URL / text signal helpers
    # --------------------------------------------------

    def _iter_url_query_pairs(self, url: Any):
        """Return query pairs directly from the URL.

        The extractor currently exposes query parameters as a mapping, which
        can collapse duplicate keys. Parsing the original URL here preserves
        every occurrence for detection.
        """
        if not url:
            return []

        try:
            query = urlsplit(str(url)).query
            return parse_qsl(query, keep_blank_values=True)
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
        """Decode high-confidence base64 strings for a second detection pass."""
        import base64

        if not self._looks_like_base64(value):
            return []

        try:
            decoded = base64.b64decode(str(value), validate=True)
            if not decoded or len(decoded) > 1024 * 1024:
                return []
            text = decoded.decode("utf-8", errors="ignore").strip()
            if not text:
                return []
            # Only feed plausible textual payloads back into the detector.
            printable = sum(ch.isprintable() or ch.isspace() for ch in text)
            if printable / max(len(text), 1) < 0.85:
                return []
            return [text]
        except Exception:
            return []

    def _analyze_text_signals(self, value: Any, findings, source, key):
        """Detect strong privacy artifacts independent of parameter naming."""
        if value is None:
            return

        text = str(value)

        for email in self._find_emails(text):
            findings.append(self.create_finding(
                "Email", source, key, email
            ))

        # Generic phone detection is intentionally conservative. It accepts
        # international +country-code forms anywhere, and plain 10-15 digit
        # values only when the key provides contact/phone context.
        phone_context = bool(re.search(
            r"(?:phone|mobile|telephone|tel|contact|msisdn|caller|recipient|number)",
            self._normalize_key(key)
        ))
        international_candidates = re.findall(
            r"\+\d[\d .()\-]{8,14}\d", text
        )
        plain_candidates = []
        if phone_context:
            plain_candidates = re.findall(r"(?<!\d)\d{10,15}(?!\d)", text)
        elif source == "URL Path":
            # Path segments frequently carry identifiers directly. Treat a
            # standalone 10-15 digit path segment as a phone candidate; do
            # not scan arbitrary path text for digit sequences.
            plain_candidates = re.findall(r"(?<!\d)\d{10,15}(?!\d)", text)

        for candidate in international_candidates + plain_candidates:
            if self._is_phone_number(candidate):
                findings.append(self.create_finding(
                    "Phone", source, key, candidate
                ))

        for decoded in self._decode_base64_candidates(text):
            for email in self._find_emails(decoded):
                findings.append(self.create_finding(
                    "Email", source, f"{key}.__base64__", email
                ))
            if re.search(r"(?:phone|mobile|telephone|tel|contact|msisdn)", self._normalize_key(decoded)):
                digits = re.sub(r"[^\d+]", "", decoded)
                if self._is_phone_number(digits):
                    findings.append(self.create_finding(
                        "Phone", source, f"{key}.__base64__", digits
                    ))

    # --------------------------------------------------
    # Structured body extraction
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

            # Scan scalar values independently of their field name. This
            # catches artifacts embedded in generic fields and JSON strings.
            signal_findings = []
            self._analyze_text_signals(
                value,
                signal_findings,
                source,
                key
            )
            findings.extend(signal_findings)

            # A form/query field may itself contain a JSON object. Parse it
            # recursively so fields such as payload='{"email":"..."}' are
            # not treated as opaque strings.
            if isinstance(value, str):
                try:
                    nested = json.loads(value)
                    if isinstance(nested, (dict, list)):
                        nested_pairs = self._extract_json_pairs(
                            nested, str(key)
                        )
                        for nested_key, nested_value in nested_pairs:
                            nested_type = self._classify_key_value(
                                nested_key, nested_value
                            )
                            if nested_type:
                                findings.append(self.create_finding(
                                    nested_type,
                                    source,
                                    nested_key,
                                    nested_value,
                                ))
                            nested_signals = []
                            self._analyze_text_signals(
                                nested_value,
                                nested_signals,
                                source,
                                nested_key
                            )
                            findings.extend(nested_signals)
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass

        # ------------------------------------------
        # Free-form email detection
        # ------------------------------------------

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
                        value
                    )
                )

            # --------------------------------------
            # URL Path
            # --------------------------------------

            url_path = self._get_url_path(getattr(request, "url", ""))
            if url_path:
                self._analyze_text_signals(
                    url_path,
                    findings,
                    "URL Path",
                    "path"
                )

            # --------------------------------------
            # Request Query Parameters
            # --------------------------------------

            # Parse the original URL as well as the extracted mapping. This
            # preserves duplicate query keys and catches values lost by a
            # dict-based representation.
            query_pairs = list(self._iter_url_query_pairs(
                getattr(request, "url", "")
            ))
            query_pairs.extend(
                list(request.query_params.items())
            )

            for key, value in query_pairs:

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

                query_signal_findings = []
                self._analyze_text_signals(
                    value,
                    query_signal_findings,
                    "Query Parameter",
                    key
                )
                for finding in query_signal_findings:
                    add_finding(
                        finding.get("type"),
                        finding.get("source"),
                        finding.get("key"),
                        finding.get("_raw_value"),
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

                else:
                    finding_type = self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(
                            finding_type,
                            "Header",
                            key,
                            value,
                            "outbound"
                        )

                header_signal_findings = []
                self._analyze_text_signals(
                    value,
                    header_signal_findings,
                    "Header",
                    key
                )
                for finding in header_signal_findings:
                    add_finding(
                        finding.get("type"),
                        finding.get("source"),
                        finding.get("key"),
                        finding.get("_raw_value"),
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

                else:
                    finding_type = self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(
                            finding_type,
                            "Cookie",
                            key,
                            value,
                            "outbound"
                        )

                cookie_signal_findings = []
                self._analyze_text_signals(
                    value,
                    cookie_signal_findings,
                    "Cookie",
                    key
                )
                for finding in cookie_signal_findings:
                    add_finding(
                        finding.get("type"),
                        finding.get("source"),
                        finding.get("key"),
                        finding.get("_raw_value"),
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

                else:
                    finding_type = self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(
                            finding_type,
                            "Response Header",
                            key,
                            value,
                            "inbound"
                        )

                response_header_signal_findings = []
                self._analyze_text_signals(
                    value,
                    response_header_signal_findings,
                    "Response Header",
                    key
                )
                for finding in response_header_signal_findings:
                    add_finding(
                        finding.get("type"),
                        finding.get("source"),
                        finding.get("key"),
                        finding.get("_raw_value"),
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

                else:
                    finding_type = self._classify_key_value(key, value)
                    if finding_type:
                        add_finding(
                            finding_type,
                            "Response Cookie",
                            key,
                            value,
                            "inbound"
                        )

                response_cookie_signal_findings = []
                self._analyze_text_signals(
                    value,
                    response_cookie_signal_findings,
                    "Response Cookie",
                    key
                )
                for finding in response_cookie_signal_findings:
                    add_finding(
                        finding.get("type"),
                        finding.get("source"),
                        finding.get("key"),
                        finding.get("_raw_value"),
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