import base64

from urllib.parse import parse_qsl, urlparse
from typing import List

from src.models.request import Request


class RequestExtractor:
    """
    Extracts HTTP requests and their corresponding responses
    from a HAR file.

    The extractor preserves:
    - Request headers
    - Request cookies
    - Query parameters
    - Request body
    - Response headers
    - Response cookies
    - Response body

    It also performs basic content-type detection for both
    request and response bodies so downstream analyzers can
    distinguish structured, text, binary, and gRPC traffic.
    """

    def __init__(self, har_data: dict):
        self.har_data = har_data

    # ---------------------------------------------------------
    # Content-type classification
    # ---------------------------------------------------------
    def _detect_body_type(self, content_type: str) -> str:
        """
        Classify a body based on its MIME/content type.
        """

        content_type_lower = (
            content_type.lower()
            if content_type
            else ""
        )

        if "application/grpc" in content_type_lower:
            return "grpc"

        elif (
            "application/json" in content_type_lower
            or (
                "application/" in content_type_lower
                and "json" in content_type_lower
            )
        ):
            return "json"

        elif "x-www-form-urlencoded" in content_type_lower:
            return "form"

        elif "multipart/form-data" in content_type_lower:
            return "multipart"

        elif (
            content_type_lower.startswith("text/")
            or content_type_lower == ""
        ):
            return "text"

        else:
            return "binary"

    # ---------------------------------------------------------
    # Header extraction
    # ---------------------------------------------------------
    def _extract_headers(self, headers: list):
        """
        Return a compatibility dictionary and ordered name/value pairs.

        HAR permits repeated header names (notably Set-Cookie).  The
        dictionary preserves the historical last-value behaviour, while the
        pairs preserve every original occurrence.
        """

        result = {}
        pairs = []

        for header in headers or []:
            name = header.get("name", "")
            value = header.get("value", "")

            if name:
                pairs.append((name, value))
                result[name] = value

        return result, pairs

    # ---------------------------------------------------------
    # Cookie extraction
    # ---------------------------------------------------------
    def _extract_cookies(self, cookies: list):
        """
        Return a compatibility dictionary and ordered name/value pairs.
        """

        result = {}
        pairs = []

        for cookie in cookies or []:
            name = cookie.get("name", "")
            value = cookie.get("value", "")

            if name:
                pairs.append((name, value))
                result[name] = value

        return result, pairs

    def _extract_raw_cookies(self, header_pairs, response=False):
        """Extract cookie occurrences from raw Cookie/Set-Cookie headers."""
        result = {}
        pairs = []
        target = "set-cookie" if response else "cookie"

        for header_name, header_value in header_pairs:
            if str(header_name).lower() != target:
                continue

            value = str(header_value or "")
            if response:
                # Each Set-Cookie header begins with its cookie name/value;
                # do not split on commas because Expires may contain one.
                cookie_parts = [value.split(";", 1)[0]]
            else:
                cookie_parts = value.split(";")

            for part in cookie_parts:
                name, separator, cookie_value = part.strip().partition("=")
                if not separator or not name:
                    continue
                pairs.append((name, cookie_value))
                result[name] = cookie_value

        return result, pairs

    @staticmethod
    def _merge_cookie_pairs(har_pairs, header_pairs):
        """Merge cookie occurrences while removing only exact duplicates."""
        merged = list(har_pairs or [])
        unmatched_har = {}

        for pair in merged:
            unmatched_har[pair] = unmatched_har.get(pair, 0) + 1

        for pair in header_pairs or []:
            if unmatched_har.get(pair, 0):
                unmatched_har[pair] -= 1
            else:
                merged.append(pair)

        result = {}
        for name, value in merged:
            result[name] = value

        return result, merged

    # ---------------------------------------------------------
    # Request body extraction
    # ---------------------------------------------------------
    def _extract_request_body(self, request: dict, headers: dict):
        """
        Extract request body and determine its type.
        """

        body = None
        body_param_pairs = []
        body_param_pairs_reconciled = False
        body_encoding = None
        content_type = ""

        post_data = request.get("postData") or {}
        toolkit_content = request.get("_content") or {}

        if not isinstance(post_data, dict):
            post_data = {}
        if not isinstance(toolkit_content, dict):
            toolkit_content = {}

        # Standard HAR uses postData. HTTP Toolkit stores request entities that
        # are not directly representable as text (notably protobuf/gRPC) in the
        # same content-shaped extension it uses for captured binary bodies.
        if post_data.get("text") is not None:
            body = post_data.get("text")
            body_encoding = post_data.get("encoding")
        elif toolkit_content.get("text") is not None:
            body = toolkit_content.get("text")
            body_encoding = toolkit_content.get("encoding")

        content_type = (
            post_data.get("mimeType")
            or toolkit_content.get("mimeType")
            or next(
                (
                    value
                    for key, value in headers.items()
                    if key.lower() == "content-type"
                ),
                ""
            )
        )

        if post_data:
            param_pairs = []
            for param in post_data.get("params", []) or []:
                if not isinstance(param, dict):
                    continue
                name = param.get("name", "")
                if name:
                    param_pairs.append((name, param.get("value", "")))

            if body is None:
                body_param_pairs = param_pairs
                body_param_pairs_reconciled = True
            elif "x-www-form-urlencoded" in content_type.lower():
                # postData.params often repeats the parsed text. Preserve only
                # occurrences not already represented by postData.text.
                represented = {}
                try:
                    reconciliation_text = str(body)
                    if str(body_encoding or "").lower() == "base64":
                        raw = reconciliation_text.encode("ascii")
                        if len(raw) > 8 * 1024 * 1024:
                            raise ValueError("encoded form body exceeds limit")
                        reconciliation_text = base64.b64decode(
                            raw, validate=True
                        ).decode("utf-8")
                    text_pairs = parse_qsl(
                        reconciliation_text, keep_blank_values=True
                    )
                except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
                    text_pairs = []
                for pair in text_pairs:
                    represented[pair] = represented.get(pair, 0) + 1
                for pair in param_pairs:
                    if represented.get(pair, 0):
                        represented[pair] -= 1
                    else:
                        body_param_pairs.append(pair)
                body_param_pairs_reconciled = True
            else:
                # For non-form bodies there is no safe generic equivalence
                # parser. Preserve all pairs and let the detector reconcile
                # exact parsed occurrences while retaining params-only values.
                body_param_pairs = param_pairs

        body_type = self._detect_body_type(
            content_type
        )

        return (
            body,
            body_param_pairs,
            body_param_pairs_reconciled,
            body_encoding,
            content_type,
            body_type,
        )

    # ---------------------------------------------------------
    # Response body extraction
    # ---------------------------------------------------------
    def _extract_response_body(
        self,
        response: dict,
        response_headers: dict,
    ):
        """
        Extract response body and determine its type.
        """

        body = None
        body_encoding = None
        content_type = ""

        content = response.get("content") or {}
        if not isinstance(content, dict):
            content = {}

        if content:
            body = content.get("text")

            body_encoding = content.get(
                "encoding"
            )

            content_type = content.get(
                "mimeType",
                ""
            )

        # Some HAR files don't provide the response
        # MIME type inside content. Fall back to
        # the response Content-Type header.
        if not content_type:
            content_type = next(
                (
                    value
                    for key, value
                    in response_headers.items()
                    if key.lower() == "content-type"
                ),
                ""
            )

        body_type = self._detect_body_type(
            content_type
        )

        return (
            body,
            body_encoding,
            content_type,
            body_type,
        )

    # ---------------------------------------------------------
    # Main extraction
    # ---------------------------------------------------------
    def extract_requests(self) -> List[Request]:

        requests = []

        entries = self.har_data["log"]["entries"]

        for entry in entries:

            request = entry["request"]
            response = entry["response"]

            parsed_url = urlparse(
                request["url"]
            )
            # urlparse().netloc retains ports and IPv6 brackets. Store the
            # normalized host so traffic attribution, evidence, and policy
            # domain matching all operate on the same value.
            request_domain = (parsed_url.hostname or parsed_url.netloc or "")
            request_domain = request_domain.lower().rstrip(".")

            # -------------------------------------------------
            # Request Headers
            # -------------------------------------------------
            headers, header_pairs = self._extract_headers(
                request.get("headers", [])
            )

            # -------------------------------------------------
            # Request Cookies
            # -------------------------------------------------
            cookies, cookie_pairs = self._extract_cookies(
                request.get("cookies", [])
            )
            _, raw_cookie_pairs = self._extract_raw_cookies(header_pairs)
            cookies, cookie_pairs = self._merge_cookie_pairs(
                cookie_pairs, raw_cookie_pairs
            )

            # -------------------------------------------------
            # Query Parameters
            # -------------------------------------------------
            query_params = {}
            url_query_pairs = parse_qsl(
                parsed_url.query,
                keep_blank_values=True
            )
            har_query_pairs = []
            for param in request.get("queryString", []) or []:
                if not isinstance(param, dict):
                    continue
                name = param.get("name", "")
                if name:
                    har_query_pairs.append((name, param.get("value", "")))

            # HAR normally repeats the URL query in queryString. Merge by
            # occurrence so extension-only values are retained without
            # duplicating the same represented occurrence.
            query_param_pairs = list(url_query_pairs)
            represented_query_pairs = {}
            for pair in url_query_pairs:
                represented_query_pairs[pair] = (
                    represented_query_pairs.get(pair, 0) + 1
                )
            for pair in har_query_pairs:
                if represented_query_pairs.get(pair, 0):
                    represented_query_pairs[pair] -= 1
                else:
                    query_param_pairs.append(pair)

            query_param_values = {}
            for key, value in query_param_pairs:
                query_param_values.setdefault(key, []).append(value)
                # Preserve the historical first-value dictionary view.
                query_params.setdefault(key, value)

            # -------------------------------------------------
            # Request Body
            # -------------------------------------------------
            (
                body,
                body_param_pairs,
                body_param_pairs_reconciled,
                body_encoding,
                content_type,
                body_type,
            ) = self._extract_request_body(
                request,
                headers
            )

            # -------------------------------------------------
            # Response Headers
            # -------------------------------------------------
            response_headers, response_header_pairs = self._extract_headers(
                response.get("headers", [])
            )

            # -------------------------------------------------
            # Response Cookies
            # -------------------------------------------------
            response_cookies, response_cookie_pairs = self._extract_cookies(
                response.get("cookies", [])
            )
            _, raw_response_cookie_pairs = self._extract_raw_cookies(
                response_header_pairs, response=True
            )
            response_cookies, response_cookie_pairs = self._merge_cookie_pairs(
                response_cookie_pairs, raw_response_cookie_pairs
            )

            # -------------------------------------------------
            # Response Body
            # -------------------------------------------------
            (
                response_body,
                response_body_encoding,
                response_content_type,
                response_body_type,
            ) = self._extract_response_body(
                response,
                response_headers
            )

            # -------------------------------------------------
            # Create Request Object
            # -------------------------------------------------
            request_object = Request(

                # Request
                method=request["method"],
                url=request["url"],
                domain=request_domain,
                status=response["status"],
                # Keep the historical response MIME field, but use the same
                # content/header fallback already applied to response bodies.
                mime_type=response_content_type,

                headers=headers,
                header_pairs=header_pairs,
                query_params=query_params,
                query_param_pairs=query_param_pairs,
                query_param_values=query_param_values,
                body=body,
                body_param_pairs=body_param_pairs,
                body_param_pairs_reconciled=body_param_pairs_reconciled,
                cookies=cookies,
                cookie_pairs=cookie_pairs,

                # Response
                response_headers=response_headers,
                response_header_pairs=response_header_pairs,
                response_cookies=response_cookies,
                response_cookie_pairs=response_cookie_pairs,
                response_body=response_body,

                response_body_type=response_body_type,
                response_body_encoding=response_body_encoding,
                response_content_type=response_content_type,

                # Network metadata
                server_ip=entry.get(
                    "serverIPAddress"
                ),

                started_datetime=entry.get(
                    "startedDateTime"
                ),

                response_size=response.get(
                    "bodySize",
                    0
                ),

                # Request body metadata
                body_type=body_type,
                body_encoding=body_encoding,
                content_type=content_type,
            )

            requests.append(
                request_object
            )

        return requests
