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
        body_encoding = None
        content_type = ""

        post_data = request.get("postData")

        if post_data:
            body = post_data.get("text")

            if body is None:
                for param in post_data.get("params", []) or []:
                    if not isinstance(param, dict):
                        continue
                    name = param.get("name", "")
                    if name:
                        body_param_pairs.append((name, param.get("value", "")))

            body_encoding = post_data.get(
                "encoding"
            )

            content_type = post_data.get(
                "mimeType",
                ""
            )

        # Some HAR files don't put mimeType inside postData.
        # Fall back to the request Content-Type header.
        if not content_type:
            content_type = next(
                (
                    value
                    for key, value in headers.items()
                    if key.lower() == "content-type"
                ),
                ""
            )

        body_type = self._detect_body_type(
            content_type
        )

        return (
            body,
            body_param_pairs,
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

        content = response.get(
            "content",
            {}
        )

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
            query_param_pairs = parse_qsl(
                parsed_url.query,
                keep_blank_values=True
            )
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
                domain=parsed_url.netloc,
                status=response["status"],
                mime_type=response.get(
                    "content",
                    {}
                ).get(
                    "mimeType",
                    ""
                ),

                headers=headers,
                header_pairs=header_pairs,
                query_params=query_params,
                query_param_pairs=query_param_pairs,
                query_param_values=query_param_values,
                body=body,
                body_param_pairs=body_param_pairs,
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
