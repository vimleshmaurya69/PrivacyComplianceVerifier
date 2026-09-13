from urllib.parse import parse_qs, urlparse
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
    def _extract_headers(self, headers: list) -> dict:
        """
        Convert HAR header list into a dictionary.
        """

        result = {}

        for header in headers or []:
            name = header.get("name", "")
            value = header.get("value", "")

            if name:
                result[name] = value

        return result

    # ---------------------------------------------------------
    # Cookie extraction
    # ---------------------------------------------------------
    def _extract_cookies(self, cookies: list) -> dict:
        """
        Convert HAR cookie list into a dictionary.
        """

        result = {}

        for cookie in cookies or []:
            name = cookie.get("name", "")
            value = cookie.get("value", "")

            if name:
                result[name] = value

        return result

    # ---------------------------------------------------------
    # Request body extraction
    # ---------------------------------------------------------
    def _extract_request_body(self, request: dict, headers: dict):
        """
        Extract request body and determine its type.
        """

        body = None
        body_encoding = None
        content_type = ""

        post_data = request.get("postData")

        if post_data:
            body = post_data.get("text")

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
            headers = self._extract_headers(
                request.get("headers", [])
            )

            # -------------------------------------------------
            # Request Cookies
            # -------------------------------------------------
            cookies = self._extract_cookies(
                request.get("cookies", [])
            )

            # -------------------------------------------------
            # Query Parameters
            # -------------------------------------------------
            query_params = {}

            parsed_query = parse_qs(
                parsed_url.query
            )

            for key, value in parsed_query.items():
                query_params[key] = (
                    value[0]
                    if value
                    else ""
                )

            # -------------------------------------------------
            # Request Body
            # -------------------------------------------------
            (
                body,
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
            response_headers = self._extract_headers(
                response.get("headers", [])
            )

            # -------------------------------------------------
            # Response Cookies
            # -------------------------------------------------
            response_cookies = self._extract_cookies(
                response.get("cookies", [])
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
                query_params=query_params,
                body=body,
                cookies=cookies,

                # Response
                response_headers=response_headers,
                response_cookies=response_cookies,
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