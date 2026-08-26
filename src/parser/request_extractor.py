from urllib.parse import parse_qs, urlparse
from typing import List

from src.models.request import Request


class RequestExtractor:
    """
    Extracts HTTP requests from a HAR file and converts them
    into Request objects.
    """

    def __init__(self, har_data: dict):
        self.har_data = har_data

    def extract_requests(self) -> List[Request]:

        requests = []

        entries = self.har_data["log"]["entries"]

        for entry in entries:

            request = entry["request"]
            response = entry["response"]

            parsed_url = urlparse(request["url"])

            # -----------------------------
            # Request Headers
            # -----------------------------
            headers = {}

            for header in request.get("headers", []):

                headers[header["name"]] = header["value"]

            # -----------------------------
            # Cookies
            # -----------------------------
            cookies = {}

            for cookie in request.get("cookies", []):

                cookies[cookie["name"]] = cookie["value"]

            # -----------------------------
            # Query Parameters
            # -----------------------------
            query_params = {}

            parsed_query = parse_qs(parsed_url.query)

            for key, value in parsed_query.items():

                query_params[key] = value[0] if value else ""

            # -----------------------------
            # Request Body
            # -----------------------------
            body = None

            if "postData" in request:

                body = request["postData"].get("text")

            # -----------------------------
            # Create Request Object
            # -----------------------------
            request_object = Request(

                method=request["method"],

                url=request["url"],

                domain=parsed_url.netloc,

                status=response["status"],

                mime_type=response.get("content", {}).get("mimeType", ""),

                headers=headers,

                query_params=query_params,

                body=body,

                cookies=cookies,

                server_ip=entry.get("serverIPAddress"),

                started_datetime=entry.get("startedDateTime"),

                response_size=response.get("bodySize", 0),
            )

            requests.append(request_object)

        return requests