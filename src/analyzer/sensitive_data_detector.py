import re

from typing import List

from src.models.request import Request


class SensitiveDataDetector:

    def __init__(self, requests: List[Request]):
        self.requests = requests

    # --------------------------------------------------
    # Redact sensitive values
    # --------------------------------------------------

    def redact_value(self, value):

        if value is None:
            return None

        value = str(value)

        if not value:
            return ""

        # Keep only a tiny preview for debugging.
        # Never export the complete sensitive value.
        if len(value) <= 4:
            return "****"

        return (
            value[:2]
            + "..."
            + value[-2:]
        )

    # --------------------------------------------------
    # Create finding
    # --------------------------------------------------

    def create_finding(
        self,
        finding_type,
        source,
        key,
        value
    ):

        return {
            "type": finding_type,
            "source": source,
            "key": key,
            "value_redacted": self.redact_value(value)
        }

    # --------------------------------------------------
    # Analyze Requests
    # --------------------------------------------------

    def analyze(self) -> List[Request]:

        for request in self.requests:

            findings = []

            # ------------------------------------------
            # Query Parameters
            # ------------------------------------------

            for key, value in request.query_params.items():

                key_lower = key.lower()

                if key_lower == "lat":

                    findings.append(
                        self.create_finding(
                            "Latitude",
                            "Query Parameter",
                            key,
                            value
                        )
                    )

                elif key_lower == "lon":

                    findings.append(
                        self.create_finding(
                            "Longitude",
                            "Query Parameter",
                            key,
                            value
                        )
                    )

                elif key_lower in [
                    "appid",
                    "api_key",
                    "apikey"
                ]:

                    findings.append(
                        self.create_finding(
                            "API Key",
                            "Query Parameter",
                            key,
                            value
                        )
                    )

                elif key_lower == "email":

                    findings.append(
                        self.create_finding(
                            "Email",
                            "Query Parameter",
                            key,
                            value
                        )
                    )

            # ------------------------------------------
            # Headers
            # ------------------------------------------

            for key, value in request.headers.items():

                key_lower = key.lower()

                if key_lower == "authorization":

                    findings.append(
                        self.create_finding(
                            "Authorization Token",
                            "Header",
                            key,
                            value
                        )
                    )

            # ------------------------------------------
            # Cookies
            # ------------------------------------------

            for key, value in request.cookies.items():

                key_lower = key.lower()

                if "session" in key_lower:

                    findings.append(
                        self.create_finding(
                            "Session Cookie",
                            "Cookie",
                            key,
                            value
                        )
                    )

            # ------------------------------------------
            # Request Body
            # ------------------------------------------

            if request.body:

                email_pattern = (
                    r"[A-Za-z0-9._%+-]+"
                    r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
                )

                emails = re.findall(
                    email_pattern,
                    request.body
                )

                for email in emails:

                    findings.append(
                        self.create_finding(
                            "Email",
                            "Request Body",
                            "email",
                            email
                        )
                    )

            request.sensitive_data = findings

        return self.requests