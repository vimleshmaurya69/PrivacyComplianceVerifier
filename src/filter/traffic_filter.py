from typing import List

from src.models.request import Request

from src.utils.config import (
    ANDROID_PATTERNS,
    THIRD_PARTY_PATTERNS,
)


class TrafficFilter:

    def __init__(
        self,
        requests: List[Request],
        app_name: str = None,
        application_services: List[str] = None,
        third_party_services: List[str] = None
    ):

        self.requests = requests

        self.app_name = (
            app_name or ""
        ).lower()

        self.application_services = [
            service.lower().strip()
            for service in (
                application_services or []
            )
        ]

        self.third_party_services = [
            service.lower().strip()
            for service in (
                third_party_services or []
            )
        ]

    # --------------------------------------------------
    # Domain Matching
    # --------------------------------------------------

    def domain_matches(
        self,
        domain: str,
        pattern: str
    ) -> bool:

        domain = domain.lower().strip()
        pattern = pattern.lower().strip()

        return (
            domain == pattern
            or domain.endswith("." + pattern)
        )

    # --------------------------------------------------
    # Classification
    # --------------------------------------------------

    def classify_requests(
        self
    ) -> List[Request]:

        for request in self.requests:

            domain = request.domain.lower().strip()

            # ------------------------------------------
            # 1. Application Services
            # ------------------------------------------

            if any(
                self.domain_matches(
                    domain,
                    pattern
                )
                for pattern in self.application_services
            ):

                request.traffic_type = "Application"

            # ------------------------------------------
            # 2. Declared Third-Party Services
            # ------------------------------------------

            elif any(
                self.domain_matches(
                    domain,
                    pattern
                )
                for pattern in self.third_party_services
            ):

                request.traffic_type = "Third Party"

            # ------------------------------------------
            # 3. Globally Known Third-Party Services
            # ------------------------------------------

            elif any(
                pattern.lower() in domain
                for pattern in THIRD_PARTY_PATTERNS
            ):

                request.traffic_type = "Third Party"

            # ------------------------------------------
            # 4. Android / Google System Traffic
            # ------------------------------------------

            elif any(
                pattern.lower() in domain
                for pattern in ANDROID_PATTERNS
            ):

                request.traffic_type = "Android System"

            # ------------------------------------------
            # 5. Unknown Traffic
            # ------------------------------------------

            else:

                request.traffic_type = "Unknown"

        return self.requests