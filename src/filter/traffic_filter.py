from typing import List

from src.models.request import Request

from src.utils.config import (
    ANDROID_PATTERNS,
    THIRD_PARTY_PATTERNS,
)


class TrafficFilter:
    """
    Classifies network requests into:
        - Application
        - Third Party
        - Android System
        - Unknown

    Classification is based on domain ownership/pattern matching.
    """

    def __init__(
        self,
        requests: List[Request],
        app_name: str = None,
        application_services: List[str] = None,
        third_party_services: List[str] = None,
    ):
        self.requests = requests
        self.app_name = (app_name or "").lower().strip()

        self.application_services = [
            service.lower().strip()
            for service in (application_services or [])
            if service and service.strip()
        ]

        self.third_party_services = [
            service.lower().strip()
            for service in (third_party_services or [])
            if service and service.strip()
        ]

    # --------------------------------------------------
    # Domain Normalization
    # --------------------------------------------------

    def normalize_domain(self, domain: str) -> str:
        """
        Normalizes a hostname before comparison.

        Handles:
            example.com
            EXAMPLE.COM
            example.com.
            example.com:443
            *.example.com

        IPv6 addresses are left unchanged.
        """
        if not domain:
            return ""

        domain = str(domain).strip().lower()

        if domain.startswith("*."):
            domain = domain[2:]

        domain = domain.rstrip(".")

        # Remove brackets and an optional numeric port from IPv6 authorities.
        if domain.startswith("[") and "]" in domain:
            closing = domain.find("]")
            host = domain[1:closing]
            suffix = domain[closing + 1:]
            if not suffix or (suffix.startswith(":") and suffix[1:].isdigit()):
                domain = host
        # Remove a numeric port from normal hostname:port values. Bare IPv6
        # addresses contain multiple colons and remain unchanged.
        elif domain.count(":") == 1:
            host, port = domain.rsplit(":", 1)
            if port.isdigit():
                domain = host

        return domain

    # --------------------------------------------------
    # Domain Matching
    # --------------------------------------------------

    def domain_matches(
        self,
        domain: str,
        pattern: str,
    ) -> bool:
        """
        Performs safe domain matching.

        Matches:
            example.com
            sub.example.com

        Does NOT match:
            notexample.com
            example.com.evil.com
        """
        domain = self.normalize_domain(domain)
        pattern = self.normalize_domain(pattern)

        if not domain or not pattern:
            return False

        return (
            domain == pattern
            or domain.endswith("." + pattern)
        )

    # --------------------------------------------------
    # Pattern Matching
    # --------------------------------------------------

    def matches_any_pattern(
        self,
        domain: str,
        patterns,
    ) -> bool:
        """
        Checks whether a domain matches any supplied
        domain pattern using safe suffix matching.
        """
        return any(
            self.domain_matches(domain, pattern)
            for pattern in patterns
            if pattern
        )

    # --------------------------------------------------
    # Classification
    # --------------------------------------------------

    def classify_requests(self) -> List[Request]:
        for request in self.requests:
            domain = self.normalize_domain(request.domain)
            request.domain = domain

            # 1. Application Services
            if self.matches_any_pattern(
                domain,
                self.application_services,
            ):
                request.traffic_type = "Application"

            # 2. Declared Third-Party Services
            elif self.matches_any_pattern(
                domain,
                self.third_party_services,
            ):
                request.traffic_type = "Third Party"

            # 3. Globally Known Third-Party Services
            elif self.matches_any_pattern(
                domain,
                THIRD_PARTY_PATTERNS,
            ):
                request.traffic_type = "Third Party"

            # 4. Known Android / Google System Traffic
            elif self.matches_any_pattern(
                domain,
                ANDROID_PATTERNS,
            ):
                request.traffic_type = "Android System"

            # 5. Unknown Traffic
            else:
                request.traffic_type = "Unknown"

        return self.requests
