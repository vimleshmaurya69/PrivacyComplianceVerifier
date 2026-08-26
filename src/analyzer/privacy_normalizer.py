from typing import List

from src.models.request import Request
from src.utils.privacy_taxonomy import PRIVACY_CATEGORY_MAP


class PrivacyNormalizer:
    """
    Converts low-level sensitive data findings into
    standardized privacy categories while preserving
    the original detection evidence.
    """

    def __init__(self, requests: List[Request]):
        self.requests = requests

    def normalize(self) -> List[Request]:

        for request in self.requests:

            if not request.sensitive_data:
                continue

            for finding in request.sensitive_data:

                # ------------------------------------------
                # Original detected artifact
                # ------------------------------------------

                artifact = finding.get(
                    "type",
                    ""
                )

                # ------------------------------------------
                # Map artifact to privacy category
                # ------------------------------------------

                category = PRIVACY_CATEGORY_MAP.get(
                    artifact,
                    "Unknown"
                )

                finding["privacy_category"] = category

                # ------------------------------------------
                # Add request-level context
                # ------------------------------------------

                finding["domain"] = request.domain

                finding["traffic_type"] = (
                    request.traffic_type
                )

        return self.requests