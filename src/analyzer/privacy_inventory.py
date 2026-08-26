from typing import Dict, List

from src.models.request import Request


class PrivacyInventoryGenerator:
    """
    Generates a summarized privacy inventory from
    normalized runtime requests.
    """

    def __init__(self, requests: List[Request]):
        self.requests = requests

    def generate(self) -> Dict:

        inventory = {}

        for request in self.requests:

            traffic_type = request.traffic_type

            if traffic_type not in inventory:

                inventory[traffic_type] = {
                    "request_count": 0,
                    "domains": set(),
                    "privacy_categories": set(),
                }

            section = inventory[traffic_type]

            section["request_count"] += 1

            if request.domain:
                section["domains"].add(request.domain)

            for finding in request.sensitive_data:

                category = finding.get("privacy_category")

                if category:
                    section["privacy_categories"].add(category)

        # Convert sets into sorted lists for JSON serialization
        for section in inventory.values():

            section["domains"] = sorted(section["domains"])

            section["privacy_categories"] = sorted(
                section["privacy_categories"]
            )

        return inventory