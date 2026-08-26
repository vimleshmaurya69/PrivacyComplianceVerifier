import json
import os
from dataclasses import asdict
from typing import List, Dict

from src.models.request import Request


class JSONExporter:
    """
    Exports framework results to JSON files.
    """

    def __init__(self, output_directory: str):

        self.output_directory = output_directory

        os.makedirs(self.output_directory, exist_ok=True)

    def export_requests(self, requests: List[Request]):

        output = []

        for request in requests:
            output.append(asdict(request))

        file_path = os.path.join(
            self.output_directory,
            "classified_requests.json"
        )

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(output, file, indent=4)

        print(f"[✓] classified_requests.json exported")

    def export_statistics(self, statistics: Dict):

        file_path = os.path.join(
            self.output_directory,
            "statistics.json"
        )

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(statistics, file, indent=4)

        print(f"[✓] statistics.json exported")

    def export_privacy_inventory(self, inventory: Dict):

        file_path = os.path.join(
            self.output_directory,
            "privacy_inventory.json"
        )

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(inventory, file, indent=4)

        print(f"[✓] privacy_inventory.json exported")

    def export_privacy_inventory(self, inventory):

        file_path = os.path.join(
         self.output_directory,
        "privacy_inventory.json"
     )

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(inventory, file, indent=4)

        print("[✓] privacy_inventory.json exported")