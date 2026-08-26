import json
from pathlib import Path


class HarLoader:

    def __init__(self, har_file):
        self.har_file = Path(har_file)

    def load(self):
        with open(self.har_file, "r", encoding="utf-8") as f:
            return json.load(f)