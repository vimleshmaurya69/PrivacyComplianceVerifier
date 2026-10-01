import json
from pathlib import Path

from src.policy.policy_models import normalize_policy_document


class PrivacyPolicyParser:

    def __init__(self, policy_file):
        self.policy_file = Path(policy_file)

    def load(self):
        if not self.policy_file.exists():
            raise FileNotFoundError(
                f"Policy file not found: {self.policy_file}"
            )

        with open(self.policy_file, "r", encoding="utf-8") as file:
            return json.load(file)

    def parse(self):
        return normalize_policy_document(self.load())


if __name__ == "__main__":

    parser = PrivacyPolicyParser(
        "data/policy/forecastie_policy.json"
    )

    policy = parser.parse()

    print("=" * 60)
    print("Privacy Evidence Parser")
    print("=" * 60)

    print(f"App : {policy['application']}")

    print("\nEvidence Sources:")

    for source in policy["sources"]:
        print(
            f" - {source.get('type', 'unknown')} : "
            f"{source.get('source') or source.get('url', 'unknown')}"
        )

    print("\nDeclared Practices:")

    if policy["declared_practices"]:

        for practice in policy["declared_practices"]:

            print(
                f" - {practice.get('data') or practice.get('data_type', 'Unknown')} "
                f"| {practice.get('category', 'Unknown')} "
                f"| {practice.get('purpose', 'Unknown')} "
                f"| {practice.get('source_type') or practice.get('source', 'Unknown')}"
            )

    else:
        print(" - None")
