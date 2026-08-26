import json
from pathlib import Path


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

        policy = self.load()

        return {
            "app": policy.get("app", "Unknown"),
            "sources": policy.get("sources", []),
            "declared_practices": policy.get(
                "declared_practices", []
            )
        }


if __name__ == "__main__":

    parser = PrivacyPolicyParser(
        "data/policy/forecastie_policy.json"
    )

    policy = parser.parse()

    print("=" * 60)
    print("Privacy Evidence Parser")
    print("=" * 60)

    print(f"App : {policy['app']}")

    print("\nEvidence Sources:")

    for source in policy["sources"]:
        print(
            f" - {source['type']} : "
            f"{source['source']}"
        )

    print("\nDeclared Practices:")

    if policy["declared_practices"]:

        for practice in policy["declared_practices"]:

            print(
                f" - {practice['data']} "
                f"| {practice['category']} "
                f"| {practice['purpose']} "
                f"| {practice['source_type']}"
            )

    else:
        print(" - None")