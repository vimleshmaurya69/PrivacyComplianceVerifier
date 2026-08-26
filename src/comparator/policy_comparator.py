import json
import os


class PolicyComparator:

    def __init__(
        self,
        observed_inventory,
        policy_data,
        app_name="Unknown",
        frida_evidence=None
    ):
        self.observed_inventory = observed_inventory
        self.policy_data = policy_data
        self.app_name = app_name
        self.frida_evidence = frida_evidence or {}

    # --------------------------------------------------
    # Extract observed privacy categories from HAR
    # --------------------------------------------------

    def get_observed_categories(self):
        categories = set()

        for traffic_type, data in self.observed_inventory.items():

            for category in data.get("privacy_categories", []):
                categories.add(category)

        return categories

    # --------------------------------------------------
    # Extract observed privacy categories from Frida
    # --------------------------------------------------

    def get_frida_categories(self):
        categories = set()

        observations = self.frida_evidence.get(
            "observations", []
        )

        if isinstance(observations, list):

            for observation in observations:

                if not isinstance(observation, dict):
                    continue

                if observation.get("status") != "observed":
                    continue

                category = observation.get(
                    "privacy_category"
                )

                if category:
                    categories.add(category)

        return categories

    # --------------------------------------------------
    # Extract declared privacy categories
    # --------------------------------------------------

    def get_declared_categories(self):
        categories = set()

        if isinstance(self.policy_data, dict):

            declared = self.policy_data.get(
                "declared_categories", []
            )

            if isinstance(declared, list):
                categories.update(declared)

            practices = self.policy_data.get(
                "declared_practices", []
            )

            if isinstance(practices, list):

                for practice in practices:

                    if isinstance(practice, dict):

                        category = practice.get("category")

                        if category:
                            categories.add(category)

                    elif isinstance(practice, str):
                        categories.add(practice)

        return categories

    # --------------------------------------------------
    # Compare observed vs declared
    # --------------------------------------------------

    def compare(self):

        har_observed = self.get_observed_categories()
        frida_observed = self.get_frida_categories()

        observed = har_observed | frida_observed
        declared = self.get_declared_categories()

        all_categories = sorted(
            observed | declared
        )

        results = []

        for category in all_categories:

            is_har_observed = category in har_observed
            is_frida_observed = category in frida_observed
            is_observed = category in observed
            is_declared = category in declared

            if is_observed and is_declared:

                status = "COMPLIANT"

                evidence_sources = []

                if is_har_observed:
                    evidence_sources.append("HAR")

                if is_frida_observed:
                    evidence_sources.append("Frida")

                explanation = (
                    "Privacy category was observed through "
                    + " and ".join(evidence_sources)
                    + " evidence and is supported by available "
                      "policy evidence."
                )

            elif is_observed and not is_declared:

                status = "POTENTIAL MISMATCH"

                evidence_sources = []

                if is_har_observed:
                    evidence_sources.append("HAR")

                if is_frida_observed:
                    evidence_sources.append("Frida")

                explanation = (
                    "Privacy category was observed through "
                    + " and ".join(evidence_sources)
                    + " evidence but no supporting declaration "
                      "was found in the available policy evidence."
                )

            elif not is_observed and is_declared:

                status = "NOT OBSERVED"

                explanation = (
                    "Privacy category was declared in available "
                    "policy evidence but was not observed through "
                    "the available HAR or Frida evidence."
                )

            else:
                continue

            results.append({
                "category": category,
                "observed": is_observed,
                "observed_har": is_har_observed,
                "observed_frida": is_frida_observed,
                "declared": is_declared,
                "status": status,
                "explanation": explanation
            })

        return results

    # --------------------------------------------------
    # Generate summary
    # --------------------------------------------------

    def generate_summary(self, results):

        compliant = sum(
            1 for result in results
            if result["status"] == "COMPLIANT"
        )

        mismatches = sum(
            1 for result in results
            if result["status"] == "POTENTIAL MISMATCH"
        )

        not_observed = sum(
            1 for result in results
            if result["status"] == "NOT OBSERVED"
        )

        if mismatches > 0:
            overall_status = "POTENTIAL NON-COMPLIANCE"

        elif compliant > 0:
            overall_status = "NO POTENTIAL MISMATCH DETECTED"

        else:
            overall_status = "INSUFFICIENT EVIDENCE"

        return {
            "compliant": compliant,
            "potential_mismatches": mismatches,
            "not_observed": not_observed,
            "overall_status": overall_status
        }

    # --------------------------------------------------
    # Console output
    # --------------------------------------------------

    def print_report(self):

        results = self.compare()
        summary = self.generate_summary(results)

        print("\n" + "=" * 70)
        print("Privacy Compliance Comparison")
        print("=" * 70)

        print(f"Application : {self.app_name}")

        print("\nHAR Observed Categories:")

        har_observed = sorted(
            self.get_observed_categories()
        )

        if har_observed:

            for category in har_observed:
                print(f"  - {category}")

        else:
            print("  - None")

        print("\nFrida Observed Categories:")

        frida_observed = sorted(
            self.get_frida_categories()
        )

        if frida_observed:

            for category in frida_observed:
                print(f"  - {category}")

        else:
            print("  - None")

        print("\nDeclared Categories:")

        declared = sorted(
            self.get_declared_categories()
        )

        if declared:

            for category in declared:
                print(f"  - {category}")

        else:
            print("  - None")

        print("\nCompliance Results:")
        print("-" * 70)

        for result in results:

            print(
                f"{result['category']} | "
                f"{result['status']}"
            )

            print(
                f"    HAR Observed   : "
                f"{result['observed_har']}"
            )

            print(
                f"    Frida Observed : "
                f"{result['observed_frida']}"
            )

            print(
                f"    Declared       : "
                f"{result['declared']}"
            )

            print(
                f"    Explanation    : "
                f"{result['explanation']}"
            )

        print("\nSummary:")
        print("-" * 70)

        print(
            f"Compliant            : "
            f"{summary['compliant']}"
        )

        print(
            f"Potential Mismatches : "
            f"{summary['potential_mismatches']}"
        )

        print(
            f"Not Observed         : "
            f"{summary['not_observed']}"
        )

        print(
            f"Overall Status       : "
            f"{summary['overall_status']}"
        )

        return results, summary


# ------------------------------------------------------
# Standalone testing
# ------------------------------------------------------

if __name__ == "__main__":

    inventory_path = (
        "data/output/privacy_inventory.json"
    )

    policy_path = (
        "data/apps/forecastie/policy/"
        "forecastie_policy.json"
    )

    if not os.path.exists(inventory_path):

        print(
            f"[ERROR] Inventory file not found: "
            f"{inventory_path}"
        )

        exit()

    if not os.path.exists(policy_path):

        print(
            f"[ERROR] Policy file not found: "
            f"{policy_path}"
        )

        exit()

    with open(
        inventory_path,
        "r",
        encoding="utf-8"
    ) as file:

        inventory = json.load(file)

    with open(
        policy_path,
        "r",
        encoding="utf-8"
    ) as file:

        policy = json.load(file)

    comparator = PolicyComparator(
        inventory,
        policy,
        "Forecastie"
    )

    comparator.print_report()