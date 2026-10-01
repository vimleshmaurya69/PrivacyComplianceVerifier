import json
import os
from copy import deepcopy

from src.comparator.semantic_category_mapping import (
    NON_COMPARABLE_OBSERVED_CATEGORIES,
    comparable_policy_categories,
    is_automatically_comparable_policy_category,
    policy_category_for_observed,
)
from src.comparator.practice_risk_assessor import assess_practice_risks
from src.comparator.observed_practice_builder import ObservedPracticeBuilder
from src.comparator.practice_matcher import PracticeMatcher
from src.policy.policy_models import (
    is_specific_verified_practice,
    normalize_policy_document,
)


COMPARISON_TRAFFIC_TYPES = {"Application", "Third Party"}


class PolicyComparator:

    def __init__(
        self,
        observed_inventory,
        policy_data,
        app_name="Unknown",
        frida_evidence=None
    ):
        self.observed_inventory = observed_inventory
        if (
            isinstance(policy_data, dict)
            and policy_data.get("_canonical_policy_model") is True
        ):
            self.policy_data = deepcopy(policy_data)
        else:
            self.policy_data = normalize_policy_document(policy_data)
        self.app_name = app_name
        self.frida_evidence = frida_evidence or {}

    # --------------------------------------------------
    # Extract observed privacy categories from HAR
    # --------------------------------------------------

    def get_observed_categories(self, traffic_types=None):
        """Return observed categories, optionally limited by traffic owner."""
        categories = set()

        for traffic_type, data in self.observed_inventory.items():
            if traffic_types is not None and traffic_type not in traffic_types:
                continue

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

    def get_frida_evidence(self, policy_category):
        """Return normalized Frida evidence for one exactly mapped category."""
        evidence = []
        observations = self.frida_evidence.get("observations", [])
        if not isinstance(observations, list):
            return evidence

        for observation in observations:
            if not isinstance(observation, dict):
                continue
            if observation.get("status") != "observed":
                continue
            observed_category = observation.get("privacy_category")
            if policy_category_for_observed(observed_category) != policy_category:
                continue
            evidence.append({
                "observed_category": observed_category,
                "artifact_type": (
                    observation.get("data_type")
                    or observation.get("type")
                ),
                "source": "Frida",
                "direction": "local access",
                "key": None,
                "domain": None,
                "traffic_type": "Runtime",
            })
        return evidence

    def get_runtime_observations(self):
        """Expose local runtime access without treating it as transmission."""
        evidence = []
        observations = self.frida_evidence.get("observations", [])
        if not isinstance(observations, list):
            return evidence

        for observation in observations:
            if not isinstance(observation, dict):
                continue
            if observation.get("status") != "observed":
                continue
            evidence.append({
                "observed_category": observation.get("privacy_category"),
                "artifact_type": (
                    observation.get("data_type")
                    or observation.get("type")
                ),
                "source": "Frida",
                "direction": "local access",
                "key": None,
                "domain": None,
                "traffic_type": "Runtime",
            })
        return evidence

    def get_attributable_observed_categories(self):
        """Return HAR categories attributable to the app or its third parties."""
        return self.get_observed_categories(COMPARISON_TRAFFIC_TYPES)

    def get_comparison_har_categories(self):
        """Return outbound HAR categories suitable for automatic comparison.

        Inbound response findings remain evidence, but do not by themselves
        prove that an app collected or transmitted an undeclared category.
        Inventories created before evidence preservation fall back to their
        section-level category lists.
        """
        categories = set()
        has_evidence = False

        for traffic_type, data in self.observed_inventory.items():
            if traffic_type not in COMPARISON_TRAFFIC_TYPES:
                continue
            findings = data.get("evidence", [])
            if not isinstance(findings, list) or not findings:
                continue
            has_evidence = True
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                if finding.get("direction") != "outbound":
                    continue
                category = finding.get("privacy_category")
                if category:
                    categories.add(category)

        if has_evidence:
            return categories
        return self.get_attributable_observed_categories()

    def get_comparable_observed_categories(self):
        """Return only observed categories approved for semantic comparison."""
        return comparable_policy_categories(self.get_comparison_har_categories())

    def get_observed_evidence(
        self,
        policy_category,
        traffic_types=None,
        directions=None,
    ):
        """Return HAR evidence whose observed category exactly maps to a policy category."""
        evidence = []

        for traffic_type, data in self.observed_inventory.items():
            if traffic_types is not None and traffic_type not in traffic_types:
                continue
            for finding in data.get("evidence", []):
                if not isinstance(finding, dict):
                    continue
                if directions is not None and finding.get("direction") not in directions:
                    continue

                observed_category = finding.get("privacy_category")
                if policy_category_for_observed(observed_category) != policy_category:
                    continue

                evidence.append({
                    "observed_category": observed_category,
                    "artifact_type": finding.get("type"),
                    "source": finding.get("source"),
                    "direction": finding.get("direction"),
                    "key": finding.get("key"),
                    "domain": finding.get("domain"),
                    "traffic_type": traffic_type,
                })

        return evidence

    def get_inbound_evidence(self):
        """Expose attributable inbound findings outside automatic comparison."""
        evidence = []
        for traffic_type, data in self.observed_inventory.items():
            if traffic_type not in COMPARISON_TRAFFIC_TYPES:
                continue
            for finding in data.get("evidence", []):
                if not isinstance(finding, dict):
                    continue
                if finding.get("direction") != "inbound":
                    continue
                evidence.append({
                    "observed_category": finding.get("privacy_category"),
                    "artifact_type": finding.get("type"),
                    "source": finding.get("source"),
                    "direction": finding.get("direction"),
                    "key": finding.get("key"),
                    "domain": finding.get("domain"),
                    "traffic_type": traffic_type,
                })
        return evidence

    def get_excluded_observed_evidence(self):
        """Expose non-comparable runtime evidence without assigning a compliance status."""
        evidence = []

        for traffic_type, data in self.observed_inventory.items():
            for finding in data.get("evidence", []):
                if not isinstance(finding, dict):
                    continue
                if finding.get("privacy_category") in NON_COMPARABLE_OBSERVED_CATEGORIES:
                    evidence.append({
                        "observed_category": finding.get("privacy_category"),
                        "artifact_type": finding.get("type"),
                        "source": finding.get("source"),
                        "direction": finding.get("direction"),
                        "key": finding.get("key"),
                        "domain": finding.get("domain"),
                        "traffic_type": traffic_type,
                    })

        return evidence

    def get_non_attributable_evidence(self):
        """Expose Android/unknown evidence without using it for app comparison."""
        evidence = []

        for traffic_type, data in self.observed_inventory.items():
            if traffic_type in COMPARISON_TRAFFIC_TYPES:
                continue
            for finding in data.get("evidence", []):
                if not isinstance(finding, dict):
                    continue
                evidence.append({
                    "observed_category": finding.get("privacy_category"),
                    "artifact_type": finding.get("type"),
                    "source": finding.get("source"),
                    "direction": finding.get("direction"),
                    "key": finding.get("key"),
                    "domain": finding.get("domain"),
                    "traffic_type": traffic_type,
                })

        return evidence

    def get_attributable_evidence(self):
        """Return all app/third-party evidence for practice-risk assessment."""
        evidence = []
        for traffic_type, data in self.observed_inventory.items():
            if traffic_type not in COMPARISON_TRAFFIC_TYPES:
                continue
            for finding in data.get("evidence", []):
                if not isinstance(finding, dict):
                    continue
                evidence.append({
                    "observed_category": finding.get("privacy_category"),
                    "artifact_type": finding.get("type"),
                    "source": finding.get("source"),
                    "direction": finding.get("direction"),
                    "key": finding.get("key"),
                    "domain": finding.get("domain"),
                    "traffic_type": traffic_type,
                })
        return evidence

    def get_practice_risks(self):
        return assess_practice_risks(self.get_attributable_evidence())

    def get_observed_practices(self):
        """Derive practice records without altering inventory evidence."""
        return ObservedPracticeBuilder(self.observed_inventory).build()

    def get_policy_practices(self, category=None):
        practices = list(self.policy_data.get("policy_practices", []))
        if category is None:
            return practices
        return [
            item for item in practices
            if item.get("privacy_category") == category
        ]

    def get_comparison_coverage(self):
        return list(self.policy_data.get("comparison_coverage", []))

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

    def get_declared_practices(self, category=None):
        """Return structured policy practices, optionally for one category."""
        practices = self.policy_data.get("declared_practices", [])
        if not isinstance(practices, list):
            return []

        structured = [item for item in practices if isinstance(item, dict)]
        if category is None:
            return structured
        return [item for item in structured if item.get("category") == category]

    def get_policy_quality(self):
        """Describe normalized policy evidence and comparison readiness."""
        source_urls = [
            source.get("url")
            for source in self.policy_data.get("sources", [])
            if isinstance(source, dict) and source.get("url")
        ]
        legacy_practices = self.get_declared_practices()
        policy_practices = self.get_policy_practices()
        verified_specific = [
            item for item in policy_practices
            if is_specific_verified_practice(item)
        ]
        verified_coverage = [
            item for item in self.get_comparison_coverage()
            if item.get("state") == "VERIFIED_COMPLETE"
        ]
        declared = self.get_declared_categories()
        issues = []
        if declared and not legacy_practices and not policy_practices:
            issues.append("POLICY_CATEGORY_LIST_ONLY")
        if not source_urls:
            issues.append("POLICY_SOURCE_MISSING")
        if not self.policy_data.get("last_verified"):
            issues.append("POLICY_VERIFICATION_DATE_MISSING")
        if declared and not verified_specific:
            issues.append("POLICY_PRACTICE_DETAIL_INCOMPLETE")
        if not verified_coverage:
            issues.append("POLICY_COVERAGE_UNKNOWN")

        return {
            "structured_practice_count": len(legacy_practices),
            "canonical_practice_count": len(policy_practices),
            "verified_specific_practice_count": len(verified_specific),
            "verified_complete_coverage_count": len(verified_coverage),
            "declared_category_count": len(declared),
            "source_count": len(set(source_urls)),
            "last_verified": self.policy_data.get("last_verified"),
            "normalization_issues": self.policy_data.get(
                "normalization_issues", []
            ),
            "issues": issues,
        }

    # --------------------------------------------------
    # Compare observed vs declared
    # --------------------------------------------------

    def compare(self):
        """Return authoritative practice-level disclosure comparisons."""
        return PracticeMatcher(self.policy_data).compare(
            self.get_observed_practices()
        )

    def compare_categories(self):
        """Return the legacy category view as non-authoritative context."""

        har_observed = self.get_comparison_har_categories()
        frida_observed = comparable_policy_categories(self.get_frida_categories())

        observed = comparable_policy_categories(har_observed)
        declared = self.get_declared_categories()

        all_categories = sorted(
            observed | frida_observed | declared
        )

        results = []

        for category in all_categories:

            is_har_observed = category in comparable_policy_categories(har_observed)
            is_frida_observed = category in frida_observed
            is_observed = is_har_observed or is_frida_observed
            is_declared = category in declared
            observed_evidence = (
                self.get_observed_evidence(
                    category,
                    COMPARISON_TRAFFIC_TYPES,
                    {"outbound"},
                )
                if is_har_observed else []
            )
            runtime_evidence = (
                self.get_frida_evidence(category)
                if is_frida_observed else []
            )
            policy_practices = self.get_policy_practices(category)

            if is_frida_observed and not is_har_observed:

                status = "RUNTIME EVIDENCE ONLY"
                explanation = (
                    "The category was observed through local runtime "
                    "instrumentation, not attributable outbound HAR traffic. "
                    "It remains separate from network-practice comparison."
                )

            elif is_observed and is_declared:

                status = (
                    "CATEGORY DECLARED"
                    if policy_practices
                    else "CATEGORY LISTED"
                )

                evidence_sources = []

                if is_har_observed:
                    evidence_sources.append("HAR")

                if policy_practices:
                    explanation = (
                        "The observed category appears in structured policy "
                        "evidence. This category context is not a practice-"
                        "level disclosure match."
                    )
                else:
                    explanation = (
                        "The category appears in the declared-category list, "
                        "but no structured policy evidence supports a specific "
                        "practice."
                    )

            elif is_observed and not is_declared:

                status = "CATEGORY NOT DECLARED"

                evidence_sources = []

                if is_har_observed:
                    evidence_sources.append("HAR")

                explanation = (
                    "Privacy category was observed through "
                    + " and ".join(evidence_sources)
                    + " evidence but is absent from the broad category list. "
                      "Practice-level coverage determines whether this can "
                      "support a potential non-disclosure."
                )

            elif not is_observed and is_declared:

                if is_automatically_comparable_policy_category(category):
                    status = "NOT OBSERVED IN CAPTURE"
                    explanation = (
                        "This HAR-comparable category is declared but was not "
                        "observed in attributable outbound traffic. This is a "
                        "capture-coverage statement, not evidence of absence."
                    )
                else:
                    status = "NOT ASSESSABLE FROM HAR"
                    explanation = (
                        "This declared category has no approved exact mapping "
                        "from HAR evidence. Runtime or other evidence may be "
                        "needed; absence from HAR is not meaningful."
                    )

            else:
                continue

            results.append({
                "comparison_level": "category",
                "category": category,
                "observed": is_observed,
                "observed_har": is_har_observed,
                "observed_frida": is_frida_observed,
                "declared": is_declared,
                "status": status,
                "explanation": explanation,
                "observed_evidence": observed_evidence,
                "runtime_evidence": runtime_evidence,
                "policy_practices": policy_practices,
            })

        return results

    # --------------------------------------------------
    # Generate summary
    # --------------------------------------------------

    def generate_summary(self, results, category_results=None):
        """Summarize practice evidence without making a legal conclusion."""
        category_results = (
            self.compare_categories()
            if category_results is None
            else category_results
        )

        practice_disclosed = sum(
            1 for result in results
            if result.get("status") == "PRACTICE DISCLOSED"
        )
        information_type_disclosed = sum(
            1 for result in results
            if result.get("status") in {
                "INFORMATION DISCLOSED", "INFORMATION TYPE DISCLOSED"
            }
        )
        potential_non_disclosures = sum(
            1 for result in results
            if result.get("status") == "POTENTIAL NON-DISCLOSURE"
        )
        insufficient_detail = sum(
            1 for result in results
            if result.get("status") == "INSUFFICIENT POLICY DETAIL"
        )
        not_observed = sum(
            1 for result in results
            if result.get("status") == "NOT OBSERVED IN CAPTURE"
        )
        not_assessable = sum(
            1 for result in results
            if result.get("status") == "NOT ASSESSABLE FROM HAR"
        )

        disclosed_categories = sum(
            1 for result in category_results
            if result.get("status") == "CATEGORY DECLARED"
        )
        declared_only_categories = sum(
            1 for result in category_results
            if result.get("status") == "CATEGORY LISTED"
        )
        category_not_observed = sum(
            1 for result in category_results
            if result.get("status") == "NOT OBSERVED IN CAPTURE"
        )
        category_not_assessable = sum(
            1 for result in category_results
            if result.get("status") == "NOT ASSESSABLE FROM HAR"
        )

        practice_risks = self.get_practice_risks()
        runtime_observations = self.get_runtime_observations()
        non_attributable = self.get_non_attributable_evidence()
        policy_quality = self.get_policy_quality()

        assessment_flags = []
        if potential_non_disclosures:
            assessment_flags.append("POTENTIAL_NON_DISCLOSURE")
        assessment_flags.extend(risk["type"] for risk in practice_risks)
        if insufficient_detail:
            assessment_flags.append("INSUFFICIENT_POLICY_DETAIL")
        if not_observed:
            assessment_flags.append("LIMITED_CAPTURE_COVERAGE")
        if not_assessable:
            assessment_flags.append("HAR_SCOPE_LIMITATION")
        if runtime_observations:
            assessment_flags.append("RUNTIME_ACCESS_OBSERVED")
        if non_attributable:
            assessment_flags.append("NON_ATTRIBUTABLE_EVIDENCE_EXCLUDED")
        assessment_flags.extend(policy_quality["issues"])
        assessment_flags = list(dict.fromkeys(assessment_flags))

        observed_results = [
            result for result in results
            if result.get("result_type") == "observed_practice"
        ]
        if potential_non_disclosures:
            assessment_status = "POTENTIAL NON-DISCLOSURE IDENTIFIED"
        elif insufficient_detail:
            assessment_status = "INSUFFICIENT POLICY DETAIL"
        elif practice_disclosed:
            assessment_status = "DISCLOSURE EVIDENCE FOUND"
        elif information_type_disclosed:
            assessment_status = "INFORMATION DISCLOSURE EVIDENCE FOUND"
        else:
            assessment_status = "INSUFFICIENT EVIDENCE"

        # HAR and policy evidence can support disclosure-gap findings, but it
        # cannot establish legal compliance or non-compliance.  Keep the
        # compatibility field while making that limitation explicit.
        compliance_determination = "NOT DETERMINED"
        overall_status = assessment_status

        return {
            "practice_disclosed": practice_disclosed,
            "information_disclosed": information_type_disclosed,
            "information_type_disclosed": information_type_disclosed,
            "potential_non_disclosures": potential_non_disclosures,
            "insufficient_policy_detail": insufficient_detail,
            "not_observed_in_capture": not_observed,
            "not_assessable_from_har": not_assessable,
            # Compatibility fields remain descriptive; they no longer drive
            # the authoritative practice-level status.
            "disclosed_categories": disclosed_categories,
            "declared_only_categories": declared_only_categories,
            "category_not_observed_in_capture": category_not_observed,
            "category_not_assessable_from_har": category_not_assessable,
            "potential_mismatches": potential_non_disclosures,
            "practice_risks": len(practice_risks),
            "runtime_observations": len(runtime_observations),
            "policy_quality": policy_quality,
            "assessment_flags": assessment_flags,
            "assessment_status": assessment_status,
            "overall_status": overall_status,
            "compliance_determination": compliance_determination,
            "scope_note": (
                "This is an experimental disclosure assessment over observed "
                "comparable practices, not a legal compliance conclusion. URL, "
                "recipient, runtime, and capture limitations remain separate "
                "qualifiers."
            ),
        }

    # --------------------------------------------------
    # Console output
    # --------------------------------------------------

    def print_report(self):

        results = self.compare()
        category_results = self.compare_categories()
        summary = self.generate_summary(results, category_results)

        print("\n" + "=" * 70)
        print("Privacy Disclosure Comparison")
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

        print("\nPractice Disclosure Results:")
        print("-" * 70)

        for result in results:
            print(
                f"{result['privacy_category']} | "
                f"{result.get('artifact_type') or result.get('artifact_types')} | "
                f"{result['status']}"
            )
            print(
                f"    Explanation    : "
                f"{result['explanation']}"
            )

        print("\nSummary:")
        print("-" * 70)

        print(
            f"Practices Disclosed : "
            f"{summary['practice_disclosed']}"
        )

        print(
            f"Information Disclosed: "
            f"{summary['information_type_disclosed']}"
        )

        print(
            f"Potential Non-Disclosure: "
            f"{summary['potential_non_disclosures']}"
        )

        print(
            f"Insufficient Policy Detail: "
            f"{summary['insufficient_policy_detail']}"
        )

        print(
            f"Not Observed in Capture: "
            f"{summary['not_observed_in_capture']}"
        )

        print(
            f"Not Assessable from HAR: "
            f"{summary['not_assessable_from_har']}"
        )

        print(
            f"Overall Status       : "
            f"{summary['overall_status']}"
        )

        print(
            f"Compliance Determination: "
            f"{summary['compliance_determination']}"
        )

        if summary["assessment_flags"]:
            print("Assessment Flags:")
            for flag in summary["assessment_flags"]:
                print(f"  - {flag}")

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
