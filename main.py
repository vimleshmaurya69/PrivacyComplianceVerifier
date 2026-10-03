import argparse
import json
import os
import statistics
import sys

from src.app_manager import AppManager
from src.parser.har_loader import HarLoader
from src.parser.request_extractor import RequestExtractor
from src.filter.traffic_filter import TrafficFilter
from src.analyzer.sensitive_data_detector import SensitiveDataDetector
from src.analyzer.privacy_normalizer import PrivacyNormalizer
from src.analyzer.privacy_inventory import PrivacyInventoryGenerator
from src.exporter.json_exporter import JSONExporter
from src.comparator.policy_comparator import PolicyComparator
from src.policy.policy_parser import PrivacyPolicyParser
from src.report.simple_result_presenter import (
    build_simple_report,
    format_simple_report,
)
from src.utils.privacy_taxonomy import PRIVACY_CATEGORY_MAP
from src.comparator.semantic_category_mapping import (
    NON_COMPARABLE_OBSERVED_CATEGORIES,
)


def main(app_name):

    # ==================================================
    # Application Configuration
    # ==================================================

    app_manager = AppManager(app_name)

    app_name = app_manager.get_app_name()
    har_file = app_manager.get_har_file()
    policy_file = app_manager.get_policy_file()
    output_path = app_manager.get_output_path()

    # ==================================================
    # Framework Header
    # ==================================================

    print("=" * 60)
    print("Privacy Compliance Verification Framework")
    print("=" * 60)

    print(f"Application : {app_name}")

    # ==================================================
    # Validate Files
    # ==================================================

    if not har_file.exists():

        print("\n[ERROR] HAR file not found:")
        print(f"        {har_file}")
        return 1

    if not policy_file.exists():

        print("\n[WARNING] Policy file not found:")
        print(f"          {policy_file}")

    # ==================================================
    # Load HAR File
    # ==================================================

    print("\nLoading HAR file...")

    har_data = HarLoader(har_file).load()

    print("HAR Loaded Successfully.")

    # ==================================================
    # Extract Requests
    # ==================================================

    print("\nExtracting requests...")

    extractor = RequestExtractor(har_data)

    requests = extractor.extract_requests()

    print(f"Total Requests : {len(requests)}")

    # ==================================================
    # Traffic Classification
    # ==================================================

    print("\nClassifying traffic...")

    traffic_filter = TrafficFilter(
        requests,
        app_name,
        app_manager.get_application_services(),
        app_manager.get_third_party_services(),
    )

    requests = traffic_filter.classify_requests()

    # ==================================================
    # Sensitive Data Detection
    # ==================================================

    print("Detecting sensitive data...")

    detector = SensitiveDataDetector(requests)

    requests = detector.analyze()

    # ==================================================
    # Privacy Normalization
    # ==================================================

    normalizer = PrivacyNormalizer(requests)

    requests = normalizer.normalize()

    # ==================================================
    # Unique Sensitive Artifact Summary
    # ==================================================

    # Request-level findings are intentionally preserved in each Request.
    # The detector separately aggregates repeated uses of the same artifact
    # so repeated Authorization headers do not become separate credentials.
    unique_sensitive_artifacts = detector.get_unique_findings()

    for artifact in unique_sensitive_artifacts:
        artifact["privacy_category"] = PRIVACY_CATEGORY_MAP.get(
            artifact.get("type", ""),
            "Unknown"
        )

    # ==================================================
    # Privacy Inventory
    # ==================================================

    print("Generating privacy inventory...")

    inventory_generator = PrivacyInventoryGenerator(requests)

    privacy_inventory = inventory_generator.generate()

    # ==================================================
    # Statistics
    # ==================================================

    # ==================================================
    # Statistics
    # ==================================================

    # Count sensitive-data findings by traffic type
    sensitive_findings_by_traffic = {
        "Application": 0,
        "Third Party": 0,
        "Android System": 0,
        "Unknown": 0,
    }

    # Count sensitive-data findings by privacy category
    sensitive_findings_by_category = {}

    for request in requests:

        traffic_type = request.traffic_type

        for finding in request.sensitive_data:

            # ------------------------------------------
            # Traffic Type Statistics
            # ------------------------------------------

            if traffic_type in sensitive_findings_by_traffic:

                sensitive_findings_by_traffic[traffic_type] += 1

            # ------------------------------------------
            # Privacy Category Statistics
            # ------------------------------------------

            category = finding.get("privacy_category", "Unknown")

            sensitive_findings_by_category[category] = (
                sensitive_findings_by_category.get(category, 0) + 1
            )

    unique_artifacts_by_category = {}

    for artifact in unique_sensitive_artifacts:
        category = artifact.get("privacy_category", "Unknown")
        unique_artifacts_by_category[category] = (
            unique_artifacts_by_category.get(category, 0) + 1
        )

    # ==================================================
    # Frida Evidence
    # ==================================================

    frida_evidence = {}
    frida_observations = []

    frida_path = app_manager.get_frida_file()

    if frida_path.exists():

        try:
            with open(frida_path, "r", encoding="utf-8") as file:
                frida_evidence = json.load(file)

            raw_frida_observations = frida_evidence.get("observations", [])
            if isinstance(raw_frida_observations, list):
                frida_observations = [
                    observation
                    for observation in raw_frida_observations
                    if (
                        isinstance(observation, dict)
                        and observation.get("status") == "observed"
                    )
                ]

        except Exception as e:
            print(f"[WARNING] Frida evidence could not be loaded: {e}")
            frida_evidence = {}
            frida_observations = []

    # ==================================================
    # Overall Statistics
    # ==================================================

    unique_artifacts_by_type = {}

    for artifact in unique_sensitive_artifacts:
        artifact_type = artifact.get("type", "Unknown")

        unique_artifacts_by_type[artifact_type] = (
            unique_artifacts_by_type.get(artifact_type, 0) + 1
        )

    statistics = {
        "app_name": app_name,
        "total_requests": len(requests),
        "har_network_requests": len(requests),
        "frida_privacy_observations": len(frida_observations),
        "total_evidence_events": (len(requests) + len(frida_observations)),
        "unique_artifacts_by_type": unique_artifacts_by_type,
        "application_requests": sum(
            1 for r in requests if r.traffic_type == "Application"
        ),
        "android_requests": sum(
            1 for r in requests if r.traffic_type == "Android System"
        ),
        "third_party_requests": sum(
            1 for r in requests if r.traffic_type == "Third Party"
        ),
        "unknown_requests": sum(1 for r in requests if r.traffic_type == "Unknown"),
        # Occurrences = request-level evidence observations. This retains
        # historical counting semantics for reproducibility.
        "sensitive_data_occurrences": sum(len(r.sensitive_data) for r in requests),
        # Unique artifacts = distinct sensitive values grouped by fingerprint.
        "unique_sensitive_artifacts": len(unique_sensitive_artifacts),
        "sensitive_data_findings": sum(len(r.sensitive_data) for r in requests),
        "comparison_outbound_occurrences": sum(
            1
            for request in requests
            for finding in request.sensitive_data
            if (
                request.traffic_type in {"Application", "Third Party"}
                and finding.get("direction") == "outbound"
                and finding.get("privacy_category")
                not in NON_COMPARABLE_OBSERVED_CATEGORIES
            )
        ),
        "attributable_inbound_occurrences": sum(
            1
            for request in requests
            for finding in request.sensitive_data
            if (
                request.traffic_type in {"Application", "Third Party"}
                and finding.get("direction") == "inbound"
            )
        ),
        "excluded_technical_occurrences": sum(
            1
            for request in requests
            for finding in request.sensitive_data
            if (
                request.traffic_type in {"Application", "Third Party"}
                and finding.get("direction") == "outbound"
                and finding.get("privacy_category")
                in NON_COMPARABLE_OBSERVED_CATEGORIES
            )
        ),
        "non_attributable_occurrences": sum(
            len(request.sensitive_data)
            for request in requests
            if request.traffic_type not in {"Application", "Third Party"}
        ),
        "sensitive_findings_by_traffic": (sensitive_findings_by_traffic),
        "sensitive_findings_by_category": (sensitive_findings_by_category),
        "unique_artifacts_by_category": (unique_artifacts_by_category),
    }
    # ==================================================
    # Export Traffic Analysis Results
    # ==================================================

    exporter = JSONExporter(output_path)

    exporter.export_requests(requests)

    exporter.export_statistics(statistics)

    exporter.export_privacy_inventory(privacy_inventory)

    exporter.export_sensitive_artifacts(unique_sensitive_artifacts)

    # ==================================================
    # Privacy Compliance Comparison
    # ==================================================

    compliance_results = None
    compliance_summary = None
    simple_report = None

    if policy_file.exists():

        print("\nComparing observed traffic " "with policy evidence...")
        compliance_path = output_path / "compliance_results.json"

        try:

            # ------------------------------------------
            # Load Policy Evidence
            # ------------------------------------------

            policy_data = PrivacyPolicyParser(policy_file).parse()

            # ------------------------------------------
            # Frida Evidence Status
            # ------------------------------------------

            if frida_evidence:
                print("[OK] Frida evidence loaded.")
            else:
                print("[i] No Frida evidence found.")

            # ------------------------------------------
            # Create Comparator
            # ------------------------------------------

            comparator = PolicyComparator(
                privacy_inventory, policy_data, app_name, frida_evidence
            )

            # ------------------------------------------
            # Compare Observed vs Declared
            # ------------------------------------------

            compliance_results = comparator.compare()
            category_results = comparator.compare_categories()

            compliance_summary = comparator.generate_summary(
                compliance_results, category_results
            )

            # ------------------------------------------
            # Build Compliance Report
            # ------------------------------------------

            compliance_report = {
                "schema_version": 2,
                "application": app_name,
                "observed_categories": sorted(comparator.get_observed_categories()),
                "comparison_observed_categories": sorted(
                    comparator.get_comparison_har_categories()
                ),
                "frida_categories": sorted(comparator.get_frida_categories()),
                "runtime_observations": comparator.get_runtime_observations(),
                "declared_categories": sorted(comparator.get_declared_categories()),
                "observed_practices": comparator.get_observed_practices(),
                "policy_practices": comparator.get_policy_practices(),
                "comparison_coverage": comparator.get_comparison_coverage(),
                "policy_quality": comparator.get_policy_quality(),
                "results": compliance_results,
                "category_results": category_results,
                "practice_risks": comparator.get_practice_risks(),
                "excluded_non_attributable_evidence": (
                    comparator.get_non_attributable_evidence()
                ),
                "inbound_evidence": comparator.get_inbound_evidence(),
                "summary": compliance_summary,
            }

            simple_report = build_simple_report(
                privacy_inventory, compliance_report, policy_data
            )
            compliance_report["simple_report"] = simple_report

            # ------------------------------------------
            # Export Compliance Results
            # ------------------------------------------

            with open(compliance_path, "w", encoding="utf-8") as file:

                json.dump(
                    exporter.sanitize_evidence_document(compliance_report),
                    file,
                    indent=4,
                )

            print("[OK] compliance_results.json exported")

        except Exception as e:

            print("\n[WARNING] Compliance comparison " f"failed: {e}")
            try:
                compliance_path.unlink(missing_ok=True)
            except OSError as cleanup_error:
                print(
                    "[WARNING] Stale compliance output could not be removed: "
                    f"{cleanup_error}"
                )
            print("Framework execution failed during policy comparison.")
            return 1

    else:

        print("\n[WARNING] No policy evidence available.")

        print("          Compliance comparison skipped.")

    # ==================================================
    # Console Summary
    # ==================================================

    print("\n" + "=" * 60)
    print("Execution Summary")
    print("=" * 60)

    print(f"Application                 : " f"{statistics['app_name']}")

    print(f"HAR Network Requests        : " f"{statistics['har_network_requests']}")

    print(
        f"Frida Privacy Observations  : " f"{statistics['frida_privacy_observations']}"
    )

    print(f"Total Evidence Events       : " f"{statistics['total_evidence_events']}")

    print(f"Application Requests        : " f"{statistics['application_requests']}")

    print(f"Android Requests            : " f"{statistics['android_requests']}")

    print(f"Third Party Requests        : " f"{statistics['third_party_requests']}")

    print(f"Unknown Requests            : " f"{statistics['unknown_requests']}")

    print(f"Sensitive Data Occurrences   : " f"{statistics['sensitive_data_occurrences']}")
    print(f"Unique Sensitive Artifacts   : " f"{statistics['unique_sensitive_artifacts']}")
    print(
        f"Comparable Outbound Findings : "
        f"{statistics['comparison_outbound_occurrences']}"
    )
    print(
        f"Attributable Inbound Findings: "
        f"{statistics['attributable_inbound_occurrences']}"
    )
    print(
        f"Excluded Technical Findings  : "
        f"{statistics['excluded_technical_occurrences']}"
    )
    print(
        f"Non-Attributable Findings    : "
        f"{statistics['non_attributable_occurrences']}"
    )

    print("\nSensitive Findings by Traffic Type")

    for traffic_type, count in statistics["sensitive_findings_by_traffic"].items():

        print(f"   {traffic_type:<20}: {count}")

    print("\nSensitive Findings by Privacy Category")

    for category, count in statistics["sensitive_findings_by_category"].items():

        print(f"   {category:<25}: {count}")

    print("\nUnique Artifacts by Privacy Category")

    for category, count in statistics["unique_artifacts_by_category"].items():

        print(f"   {category:<25}: {count}")

    print("\nUnique Artifacts by Type")

    for artifact_type, count in statistics["unique_artifacts_by_type"].items():

        print(f"   {artifact_type:<25}: {count}")
    # ==================================================
    # Privacy Categories
    # ==================================================

    print("\nPrivacy Categories")

    for traffic_type, data in privacy_inventory.items():

        print(f"\n[{traffic_type}]")

        print(f"Requests : " f"{data['request_count']}")

        print("Domains:")

        for domain in data["domains"]:

            print(f"   - {domain}")

        print("Privacy Categories:")

        for category in data["privacy_categories"]:

            print(f"   - {category}")

    # ==================================================
    # Simple Policy-versus-Traffic Result
    # ==================================================

    if simple_report is not None:
        print("\n" + format_simple_report(simple_report))

    # ==================================================
    # Output Files
    # ==================================================

    print("\nResults exported to:")

    print(f"   {output_path / 'classified_requests.json'}")

    print(f"   {output_path / 'statistics.json'}")

    print(f"   {output_path / 'privacy_inventory.json'}")

    print(f"   {output_path / 'sensitive_artifacts.json'}")

    if compliance_results is not None:

        print(f"   {output_path / 'compliance_results.json'}")

    print("\nFramework execution completed successfully.")
    return 0


# ======================================================
# Program Entry Point
# ======================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=("Privacy Compliance Verification Framework")
    )

    parser.add_argument("--app", required=True, help="Application name to analyze")

    args = parser.parse_args()

    sys.exit(main(args.app))
