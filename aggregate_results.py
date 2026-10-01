import csv
import json
from pathlib import Path


OUTPUT_ROOT = Path("data/output")
ANALYSIS_ROOT = Path("data/analysis")


def _count_status(results, *statuses):
    return sum(1 for result in results if result.get("status") in statuses)


def build_rows(output_root=OUTPUT_ROOT):
    rows = []

    for app_dir in sorted(output_root.iterdir()):
        if not app_dir.is_dir():
            continue

        stats_file = app_dir / "statistics.json"
        compliance_file = app_dir / "compliance_results.json"
        if not stats_file.exists():
            continue

        with open(stats_file, "r", encoding="utf-8") as file:
            stats = json.load(file)

        compliance = {}
        if compliance_file.exists():
            with open(compliance_file, "r", encoding="utf-8") as file:
                compliance = json.load(file)

        results = compliance.get("results", [])
        category_results = compliance.get("category_results", [])
        summary = compliance.get("summary", {})
        schema_version = compliance.get("schema_version", 1)

        if schema_version >= 2:
            practice_disclosed = _count_status(results, "PRACTICE DISCLOSED")
            information_type_disclosed = _count_status(
                results,
                "INFORMATION DISCLOSED",
                "INFORMATION TYPE DISCLOSED",
            )
            potential_non_disclosures = _count_status(
                results, "POTENTIAL NON-DISCLOSURE"
            )
            insufficient_policy_detail = _count_status(
                results, "INSUFFICIENT POLICY DETAIL"
            )
            disclosed_categories = _count_status(
                category_results, "CATEGORY DECLARED"
            )
            declared_only_categories = _count_status(
                category_results, "CATEGORY LISTED"
            )
            report_format = "practice-v2"
        else:
            practice_disclosed = 0
            information_type_disclosed = 0
            potential_non_disclosures = 0
            insufficient_policy_detail = 0
            disclosed_categories = _count_status(
                results, "DISCLOSED", "COMPLIANT"
            )
            declared_only_categories = _count_status(
                results, "DECLARED ONLY"
            )
            report_format = "legacy-category"

        rows.append({
            "application": stats.get("app_name", app_dir.name),
            "total_requests": stats.get("total_requests", 0),
            "application_requests": stats.get("application_requests", 0),
            "third_party_requests": stats.get("third_party_requests", 0),
            "android_requests": stats.get("android_requests", 0),
            "unknown_requests": stats.get("unknown_requests", 0),
            "frida_observations": stats.get("frida_privacy_observations", 0),
            "total_evidence_events": stats.get("total_evidence_events", 0),
            "sensitive_occurrences": stats.get("sensitive_data_occurrences", 0),
            "unique_sensitive_artifacts": stats.get(
                "unique_sensitive_artifacts", 0
            ),
            "comparison_outbound_occurrences": stats.get(
                "comparison_outbound_occurrences", 0
            ),
            "attributable_inbound_occurrences": stats.get(
                "attributable_inbound_occurrences", 0
            ),
            "excluded_technical_occurrences": stats.get(
                "excluded_technical_occurrences", 0
            ),
            "non_attributable_occurrences": stats.get(
                "non_attributable_occurrences", 0
            ),
            "personal_information": stats.get(
                "sensitive_findings_by_category", {}
            ).get("Personal Information", 0),
            "authentication": stats.get(
                "sensitive_findings_by_category", {}
            ).get("Authentication", 0),
            "device_identifier": stats.get(
                "sensitive_findings_by_category", {}
            ).get("Device Identifier", 0),
            "location": stats.get(
                "sensitive_findings_by_category", {}
            ).get("Location", 0),
            "network_information": stats.get(
                "sensitive_findings_by_category", {}
            ).get("Network Information", 0),
            "security": stats.get(
                "sensitive_findings_by_category", {}
            ).get("Security", 0),
            "api_credentials": stats.get(
                "sensitive_findings_by_category", {}
            ).get("API Credentials", 0),
            "unknown_category": stats.get(
                "sensitive_findings_by_category", {}
            ).get("Unknown", 0),
            "practice_disclosed": practice_disclosed,
            "information_type_disclosed": information_type_disclosed,
            "potential_non_disclosures": potential_non_disclosures,
            "insufficient_policy_detail": insufficient_policy_detail,
            "disclosed_categories": disclosed_categories,
            "declared_only_categories": declared_only_categories,
            "category_not_observed_in_capture": summary.get(
                "category_not_observed_in_capture", 0
            ),
            "category_not_assessable_from_har": summary.get(
                "category_not_assessable_from_har", 0
            ),
            "not_observed_in_capture": summary.get(
                "not_observed_in_capture",
                _count_status(results, "NOT OBSERVED IN CAPTURE", "NOT OBSERVED"),
            ),
            "not_assessable_from_har": summary.get(
                "not_assessable_from_har",
                _count_status(results, "NOT ASSESSABLE FROM HAR"),
            ),
            "practice_risks": summary.get(
                "practice_risks", len(compliance.get("practice_risks", []))
            ),
            "runtime_observations": summary.get(
                "runtime_observations",
                len(compliance.get("runtime_observations", [])),
            ),
            "overall_status": summary.get("overall_status", "NO REPORT"),
            "compliance_determination": summary.get(
                "compliance_determination", "LEGACY REPORT"
            ),
            "assessment_flags": ";".join(
                summary.get("assessment_flags", [])
            ),
            "policy_quality_issues": ";".join(
                summary.get("policy_quality", {}).get("issues", [])
            ),
            "report_format": report_format,
        })

    return rows


def write_results(rows, analysis_root=ANALYSIS_ROOT):
    analysis_root.mkdir(parents=True, exist_ok=True)
    csv_file = analysis_root / "master_results.csv"
    json_file = analysis_root / "master_results.json"

    if rows:
        with open(csv_file, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(rows, file, indent=2)

    return csv_file, json_file


def main():
    rows = build_rows()
    csv_file, json_file = write_results(rows)

    print("=" * 60)
    print("MASTER EXPERIMENT DATASET")
    print("=" * 60)
    print(f"Applications : {len(rows)}")
    print(f"CSV          : {csv_file}")
    print(f"JSON         : {json_file}")
    print("=" * 60)

    for row in rows:
        print(
            f"{row['application']:<20} "
            f"Requests={row['total_requests']:<5} "
            f"Sensitive={row['sensitive_occurrences']:<5} "
            f"Disclosed={row['practice_disclosed']:<3} "
            f"InfoType={row['information_type_disclosed']:<3} "
            f"PotentialNonDisclosure={row['potential_non_disclosures']} "
            f"Status={row['overall_status']}"
        )


if __name__ == "__main__":
    main()
