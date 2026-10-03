import csv
import json
from pathlib import Path


OUTPUT_ROOT = Path("data/output")
ANALYSIS_ROOT = Path("data/analysis")
APP_ROOT = Path("data/apps")


def _count_status(results, *statuses):
    return sum(1 for result in results if result.get("status") in statuses)


def _count_unique_information_types(results, *statuses):
    matching = [item for item in results if item.get("status") in statuses]
    information_types = {
        artifact
        for item in matching
        for artifact in (
            [item.get("artifact_type")] + list(item.get("artifact_types", []))
        )
        if artifact
    }
    return len(information_types) if information_types else len(matching)


def _simple_presentation(compliance, results, summary):
    """Read the new concise report or derive it from legacy detailed output."""
    simple = compliance.get("simple_report", {})
    comparison = {
        item.get("result"): item.get(
            "information_type_count", item.get("count", 0)
        )
        for item in simple.get("comparison", [])
        if isinstance(item, dict) and item.get("result")
    }
    if not comparison:
        comparison = {
            "PRACTICE DISCLOSED": _count_unique_information_types(
                results, "PRACTICE DISCLOSED"
            ),
            "INFORMATION TYPE DISCLOSED": _count_unique_information_types(
                results,
                "INFORMATION DISCLOSED",
                "INFORMATION TYPE DISCLOSED",
            ),
            "POTENTIAL NON-DISCLOSURE": _count_unique_information_types(
                results, "POTENTIAL NON-DISCLOSURE"
            ),
            "POLICY DETAIL INSUFFICIENT": _count_unique_information_types(
                results, "INSUFFICIENT POLICY DETAIL"
            ),
            "DECLARED - NOT OBSERVED IN CAPTURE": _count_unique_information_types(
                results, "NOT OBSERVED IN CAPTURE", "NOT OBSERVED"
            ),
            "NOT ASSESSABLE FROM HAR": _count_unique_information_types(
                results, "NOT ASSESSABLE FROM HAR"
            ),
        }

    # Canonical information-type presentation (v1).  Keep the legacy keys
    # above available for older generated reports.
    disclosed = comparison.get("DISCLOSED", 0)
    not_disclosed = comparison.get(
        "NOT_DISCLOSED_IN_REVIEWED_POLICY", 0
    )
    review_incomplete = comparison.get("POLICY_REVIEW_INCOMPLETE", 0)
    declared_not_observed = comparison.get(
        "DECLARED_NOT_OBSERVED_IN_CAPTURE",
        comparison.get("DECLARED - NOT OBSERVED IN CAPTURE", 0),
    )
    not_assessable = comparison.get(
        "NOT_ASSESSABLE_FROM_HAR",
        comparison.get("NOT ASSESSABLE FROM HAR", 0),
    )

    policy_declares = simple.get("policy_declares", {})
    categories = policy_declares.get(
        "categories", compliance.get("declared_categories", [])
    )
    information_types = policy_declares.get("information_types", [])
    if not information_types:
        information_types = sorted({
            artifact
            for practice in compliance.get("policy_practices", [])
            if isinstance(practice, dict)
            for artifact in practice.get("artifact_types", [])
            if artifact
        })

    traffic_types = sorted({
        item.get("artifact_type")
        for item in simple.get(
            "traffic_transmits", compliance.get("observed_practices", [])
        )
        if isinstance(item, dict) and item.get("artifact_type")
    })
    risks = simple.get("risk_signals", compliance.get("practice_risks", []))
    risk_names = [
        item.get("title") or item.get("type")
        for item in risks
        if isinstance(item, dict) and (item.get("title") or item.get("type"))
    ]

    result = simple.get("result")
    if not result:
        if comparison.get("POTENTIAL NON-DISCLOSURE", 0) or risk_names:
            result = "POLICY-TRAFFIC REVIEW REQUIRED"
        elif comparison.get("POLICY DETAIL INSUFFICIENT", 0):
            result = "POLICY DETAIL INSUFFICIENT"
        elif (
            comparison.get("PRACTICE DISCLOSED", 0)
            or comparison.get("INFORMATION TYPE DISCLOSED", 0)
        ):
            result = "POLICY-TRAFFIC MATCHES FOUND"
        elif traffic_types:
            result = "TRAFFIC OBSERVED - POLICY COMPARISON LIMITED"
        else:
            result = "INSUFFICIENT EVIDENCE"

    return {
        "policy_categories": sorted(set(categories)),
        "policy_information_types": sorted(set(information_types)),
        "traffic_information_types": traffic_types,
        "comparison": comparison,
        "risk_signals": risk_names,
        "result": result,
        "policy_review_status": simple.get("policy_review", {}).get(
            "status", "UNKNOWN"
        ),
        "disclosed_information_types": disclosed,
        "not_disclosed_information_types": not_disclosed,
        "policy_review_incomplete_types": review_incomplete,
        "declared_not_observed_types": declared_not_observed,
        "not_assessable_types": not_assessable,
        "compliance_determination": simple.get(
            "compliance_determination", "NOT DETERMINED"
        ),
    }


def _aggregate_exclusions(app_root):
    excluded = set()
    if not app_root.exists():
        return excluded
    for config_file in app_root.glob("*/app_config.json"):
        try:
            with open(config_file, "r", encoding="utf-8") as file:
                config = json.load(file)
        except (OSError, json.JSONDecodeError):
            continue
        if config.get("exclude_from_aggregate") is True:
            excluded.add(config_file.parent.name.casefold())
    return excluded


def build_rows(output_root=OUTPUT_ROOT, app_root=APP_ROOT):
    rows = []
    excluded_apps = _aggregate_exclusions(Path(app_root))

    for app_dir in sorted(output_root.iterdir()):
        if not app_dir.is_dir():
            continue
        if app_dir.name.casefold() in excluded_apps:
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

        presentation = _simple_presentation(compliance, results, summary)

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
            "policy_declares": ";".join(
                presentation["policy_information_types"]
                or presentation["policy_categories"]
            ),
            "traffic_transmits": ";".join(
                presentation["traffic_information_types"]
            ),
            "declared_and_observed": presentation["comparison"].get(
                "PRACTICE DISCLOSED", 0
            ),
            "policy_mentions_observed_information": presentation[
                "comparison"
            ].get("INFORMATION TYPE DISCLOSED", 0),
            "observed_no_explicit_policy_match": presentation[
                "comparison"
            ].get("POTENTIAL NON-DISCLOSURE", 0),
            "policy_detail_insufficient_simple": presentation[
                "comparison"
            ].get("POLICY DETAIL INSUFFICIENT", 0),
            "declared_not_observed": presentation["comparison"].get(
                "DECLARED - NOT OBSERVED IN CAPTURE", 0
            ),
            "risk_signals": ";".join(presentation["risk_signals"]),
            "result": presentation["result"],
            "policy_review_status": presentation["policy_review_status"],
            "observed_information_type_count": len(
                presentation["traffic_information_types"]
            ),
            "disclosed_information_type_count": presentation[
                "disclosed_information_types"
            ],
            "not_disclosed_information_type_count": presentation[
                "not_disclosed_information_types"
            ],
            "policy_review_incomplete_type_count": presentation[
                "policy_review_incomplete_types"
            ],
            "declared_not_observed_type_count": presentation[
                "declared_not_observed_types"
            ],
            "not_assessable_type_count": presentation[
                "not_assessable_types"
            ],
            "capture_scoped_result": presentation["result"],
            "simple_compliance_determination": presentation[
                "compliance_determination"
            ],
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
            f"Disclosed={row['disclosed_information_type_count']:<3} "
            f"NotDisclosed={row['not_disclosed_information_type_count']:<3} "
            f"ReviewIncomplete={row['policy_review_incomplete_type_count']:<3} "
            f"Risks={row['risk_signals'] or 'None'} "
            f"Result={row['result']}"
        )


if __name__ == "__main__":
    main()
