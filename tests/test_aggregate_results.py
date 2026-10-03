import json

from aggregate_results import build_rows


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_aggregate_reads_practice_v2_results(tmp_path):
    app = tmp_path / "Example"
    write_json(app / "statistics.json", {
        "app_name": "Example",
        "total_requests": 1,
        "comparison_outbound_occurrences": 3,
        "attributable_inbound_occurrences": 2,
        "excluded_technical_occurrences": 1,
        "non_attributable_occurrences": 4,
        "sensitive_findings_by_category": {},
    })
    write_json(app / "compliance_results.json", {
        "schema_version": 2,
        "results": [
            {"status": "PRACTICE DISCLOSED"},
            {"status": "INFORMATION DISCLOSED"},
            {"status": "INFORMATION TYPE DISCLOSED"},
            {"status": "POTENTIAL NON-DISCLOSURE"},
            {"status": "INSUFFICIENT POLICY DETAIL"},
        ],
        "category_results": [{"status": "CATEGORY DECLARED"}],
        "summary": {
            "overall_status": "POTENTIAL NON-DISCLOSURE",
            "compliance_determination": "NOT DETERMINED",
            "assessment_flags": ["POTENTIAL_NON_DISCLOSURE"],
            "policy_quality": {"issues": []},
        },
    })

    row = build_rows(tmp_path)[0]
    assert row["practice_disclosed"] == 1
    assert row["information_type_disclosed"] == 2
    assert row["potential_non_disclosures"] == 1
    assert row["insufficient_policy_detail"] == 1
    assert row["disclosed_categories"] == 1
    assert row["comparison_outbound_occurrences"] == 3
    assert row["attributable_inbound_occurrences"] == 2
    assert row["excluded_technical_occurrences"] == 1
    assert row["non_attributable_occurrences"] == 4
    assert row["report_format"] == "practice-v2"
    assert row["declared_and_observed"] == 1
    assert row["policy_mentions_observed_information"] == 2
    assert row["observed_no_explicit_policy_match"] == 1
    assert row["policy_detail_insufficient_simple"] == 1
    assert row["result"] == "POLICY-TRAFFIC REVIEW REQUIRED"


def test_aggregate_keeps_legacy_reports_loadable(tmp_path):
    app = tmp_path / "Legacy"
    write_json(app / "statistics.json", {
        "app_name": "Legacy",
        "total_requests": 1,
        "sensitive_findings_by_category": {},
    })
    write_json(app / "compliance_results.json", {
        "results": [
            {"status": "DISCLOSED"},
            {"status": "POTENTIAL MISMATCH"},
        ],
        "summary": {
            "overall_status": "POTENTIAL NON-COMPLIANCE",
            "compliance_determination": "NOT DETERMINED",
            "assessment_flags": [],
            "policy_quality": {"issues": []},
        },
    })

    row = build_rows(tmp_path)[0]
    assert row["practice_disclosed"] == 0
    assert row["information_type_disclosed"] == 0
    assert row["potential_non_disclosures"] == 0
    assert row["disclosed_categories"] == 1
    assert row["report_format"] == "legacy-category"


def test_aggregate_exports_capture_scoped_information_type_fields(tmp_path):
    app = tmp_path / "Simple"
    write_json(app / "statistics.json", {
        "app_name": "Simple",
        "total_requests": 2,
        "sensitive_findings_by_category": {},
    })
    write_json(app / "compliance_results.json", {
        "schema_version": 2,
        "results": [],
        "summary": {"compliance_determination": "NOT DETERMINED"},
        "simple_report": {
            "policy_review": {"status": "REVIEWED_COMPLETE"},
            "policy_declares": {"categories": [], "information_types": ["Phone"]},
            "traffic_transmits": [
                {"artifact_type": "Phone"},
                {"artifact_type": "Email"},
            ],
            "comparison": [
                {"result": "DISCLOSED", "information_type_count": 1},
                {
                    "result": "NOT_DISCLOSED_IN_REVIEWED_POLICY",
                    "information_type_count": 1,
                },
                {
                    "result": "DECLARED_NOT_OBSERVED_IN_CAPTURE",
                    "information_type_count": 2,
                },
            ],
            "risk_signals": [],
            "result": "POTENTIALLY_NON_COMPLIANT",
            "compliance_determination": "NOT DETERMINED",
        },
    })

    row = build_rows(tmp_path)[0]
    assert row["policy_review_status"] == "REVIEWED_COMPLETE"
    assert row["observed_information_type_count"] == 2
    assert row["disclosed_information_type_count"] == 1
    assert row["not_disclosed_information_type_count"] == 1
    assert row["declared_not_observed_type_count"] == 2
    assert row["capture_scoped_result"] == "POTENTIALLY_NON_COMPLIANT"
    assert row["simple_compliance_determination"] == "NOT DETERMINED"


def test_aggregate_excludes_marked_synthetic_application(tmp_path):
    output_root = tmp_path / "output"
    app_root = tmp_path / "apps"
    write_json(output_root / "Real" / "statistics.json", {
        "app_name": "Real",
        "sensitive_findings_by_category": {},
    })
    write_json(output_root / "Synthetic" / "statistics.json", {
        "app_name": "Synthetic",
        "sensitive_findings_by_category": {},
    })
    write_json(app_root / "Synthetic" / "app_config.json", {
        "exclude_from_aggregate": True,
    })

    rows = build_rows(output_root, app_root)

    assert [row["application"] for row in rows] == ["Real"]
