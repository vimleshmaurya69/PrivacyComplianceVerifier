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
