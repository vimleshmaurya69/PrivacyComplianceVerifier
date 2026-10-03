from src.report.simple_result_presenter import build_simple_report, format_simple_report


def _inventory(*findings):
    return {"Application": {"evidence": list(findings)}}


def _finding(artifact, category="Personal Information", **overrides):
    value = {
        "type": artifact,
        "privacy_category": category,
        "source": "Query Parameter",
        "direction": "outbound",
        "key": artifact.lower().replace(" ", "_"),
        "domain": "api.example.test",
    }
    value.update(overrides)
    return value


def _policy(practices, complete=True):
    return {
        "policy_available": True,
        "sources": [{"source_id": "policy", "url": "https://example.test/privacy"}],
        "last_verified": "2026-10-03" if complete else None,
        "declared_categories": ["Personal Information"],
        "policy_practices": practices,
    }


def _practice(artifact=None, text=None, category="Personal Information"):
    return {
        "practice_id": f"p-{artifact or 'legacy'}",
        "privacy_category": category,
        "artifact_types": [artifact] if artifact else [],
        "provenance": {
            "source_ids": ["policy"],
            "locator": "Section 1",
            "evidence": text,
            "reviewed_at": "2026-10-03",
        },
        "legacy_evidence": {"data_type": text},
    }


def test_simple_report_is_one_decision_per_information_type_and_no_raw_values():
    inventory = _inventory(
        _finding("Phone", value_redacted="+12025550147"),
        _finding("Phone", domain="other.example.test"),
        _finding("Device ID", "Device Identifier", source="Request Body"),
    )
    inventory["Android System"] = {"evidence": [_finding("Email")]}
    compliance = {"practice_risks": [{
        "type": "PERSONAL_DATA_IN_URL",
        "severity": "MEDIUM",
        "explanation": "URL logging risk.",
        "evidence": [{"key": "phone"}],
    }]}
    report = build_simple_report(inventory, compliance, _policy([_practice("Phone")]))

    assert report["policy_declares"]["information_types"] == ["Phone"]
    assert [item["artifact_type"] for item in report["traffic_transmits"]] == ["Device ID", "Phone"]
    phone = next(item for item in report["information_type_results"] if item["artifact_type"] == "Phone")
    assert phone["occurrences"] == 2
    assert phone["status"] == "DISCLOSED"
    device = next(item for item in report["information_type_results"] if item["artifact_type"] == "Device ID")
    assert device["status"] == "NOT_DISCLOSED_IN_REVIEWED_POLICY"
    assert report["non_attributable_outbound_findings"] == 1
    assert report["capture_scoped_result"] == "POTENTIALLY_NON_COMPLIANT"
    assert report["compliance_determination"] == "NOT DETERMINED"

    rendered = format_simple_report(report)
    assert "Policy vs Observed Network Traffic" in rendered
    assert "Phone" in rendered and "IN POLICY" in rendered
    assert "Device ID" in rendered and "NOT IN POLICY" in rendered
    assert "Project result: POTENTIALLY NON-COMPLIANT" in rendered
    assert "Separate transmission-risk signals" in rendered
    assert "+12025550147" not in rendered


def test_cli_table_explains_no_risk_does_not_mean_disclosed():
    report = build_simple_report(
        _inventory(_finding("Email")),
        {"practice_risks": []},
        _policy([]),
    )
    rendered = format_simple_report(report)
    assert "Information Type" in rendered
    assert "Observed" in rendered
    assert "In Policy" in rendered
    assert "None detected. This does not mean every observed type was disclosed." in rendered


def test_incomplete_review_does_not_turn_absence_into_non_disclosure():
    report = build_simple_report(
        _inventory(_finding("Latitude", "Location")),
        {"practice_risks": []},
        _policy([], complete=False),
    )
    assert report["result"] == "CANNOT_DETERMINE"
    assert report["comparison"][0]["result"] == "POLICY_REVIEW_INCOMPLETE"


def test_broad_category_does_not_disclose_specific_artifact():
    policy = _policy([_practice(text="We collect personal information.")])
    report = build_simple_report(_inventory(_finding("Email")), {"practice_risks": []}, policy)
    assert report["information_type_results"][0]["status"] == "NOT_DISCLOSED_IN_REVIEWED_POLICY"


def test_precise_coordinates_disclose_latitude_and_longitude_but_location_alone_does_not():
    inventory = _inventory(_finding("Latitude", "Location"), _finding("Longitude", "Location"))
    coordinate_policy = _policy([_practice(text="We collect GPS coordinates.", category="Location")])
    report = build_simple_report(inventory, {"practice_risks": []}, coordinate_policy)
    observed = [item for item in report["information_type_results"] if item["occurrences"]]
    assert {item["status"] for item in observed} == {"DISCLOSED"}

    broad_policy = _policy([_practice(text="We collect location.", category="Location")])
    broad = build_simple_report(inventory, {"practice_risks": []}, broad_policy)
    observed = [item for item in broad["information_type_results"] if item["occurrences"]]
    assert {item["status"] for item in observed} == {"NOT_DISCLOSED_IN_REVIEWED_POLICY"}


def test_url_risk_stays_separate_from_disclosure_result():
    compliance = {"practice_risks": [{"type": "PERSONAL_DATA_IN_URL", "evidence": [{}]}]}
    report = build_simple_report(_inventory(_finding("Phone")), compliance, _policy([_practice("Phone")]))
    assert report["capture_scoped_result"] == "COMPLIANT_WITHIN_CAPTURE_SCOPE"
    assert len(report["risk_signals"]) == 1


def test_non_comparable_technical_category_is_excluded():
    report = build_simple_report(
        _inventory(_finding("API Key", "API Credentials")),
        {"practice_risks": []},
        _policy([_practice("Phone")]),
    )
    assert report["traffic_transmits"] == []
    assert report["result"] == "CANNOT_DETERMINE"
    assert report["excluded_evidence"][0]["artifact_type"] == "API Key"
    assert report["excluded_evidence"][0]["reason"] == "NOT_COMPARABLE_CATEGORY"
    assert report["excluded_non_comparable_findings"] == 1


def test_declared_har_incapable_type_is_not_assessable():
    report = build_simple_report({}, {"practice_risks": []}, _policy([_practice("Camera", category="Media Access")]))
    assert report["information_type_results"][0]["status"] == "NOT_ASSESSABLE_FROM_HAR"
