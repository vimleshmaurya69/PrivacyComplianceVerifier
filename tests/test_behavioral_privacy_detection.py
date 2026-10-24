import json

from src.analyzer.privacy_inventory import PrivacyInventoryGenerator
from src.analyzer.privacy_normalizer import PrivacyNormalizer
from src.analyzer.sensitive_data_detector import SensitiveDataDetector
from src.comparator.information_type_comparator import (
    DISCLOSED,
    NOT_DISCLOSED,
    compare_information_types,
)
from src.comparator.policy_comparator import PolicyComparator
from src.comparator.practice_risk_assessor import assess_practice_risks
from src.models.request import Request
from src.policy.policy_artifact_semantics import extract_explicit_policy_artifacts


def make_request(
    *,
    url="https://api.example.test/",
    domain="api.example.test",
    body=None,
    content_type="application/json",
    query_pairs=None,
    traffic_type="Application",
):
    return Request(
        method="POST" if body is not None else "GET",
        url=url,
        domain=domain,
        status=200,
        mime_type=content_type,
        query_param_pairs=list(query_pairs or []),
        body=body,
        body_type="json" if content_type == "application/json" else "text",
        content_type=content_type,
        traffic_type=traffic_type,
    )


def analyze(requests):
    detector = SensitiveDataDetector(requests)
    analyzed = detector.analyze()
    PrivacyNormalizer(analyzed).normalize()
    return analyzed


def findings_of(request, finding_type):
    return [
        finding
        for finding in request.sensitive_data
        if finding.get("type") == finding_type
    ]


def complete_policy(practices=None):
    return {
        "policy_available": True,
        "last_verified": "2026-10-23",
        "sources": [{
            "source_id": "policy",
            "title": "Privacy Policy",
            "url": "https://example.test/privacy",
        }],
        "information_type_review": {
            "status": "REVIEWED_COMPLETE",
            "reviewed_at": "2026-10-23",
        },
        "policy_practices": list(practices or []),
    }


def test_explicit_installed_app_array_is_detected_once_without_raw_values():
    request = make_request(body=json.dumps({
        "apps_installed": [
            {"package_name": "com.example.alpha"},
            {"package_name": "org.example.beta"},
            {"package_name": "in.example.gamma"},
        ]
    }))

    analyze([request])

    findings = findings_of(request, "Installed Application List")
    assert len(findings) == 1
    assert findings[0]["key"] == "apps_installed"
    assert findings[0]["privacy_category"] == "Device Information"
    assert findings[0]["value_redacted"] == "[REDACTED APPLICATION INVENTORY]"
    assert "com.example.alpha" not in json.dumps(findings)


def test_string_installed_apps_array_is_detected_at_nested_path():
    request = make_request(body=json.dumps({
        "checkout": {
            "installedApps": ["com.payment.one", "com.payment.two"]
        }
    }))

    analyze([request])

    findings = findings_of(request, "Installed Application List")
    assert len(findings) == 1
    assert findings[0]["key"] == "checkout.installedApps"


def test_isolated_or_single_package_fields_do_not_become_app_inventory():
    request = make_request(body=json.dumps({
        "package_name": "com.host.application",
        "installedApps": ["com.payment.one"],
        "packages": ["com.example.alpha", "com.example.beta"],
    }))

    analyze([request])

    assert findings_of(request, "Installed Application List") == []


def test_explicit_search_keys_and_search_endpoint_query_are_detected():
    body_request = make_request(body=json.dumps({"typedKeyword": "running shoes"}))
    query_request = make_request(
        url="https://api.example.test/catalog/search?q=running%20shoes",
        body=None,
        query_pairs=[("q", "running shoes")],
    )

    analyze([body_request, query_request])

    body_finding = findings_of(body_request, "Search Query")[0]
    query_finding = findings_of(query_request, "Search Query")[0]
    assert body_finding["key"] == "typedKeyword"
    assert query_finding["source"] == "Query Parameter"
    assert body_finding["value_redacted"] == "[REDACTED SEARCH QUERY]"
    assert body_finding["privacy_category"] == "Search"


def test_generic_query_keys_need_search_endpoint_and_human_text():
    graphql = make_request(
        url="https://api.example.test/graphql?q=viewer",
        body=None,
        query_pairs=[("q", "viewer")],
    )
    numeric = make_request(
        url="https://api.example.test/search?q=123456",
        body=None,
        query_pairs=[("q", "123456")],
    )
    opaque = make_request(body=json.dumps({
        "search_query": "0123456789abcdef0123456789abcdef"
    }))

    analyze([graphql, numeric, opaque])

    assert findings_of(graphql, "Search Query") == []
    assert findings_of(numeric, "Search Query") == []
    assert findings_of(opaque, "Search Query") == []


def test_exact_search_value_correlation_marks_only_third_party_occurrence():
    application = make_request(
        body=json.dumps({"typedKeyword": "running shoes"}),
        domain="shop.example.test",
        traffic_type="Application",
    )
    third_party = make_request(
        url="https://graph.example.test/events",
        domain="graph.example.test",
        body=json.dumps({
            "custom_events": [{"fb_search_string": "running shoes"}]
        }),
        traffic_type="Third Party",
    )

    analyze([application, third_party])

    app_finding = findings_of(application, "Search Query")[0]
    third_finding = findings_of(third_party, "Search Query")[0]
    assert app_finding.get("cross_domain_match") is not True
    assert third_finding["cross_domain_match"] is True
    assert third_finding["correlated_application_domains"] == [
        "shop.example.test"
    ]


def test_different_search_values_do_not_create_cross_domain_match():
    application = make_request(
        body=json.dumps({"typedKeyword": "running shoes"}),
        traffic_type="Application",
    )
    third_party = make_request(
        body=json.dumps({"fb_search_string": "winter jackets"}),
        domain="tracker.example.test",
        traffic_type="Third Party",
    )

    analyze([application, third_party])

    assert not any(
        finding.get("cross_domain_match")
        for request in (application, third_party)
        for finding in request.sensitive_data
    )


def test_inventory_and_risk_results_preserve_behavioral_provenance():
    installed = make_request(body=json.dumps({
        "installedApps": ["com.payment.one", "com.payment.two"]
    }))
    application_search = make_request(
        url="https://shop.example.test/search?q=running%20shoes",
        domain="shop.example.test",
        body=None,
        query_pairs=[("q", "running shoes")],
        traffic_type="Application",
    )
    third_party_search = make_request(
        domain="tracker.example.test",
        body=json.dumps({"fb_search_string": "running shoes"}),
        traffic_type="Third Party",
    )
    requests = analyze([installed, application_search, third_party_search])
    inventory = PrivacyInventoryGenerator(requests).generate()

    third_evidence = next(
        item
        for item in inventory["Third Party"]["evidence"]
        if item["type"] == "Search Query"
    )
    assert third_evidence["cross_domain_match"] is True
    assert third_evidence["domain"] == "tracker.example.test"
    assert "value_redacted" not in third_evidence

    risks = PolicyComparator(inventory, complete_policy()).get_practice_risks()
    assert {risk["type"] for risk in risks} == {
        "INSTALLED_APP_LIST_TRANSMITTED",
        "SEARCH_ACTIVITY_IN_URL",
        "SEARCH_ACTIVITY_SHARED_WITH_THIRD_PARTY",
    }


def test_third_party_personal_location_and_identifier_flows_are_separate_risks():
    evidence = [
        {
            "artifact_type": "Latitude",
            "observed_category": "Location",
            "source": "Request Body",
            "direction": "outbound",
            "traffic_type": "Third Party",
            "domain": "analytics.example.test",
        },
        {
            "artifact_type": "Email",
            "observed_category": "Personal Information",
            "source": "Request Body",
            "direction": "outbound",
            "traffic_type": "Third Party",
            "domain": "analytics.example.test",
        },
        {
            "artifact_type": "Device ID",
            "observed_category": "Device Identifier",
            "source": "Header",
            "direction": "outbound",
            "traffic_type": "Third Party",
            "domain": "analytics.example.test",
        },
        {
            "artifact_type": "Phone",
            "observed_category": "Personal Information",
            "source": "Request Body",
            "direction": "inbound",
            "traffic_type": "Third Party",
            "domain": "analytics.example.test",
        },
    ]

    risks = assess_practice_risks(evidence)

    assert {risk["type"] for risk in risks} == {
        "PRECISE_LOCATION_SHARED_WITH_THIRD_PARTY",
        "PERSONAL_DATA_SHARED_WITH_THIRD_PARTY",
        "PERSISTENT_IDENTIFIER_SHARED_WITH_THIRD_PARTY",
    }
    assert all(risk["status"] == "REVIEW REQUIRED" for risk in risks)
    assert all("value_redacted" not in item for risk in risks for item in risk["evidence"])


def test_explicit_search_policy_evidence_matches_search_query():
    request = make_request(body=json.dumps({"search_term": "privacy tools"}))
    inventory = PrivacyInventoryGenerator(analyze([request])).generate()
    policy = complete_policy([{
        "practice_id": "search",
        "privacy_category": "Search",
        "artifact_types": ["Search Query"],
        "action": "collect",
        "recipient_scope": "unknown",
        "provenance": {"evidence": "We collect search queries."},
    }])

    result = compare_information_types(inventory, policy)

    observed = next(
        item for item in result["information_type_results"]
        if item["artifact_type"] == "Search Query" and item["occurrences"]
    )
    assert observed["status"] == DISCLOSED


def test_missing_installed_app_declaration_is_reported_for_reviewed_policy():
    request = make_request(body=json.dumps({
        "installedApps": ["com.payment.one", "com.payment.two"]
    }))
    inventory = PrivacyInventoryGenerator(analyze([request])).generate()

    result = compare_information_types(inventory, complete_policy())

    observed = next(
        item for item in result["information_type_results"]
        if item["artifact_type"] == "Installed Application List"
    )
    assert observed["status"] == NOT_DISCLOSED


def test_policy_prose_aliases_require_explicit_search_or_installed_app_language():
    assert extract_explicit_policy_artifacts(
        "We collect search queries and search-related interactions.", "Search"
    ) == ["Search Query"]
    assert extract_explicit_policy_artifacts(
        "We collect applications installed on your device.",
        "Device Information",
    ) == ["Installed Application List"]
    assert extract_explicit_policy_artifacts(
        "We collect usage data and device information.", "Usage Data"
    ) == []
