import json
from pathlib import Path

from src.analyzer.privacy_inventory import PrivacyInventoryGenerator
from src.analyzer.privacy_normalizer import PrivacyNormalizer
from src.analyzer.sensitive_data_detector import SensitiveDataDetector
from src.comparator.policy_comparator import PolicyComparator
from src.filter.traffic_filter import TrafficFilter
from src.parser.har_loader import HarLoader
from src.parser.request_extractor import RequestExtractor
from src.policy.policy_parser import PrivacyPolicyParser
from src.report.simple_result_presenter import build_simple_report


APP_ROOT = Path("data/apps")
SYNTHETIC_CASES = (
    "synthetic_disclosed",
    "synthetic_nondisclosure",
    "synthetic_partial_policy",
    "synthetic_url_risk",
    "synthetic_technical",
    "synthetic_limited_capture",
)


def _run_case(case_id):
    root = APP_ROOT / case_id
    config = json.loads((root / "app_config.json").read_text(encoding="utf-8"))
    har = HarLoader(root / config["har_file"]).load()
    requests = RequestExtractor(har).extract_requests()
    requests = TrafficFilter(
        requests,
        config["app_name"],
        config["application_services"],
        config["third_party_services"],
    ).classify_requests()
    requests = SensitiveDataDetector(requests).analyze()
    requests = PrivacyNormalizer(requests).normalize()
    inventory = PrivacyInventoryGenerator(requests).generate()
    policy = PrivacyPolicyParser(root / config["policy_file"]).parse()
    comparator = PolicyComparator(inventory, policy, config["app_name"])
    results = comparator.compare()
    category_results = comparator.compare_categories()
    compliance_report = {
        "results": results,
        "category_results": category_results,
        "policy_practices": comparator.get_policy_practices(),
        "declared_categories": sorted(comparator.get_declared_categories()),
        "practice_risks": comparator.get_practice_risks(),
    }
    return config, requests, build_simple_report(
        inventory, compliance_report, policy
    )


def _observed_results(report):
    return {
        item["artifact_type"]: item
        for item in report["information_type_results"]
        if item["occurrences"] > 0
    }


def test_synthetic_cases_are_excluded_from_empirical_aggregate():
    for case_id in SYNTHETIC_CASES:
        config = json.loads(
            (APP_ROOT / case_id / "app_config.json").read_text(encoding="utf-8")
        )
        assert config["exclude_from_aggregate"] is True
        assert config["dataset_role"] == "controlled_validation"


def test_fully_disclosed_case_reproduces_disclosed_result():
    _, requests, report = _run_case("synthetic_disclosed")

    assert len(requests) == 1
    observed = _observed_results(report)
    assert observed["Email"]["status"] == "DISCLOSED"
    assert observed["Latitude"]["status"] == "DISCLOSED"
    assert report["capture_scoped_result"] == "COMPLIANT_WITHIN_CAPTURE_SCOPE"


def test_clear_nondisclosure_case_reproduces_policy_gap():
    _, _, report = _run_case("synthetic_nondisclosure")

    observed = _observed_results(report)
    assert observed["Phone"]["status"] == "NOT_DISCLOSED_IN_REVIEWED_POLICY"
    assert report["capture_scoped_result"] == "POTENTIALLY_NON_COMPLIANT"


def test_partial_policy_case_does_not_manufacture_nondisclosure():
    _, _, report = _run_case("synthetic_partial_policy")

    observed = _observed_results(report)
    assert observed["User ID"]["status"] == "POLICY_REVIEW_INCOMPLETE"
    assert report["capture_scoped_result"] == "CANNOT_DETERMINE"


def test_disclosed_url_case_keeps_risk_separate_from_policy_result():
    _, _, report = _run_case("synthetic_url_risk")

    observed = _observed_results(report)
    assert observed["Phone"]["status"] == "DISCLOSED"
    assert report["capture_scoped_result"] == "COMPLIANT_WITHIN_CAPTURE_SCOPE"
    assert [risk["type"] for risk in report["risk_signals"]] == [
        "PERSONAL_DATA_IN_URL"
    ]


def test_technical_case_preserves_authentication_evidence():
    _, requests, report = _run_case("synthetic_technical")

    assert {item["type"] for item in requests[0].sensitive_data} == {
        "Authorization Token"
    }
    observed = _observed_results(report)
    assert observed["Authorization Token"]["status"] == (
        "NOT_DISCLOSED_IN_REVIEWED_POLICY"
    )


def test_limited_capture_case_reports_declared_but_not_observed():
    _, requests, report = _run_case("synthetic_limited_capture")

    assert requests == []
    email = next(
        item
        for item in report["information_type_results"]
        if item["artifact_type"] == "Email"
    )
    assert email["status"] == "DECLARED_NOT_OBSERVED_IN_CAPTURE"
    assert report["capture_scoped_result"] == "CANNOT_DETERMINE"
