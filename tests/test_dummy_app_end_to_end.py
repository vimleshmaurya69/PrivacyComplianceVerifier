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


FIXTURE_ROOT = Path("data/apps/DummyTestApp")


def test_dummy_app_exercises_practice_level_decisions_end_to_end():
    config = json.loads(
        (FIXTURE_ROOT / "app_config.json").read_text(encoding="utf-8")
    )
    har = HarLoader(FIXTURE_ROOT / config["har_file"]).load()
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
    policy = PrivacyPolicyParser(FIXTURE_ROOT / config["policy_file"]).parse()

    comparator = PolicyComparator(inventory, policy, config["app_name"])
    results = comparator.compare()
    summary = comparator.generate_summary(
        results, comparator.compare_categories()
    )

    assert len(requests) == 1
    assert requests[0].traffic_type == "Application"
    assert {item["type"] for item in requests[0].sensitive_data} == {
        "Phone",
        "Email",
        "Device ID",
        "Latitude",
    }

    observed = {
        item["artifact_type"]: item
        for item in results
        if item["result_type"] == "observed_practice"
    }
    assert observed["Phone"]["status"] == "PRACTICE DISCLOSED"
    assert observed["Phone"]["risk_flags"] == ["PERSONAL_DATA_IN_URL"]
    assert observed["Email"]["status"] == "INFORMATION DISCLOSED"
    assert observed["Device ID"]["status"] == "POTENTIAL NON-DISCLOSURE"
    assert observed["Latitude"]["status"] == "INSUFFICIENT POLICY DETAIL"

    declared = {
        tuple(item.get("artifact_types", [])): item
        for item in results
        if item["result_type"] == "declared_practice"
    }
    assert declared[("Authorization Token",)]["status"] == (
        "NOT OBSERVED IN CAPTURE"
    )
    assert declared[("Camera",)]["status"] == "NOT ASSESSABLE FROM HAR"

    assert summary["practice_disclosed"] == 1
    assert summary["information_disclosed"] == 1
    assert summary["potential_non_disclosures"] == 1
    assert summary["insufficient_policy_detail"] == 1
    assert summary["not_observed_in_capture"] == 1
    assert summary["not_assessable_from_har"] == 1
    assert summary["compliance_determination"] == "NOT DETERMINED"
