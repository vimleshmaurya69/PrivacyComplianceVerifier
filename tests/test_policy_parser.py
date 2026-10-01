import json
from pathlib import Path

from src.policy.policy_parser import PrivacyPolicyParser


def parse_policy(tmp_path, payload):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(payload), encoding="utf-8")
    return PrivacyPolicyParser(policy_path).parse()


def test_parser_preserves_legacy_evidence_without_inventing_specificity(tmp_path):
    parsed = parse_policy(tmp_path, {
        "app": "Synthetic App",
        "source": "https://example.test/privacy",
        "privacy_summary_source": "https://example.test/summary",
        "last_verified": "2026-09-28",
        "policy_available": True,
        "declared_categories": ["Location"],
        "declared_practices": [{
            "category": "Location",
            "data_type": "Location information",
            "purpose": "Maps",
        }],
    })

    assert parsed["application"] == "Synthetic App"
    assert parsed["declared_categories"] == ["Location"]
    assert parsed["declared_practices"][0]["purpose"] == "Maps"
    assert parsed["last_verified"] == "2026-09-28"
    assert parsed["policy_available"] is True
    assert [source["url"] for source in parsed["sources"]] == [
        "https://example.test/privacy",
        "https://example.test/summary",
    ]

    practice = parsed["policy_practices"][0]
    assert practice["privacy_category"] == "Location"
    assert practice["artifact_types"] == []
    assert practice["action"] == "unknown"
    assert practice["recipient_scope"] == "unknown"
    assert practice["verification"]["state"] == "UNVERIFIED"
    assert practice["legacy_evidence"]["data_type"] == "Location information"


def test_policy_sources_is_normalized_and_deduplicated(tmp_path):
    parsed = parse_policy(tmp_path, {
        "app_name": "Synthetic App",
        "policy_sources": [
            "https://example.test/privacy",
            "https://example.test/privacy",
        ],
        "website_source": "https://example.test/about",
    })

    assert [source["url"] for source in parsed["sources"]] == [
        "https://example.test/privacy",
        "https://example.test/about",
    ]


def test_invalid_verified_complete_coverage_is_downgraded(tmp_path):
    parsed = parse_policy(tmp_path, {
        "application": "Synthetic App",
        "comparison_coverage": [{
            "privacy_category": "Personal Information",
            "action": "transmit",
            "recipient_scope": "first_party",
            "state": "VERIFIED_COMPLETE",
        }],
    })

    coverage = parsed["comparison_coverage"][0]
    assert coverage["state"] == "UNKNOWN"
    assert coverage["requested_state"] == "VERIFIED_COMPLETE"
    assert "INVALID_VERIFIED_COMPLETE_DOWNGRADED" in coverage["issues"]


def test_policy_perspective_actions_are_preserved(tmp_path):
    parsed = parse_policy(tmp_path, {
        "application": "Synthetic App",
        "sources": [{
            "source_id": "source-1",
            "url": "https://example.test/privacy",
        }],
        "last_verified": "2026-09-28",
        "policy_practices": [
            {
                "practice_id": "collect-phone",
                "privacy_category": "Personal Information",
                "artifact_types": ["Phone"],
                "action": "collect",
                "recipient_scope": "unknown",
                "provenance": {"source_ids": ["source-1"]},
                "verification": {"state": "VERIFIED"},
            },
            {
                "practice_id": "share-phone",
                "privacy_category": "Personal Information",
                "artifact_types": ["Phone"],
                "action": "share",
                "recipient_scope": "third_party",
                "provenance": {"source_ids": ["source-1"]},
                "verification": {"state": "VERIFIED"},
            },
        ],
    })

    assert [item["action"] for item in parsed["policy_practices"]] == [
        "collect", "share"
    ]


def test_existing_repository_policy_formats_remain_loadable():
    config_paths = sorted(Path("data/apps").glob("*/app_config.json"))
    assert config_paths
    for config_path in config_paths:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        policy_path = config_path.parent / config["policy_file"]
        parsed = PrivacyPolicyParser(policy_path).parse()
        assert parsed["schema_version"] == 2
        assert isinstance(parsed["declared_categories"], list)
        assert isinstance(parsed["policy_practices"], list)
        assert isinstance(parsed["sources"], list)
