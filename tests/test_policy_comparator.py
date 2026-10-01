import unittest
from contextlib import redirect_stdout
from io import StringIO

from src.comparator.policy_comparator import PolicyComparator


SOURCE = {"url": "https://example.test/privacy"}
REVIEWED_AT = "2026-09-28"


def evidence(
    category,
    artifact_type="Email",
    source="Request Body",
    direction="outbound",
    domain="api.example.test",
    policy_scope=None,
):
    item = {
        "type": artifact_type,
        "privacy_category": category,
        "source": source,
        "direction": direction,
        "key": "profile.value",
        "domain": domain,
    }
    if policy_scope:
        item["policy_recipient_scope"] = policy_scope
        item["recipient_scope_justification"] = {
            "verified": True,
            "basis": "synthetic regression evidence",
        }
    return item


def inventory(items=None, traffic_type="Application", categories=None):
    return {
        traffic_type: {
            "privacy_categories": categories or sorted({
                item["privacy_category"] for item in (items or [])
            }),
            "evidence": items or [],
        }
    }


def policy(practices=None, coverage=None, categories=None, sources=None):
    return {
        "application": "Synthetic App",
        "sources": sources if sources is not None else [SOURCE],
        "last_verified": REVIEWED_AT,
        "declared_categories": categories or [],
        "policy_practices": practices or [],
        "comparison_coverage": coverage or [],
    }


def practice(
    category="Personal Information",
    artifacts=None,
    action="transmit",
    recipient_scope="first_party",
    domains=None,
    practice_id="declared-1",
):
    return {
        "practice_id": practice_id,
        "privacy_category": category,
        "artifact_types": artifacts or ["Phone"],
        "action": action,
        "recipient_scope": recipient_scope,
        "recipient_domains": domains or [],
        "provenance": {
            "source_ids": ["source-1"],
            "locator": "Synthetic policy section",
            "evidence": "Synthetic source-backed policy statement.",
            "reviewed_at": REVIEWED_AT,
        },
        "verification": {
            "state": "VERIFIED",
            "reviewed_at": REVIEWED_AT,
        },
        "coverage": "VERIFIED",
    }


def complete_coverage(
    category="Personal Information",
    action="transmit",
    recipient_scope="first_party",
    artifacts=None,
    domains=None,
):
    return {
        "privacy_category": category,
        "artifact_types": artifacts or [],
        "action": action,
        "recipient_scope": recipient_scope,
        "recipient_domains": domains or [],
        "state": "VERIFIED_COMPLETE",
        "provenance": {
            "source_ids": ["source-1"],
            "locator": "Synthetic complete-coverage section",
            "evidence": "Synthetic evidence supporting complete coverage.",
            "reviewed_at": REVIEWED_AT,
        },
    }


def observed_results(instance):
    return [
        result for result in instance.compare()
        if result["result_type"] == "observed_practice"
    ]


class PolicyPracticeComparisonTests(unittest.TestCase):

    def test_exact_practice_match_is_disclosed(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy([practice()]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("PRACTICE DISCLOSED", result["status"])
        self.assertEqual("Phone", result["artifact_type"])
        self.assertEqual("first_party", result["policy_recipient_scope"])
        self.assertEqual("declared-1", result["matching_policy_practices"][0]["practice_id"])

    def test_category_only_statement_is_insufficient_detail(self):
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy(categories=["Personal Information"]),
        )
        self.assertEqual(
            "INSUFFICIENT POLICY DETAIL",
            observed_results(instance)[0]["status"],
        )

    def test_missing_practice_with_verified_complete_coverage(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy(coverage=[complete_coverage()]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("POTENTIAL NON-DISCLOSURE", result["status"])
        self.assertEqual(
            "VERIFIED_COMPLETE", result["applicable_coverage"][0]["state"]
        )

    def test_missing_practice_with_partial_coverage_is_insufficient(self):
        coverage = complete_coverage()
        coverage["state"] = "PARTIAL"
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy(coverage=[coverage]),
        )
        self.assertEqual(
            "INSUFFICIENT POLICY DETAIL",
            observed_results(instance)[0]["status"],
        )

    def test_verified_complete_recipient_scope_gap_takes_precedence(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="third_party"
            )]),
            policy(
                [practice(recipient_scope="first_party")],
                [complete_coverage(recipient_scope="third_party")],
            ),
        )
        result = observed_results(instance)[0]
        self.assertEqual("POTENTIAL NON-DISCLOSURE", result["status"])
        self.assertIn(
            "RECIPIENT_SCOPE_OR_DOMAIN_DIFFERS",
            result["candidate_failures"][0]["reasons"],
        )

    def test_artifact_type_difference_is_not_collapsed(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Email", policy_scope="first_party"
            )]),
            policy(
                [practice(artifacts=["Phone"])],
                [complete_coverage(artifacts=["Email"])],
            ),
        )
        result = observed_results(instance)[0]
        self.assertEqual("POTENTIAL NON-DISCLOSURE", result["status"])
        self.assertIn(
            "ARTIFACT_TYPE_DIFFERS",
            result["candidate_failures"][0]["reasons"],
        )

    def test_verified_complete_action_gap_takes_precedence(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy(
                [practice(action="receive")],
                [complete_coverage(action="transmit")],
            ),
        )
        result = observed_results(instance)[0]
        self.assertEqual("POTENTIAL NON-DISCLOSURE", result["status"])
        self.assertIn(
            "ACTION_DIFFERS", result["candidate_failures"][0]["reasons"]
        )

    def test_collect_and_matching_transmit_discloses_information_type_only(self):
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy([practice(
                action="collect", recipient_scope="unknown"
            )]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("INFORMATION DISCLOSED", result["status"])
        self.assertEqual([], result["matching_policy_practices"])
        self.assertEqual(
            "declared-1",
            result["information_type_policy_practices"][0]["practice_id"],
        )

    def test_collect_different_artifact_remains_insufficient(self):
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Email")]),
            policy([practice(
                artifacts=["Phone"],
                action="collect",
                recipient_scope="unknown",
            )]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("INSUFFICIENT POLICY DETAIL", result["status"])
        self.assertEqual([], result["information_type_policy_practices"])

    def test_collect_location_matches_observed_latitude(self):
        instance = PolicyComparator(
            inventory([evidence("Location", "Latitude")]),
            policy([practice(
                category="Location",
                artifacts=["Location"],
                action="collect",
                recipient_scope="unknown",
            )]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("INFORMATION DISCLOSED", result["status"])
        self.assertEqual(
            "Location",
            result["decision_trace"]["matched_policy_artifact_type"],
        )

    def test_third_party_ownership_does_not_establish_policy_recipient_scope(self):
        instance = PolicyComparator(
            inventory(
                [evidence("Device Identifier", "Advertising ID")],
                traffic_type="Third Party",
            ),
            policy([practice(
                category="Device Identifier",
                artifacts=["Device Identifier"],
                action="share",
                recipient_scope="third_party",
            )]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("INFORMATION DISCLOSED", result["status"])
        self.assertEqual(
            "POLICY_INFORMATION_TYPE_MATCH",
            result["reason_code"],
        )

    def test_complete_category_coverage_can_support_non_disclosure(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Contacts", "Contact List", policy_scope="first_party"
            )]),
            policy(
                coverage=[complete_coverage(category="*")],
                categories=["Personal Information", "Location"],
            ),
        )
        result = observed_results(instance)[0]
        self.assertEqual("POTENTIAL NON-DISCLOSURE", result["status"])
        self.assertEqual(
            "OBSERVED_INFORMATION_NOT_DISCLOSED_WITHIN_VERIFIED_COVERAGE",
            result["decision_trace"]["reason_code"],
        )

    def test_unknown_coverage_contacts_remains_insufficient(self):
        coverage = complete_coverage(category="*")
        coverage["state"] = "UNKNOWN"
        instance = PolicyComparator(
            inventory([evidence("Contacts", "Contact List")]),
            policy(
                coverage=[coverage],
                categories=["Personal Information", "Location"],
            ),
        )
        self.assertEqual(
            "INSUFFICIENT POLICY DETAIL",
            observed_results(instance)[0]["status"],
        )

    def test_legacy_artifact_mentions_require_canonical_verification(self):
        legacy_policy = {
            "application": "Synthetic App",
            "source": "https://example.test/privacy",
            "last_verified": REVIEWED_AT,
            "declared_categories": ["Personal Information"],
            "declared_practices": [{
                "category": "Personal Information",
                "data_type": "Name, email address and phone number",
                "source": "privacy_policy",
            }],
        }
        instance = PolicyComparator(
            inventory([
                evidence("Personal Information", "Name"),
                evidence("Personal Information", "Email"),
            ]),
            legacy_policy,
        )
        results = observed_results(instance)
        self.assertEqual(
            ["INSUFFICIENT POLICY DETAIL", "INSUFFICIENT POLICY DETAIL"],
            [item["status"] for item in results],
        )
        self.assertTrue(all(
            not item["information_type_policy_practices"]
            for item in results
        ))

    def test_mobile_application_phrase_does_not_disclose_phone(self):
        legacy_policy = {
            "application": "Synthetic App",
            "source": "https://example.test/privacy",
            "last_verified": REVIEWED_AT,
            "declared_categories": ["Personal Information"],
            "declared_practices": [{
                "category": "Personal Information",
                "data_type": "Unique mobile application identifiers",
                "source": "privacy_policy",
            }],
        }
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            legacy_policy,
        )

        self.assertEqual(
            "INSUFFICIENT POLICY DETAIL",
            observed_results(instance)[0]["status"],
        )

    def test_legacy_mobile_phone_mention_is_not_action_disclosure(self):
        legacy_policy = {
            "application": "Synthetic App",
            "source": "https://example.test/privacy",
            "last_verified": REVIEWED_AT,
            "declared_categories": ["Personal Information"],
            "declared_practices": [{
                "category": "Personal Information",
                "data_type": "Mobile phone number",
                "source": "privacy_policy",
            }],
        }
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            legacy_policy,
        )

        self.assertEqual(
            "INSUFFICIENT POLICY DETAIL",
            observed_results(instance)[0]["status"],
        )

    def test_broad_authentication_does_not_disclose_authorization_token(self):
        legacy_policy = {
            "application": "Synthetic App",
            "source": "https://example.test/privacy",
            "last_verified": REVIEWED_AT,
            "declared_categories": ["Authentication"],
            "declared_practices": [{
                "category": "Authentication",
                "data_type": "Account authentication and OTP verification",
                "source": "privacy_policy",
            }],
        }
        instance = PolicyComparator(
            inventory([evidence("Authentication", "Authorization Token")]),
            legacy_policy,
        )
        self.assertEqual(
            "INSUFFICIENT POLICY DETAIL",
            observed_results(instance)[0]["status"],
        )

    def test_information_disclosure_has_machine_readable_decision_trace(self):
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy([practice(
                action="collect", recipient_scope="unknown"
            )]),
        )
        trace = observed_results(instance)[0]["decision_trace"]
        self.assertEqual("Personal Information", trace["observed_category"])
        self.assertEqual("Phone", trace["observed_artifact_type"])
        self.assertEqual("transmit", trace["observed_action"])
        self.assertEqual("application", trace["observed_recipient_scope"])
        self.assertEqual("declared-1", trace["matched_policy_practice_id"])
        self.assertEqual("collect", trace["matched_policy_action"])
        self.assertEqual("INFORMATION DISCLOSED", trace["decision"])
        self.assertEqual(
            "POLICY_COLLECTION_MATCHES_OBSERVED_TRANSMISSION",
            trace["reason_code"],
        )

    def test_verified_complete_coverage_wins_over_information_match(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy(
                [practice(action="collect", recipient_scope="unknown")],
                [complete_coverage()],
            ),
        )
        self.assertEqual(
            "POTENTIAL NON-DISCLOSURE",
            observed_results(instance)[0]["status"],
        )

    def test_collect_and_third_party_transmit_is_information_type_only(self):
        instance = PolicyComparator(
            inventory(
                [evidence("Personal Information", "Phone")],
                traffic_type="Third Party",
            ),
            policy([practice(
                action="collect", recipient_scope="unknown"
            )]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("INFORMATION DISCLOSED", result["status"])
        self.assertNotEqual("PRACTICE DISCLOSED", result["status"])
        self.assertEqual("third_party", result["traffic_recipient_scope"])
        self.assertEqual("unknown", result["policy_recipient_scope"])

    def test_share_and_explicit_third_party_scope_is_practice_disclosed(self):
        instance = PolicyComparator(
            inventory(
                [evidence(
                    "Personal Information",
                    "Phone",
                    policy_scope="third_party",
                )],
                traffic_type="Third Party",
            ),
            policy([practice(
                action="share", recipient_scope="third_party"
            )]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("PRACTICE DISCLOSED", result["status"])
        self.assertEqual("share", result["matching_policy_practices"][0]["action"])

    def test_broad_category_does_not_disclose_information_type(self):
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy(categories=["Personal Information"]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("INSUFFICIENT POLICY DETAIL", result["status"])
        self.assertEqual([], result["information_type_policy_practices"])

    def test_collect_information_type_keeps_url_risk_separate(self):
        item = evidence(
            "Personal Information", "Phone", source="Query Parameter"
        )
        instance = PolicyComparator(
            inventory([item]),
            policy([practice(
                action="collect", recipient_scope="unknown"
            )]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("INFORMATION DISCLOSED", result["status"])
        self.assertEqual(["PERSONAL_DATA_IN_URL"], result["risk_flags"])
        self.assertEqual(
            "PERSONAL_DATA_IN_URL", instance.get_practice_risks()[0]["type"]
        )

    def test_information_type_bridge_does_not_infer_purpose(self):
        declared = practice(action="collect", recipient_scope="unknown")
        declared["purpose"] = "Account verification"
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy([declared]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("INFORMATION DISCLOSED", result["status"])
        self.assertNotIn("purpose", instance.get_observed_practices()[0])
        self.assertNotIn("purpose", result)

    def test_share_domain_matching_keeps_existing_domain_rules(self):
        matching = {"domain": "api.example.test", "include_subdomains": False}
        other = {"domain": "other.example.test", "include_subdomains": False}

        matched = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy([practice(action="share", domains=[matching])]),
        )
        self.assertEqual(
            "PRACTICE DISCLOSED", observed_results(matched)[0]["status"]
        )

        unmatched = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy([practice(action="share", domains=[other])]),
        )
        self.assertEqual(
            "INFORMATION DISCLOSED",
            observed_results(unmatched)[0]["status"],
        )

    def test_information_disclosure_does_not_determine_compliance(self):
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy([practice(
                action="collect", recipient_scope="unknown"
            )]),
        )
        summary = instance.generate_summary(instance.compare())
        self.assertEqual(1, summary["information_type_disclosed"])
        self.assertEqual(
            "INFORMATION DISCLOSURE EVIDENCE FOUND",
            summary["overall_status"],
        )
        self.assertEqual("NOT DETERMINED", summary["compliance_determination"])

    def test_application_traffic_does_not_imply_policy_first_party_scope(self):
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy([practice(recipient_scope="first_party")]),
        )
        observed = instance.get_observed_practices()[0]
        result = observed_results(instance)[0]
        self.assertEqual("application", observed["traffic_recipient_scope"])
        self.assertEqual("unknown", observed["policy_recipient_scope"])
        self.assertEqual("INFORMATION DISCLOSED", result["status"])
        self.assertIn(
            "OBSERVED_POLICY_RECIPIENT_SCOPE_UNRESOLVED",
            result["candidate_failures"][0]["reasons"],
        )

    def test_third_party_traffic_does_not_imply_policy_third_party_scope(self):
        instance = PolicyComparator(
            inventory(
                [evidence("Personal Information", "Phone")],
                traffic_type="Third Party",
            ),
            policy([practice(
                action="share", recipient_scope="third_party"
            )]),
        )
        observed = instance.get_observed_practices()[0]
        self.assertEqual("third_party", observed["traffic_recipient_scope"])
        self.assertEqual("unknown", observed["policy_recipient_scope"])
        result = observed_results(instance)[0]
        self.assertEqual("INFORMATION DISCLOSED", result["status"])
        self.assertIn(
            "OBSERVED_POLICY_RECIPIENT_SCOPE_UNRESOLVED",
            result["candidate_failures"][0]["reasons"],
        )

    def test_explicit_scope_justification_still_supports_practice_match(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy([practice(recipient_scope="first_party")]),
        )
        self.assertEqual(
            "PRACTICE DISCLOSED", observed_results(instance)[0]["status"]
        )

    def test_retain_and_local_access_do_not_disclose_network_transmission(self):
        for action in ("retain", "local_access"):
            with self.subTest(action=action):
                instance = PolicyComparator(
                    inventory([evidence("Personal Information", "Phone")]),
                    policy([practice(
                        action=action,
                        recipient_scope="unknown",
                    )]),
                )
                result = observed_results(instance)[0]
                self.assertEqual("INSUFFICIENT POLICY DETAIL", result["status"])
                self.assertEqual([], result["information_type_policy_practices"])

    def test_policy_domain_matching_handles_ipv6_and_wildcards(self):
        cases = [
            ("[2001:db8::1]:8443", "[2001:db8::1]:443"),
            ("api.example.test", "*.example.test"),
        ]
        for observed_domain, policy_domain in cases:
            with self.subTest(observed_domain=observed_domain):
                instance = PolicyComparator(
                    inventory([evidence(
                        "Personal Information",
                        "Phone",
                        domain=observed_domain,
                    )]),
                    policy([practice(domains=[policy_domain])]),
                )
                self.assertEqual(
                    "PRACTICE DISCLOSED",
                    observed_results(instance)[0]["status"],
                )

    def test_frida_only_category_is_reported_as_runtime_evidence(self):
        instance = PolicyComparator(
            {},
            policy(),
            frida_evidence={"observations": [{
                "status": "observed",
                "privacy_category": "Personal Information",
                "data_type": "Phone",
            }]},
        )
        results = instance.compare_categories()
        self.assertEqual(1, len(results))
        self.assertEqual("RUNTIME EVIDENCE ONLY", results[0]["status"])
        self.assertTrue(results[0]["observed_frida"])
        self.assertFalse(results[0]["observed_har"])

    def test_explicit_policy_domain_can_justify_recipient_match(self):
        domain = {"domain": "api.example.test", "include_subdomains": False}
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy([practice(domains=[domain])]),
        )
        self.assertEqual(
            "PRACTICE DISCLOSED", observed_results(instance)[0]["status"]
        )

    def test_domain_is_not_compared_when_policy_does_not_declare_it(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy([practice(domains=[])]),
        )
        self.assertEqual(
            "PRACTICE DISCLOSED", observed_results(instance)[0]["status"]
        )

    def test_verified_complete_domain_gap_takes_precedence(self):
        declared_domain = {"domain": "declared.example", "include_subdomains": False}
        observed_domain = {"domain": "api.example.test", "include_subdomains": False}
        instance = PolicyComparator(
            inventory([evidence("Personal Information", "Phone")]),
            policy(
                [practice(domains=[declared_domain])],
                [complete_coverage(domains=[observed_domain])],
            ),
        )
        self.assertEqual(
            "POTENTIAL NON-DISCLOSURE",
            observed_results(instance)[0]["status"],
        )

    def test_url_risk_remains_separate_from_disclosure(self):
        item = evidence(
            "Personal Information",
            "Phone",
            source="Query Parameter",
            policy_scope="first_party",
        )
        instance = PolicyComparator(inventory([item]), policy([practice()]))
        result = observed_results(instance)[0]
        self.assertEqual("PRACTICE DISCLOSED", result["status"])
        self.assertEqual(["PERSONAL_DATA_IN_URL"], result["risk_flags"])
        self.assertEqual(
            "PERSONAL_DATA_IN_URL", instance.get_practice_risks()[0]["type"]
        )

    def test_runtime_evidence_does_not_create_network_result(self):
        instance = PolicyComparator(
            {},
            policy(),
            frida_evidence={"observations": [{
                "status": "observed",
                "privacy_category": "Personal Information",
                "data_type": "Local Media Files",
            }]},
        )
        self.assertEqual([], instance.compare())
        summary = instance.generate_summary([])
        self.assertEqual("INSUFFICIENT EVIDENCE", summary["overall_status"])
        self.assertIn("RUNTIME_ACCESS_OBSERVED", summary["assessment_flags"])

    def test_not_comparable_categories_are_excluded(self):
        items = [
            evidence("Security", "CSRF Token"),
            evidence("API Credentials", "API Key"),
            evidence("Unknown", "Unknown"),
        ]
        instance = PolicyComparator(inventory(items), policy())
        self.assertEqual([], instance.compare())
        self.assertEqual(3, len(instance.get_excluded_observed_evidence()))

    def test_android_and_unknown_traffic_are_excluded(self):
        item = evidence("Personal Information", "Email")
        observed_inventory = {
            "Android System": {
                "privacy_categories": ["Personal Information"],
                "evidence": [item],
            },
            "Unknown": {
                "privacy_categories": ["Personal Information"],
                "evidence": [item],
            },
        }
        instance = PolicyComparator(observed_inventory, policy())
        self.assertEqual([], instance.compare())
        self.assertEqual(2, len(instance.get_non_attributable_evidence()))

    def test_inbound_evidence_remains_separate(self):
        item = evidence(
            "Personal Information", "Email", direction="inbound"
        )
        instance = PolicyComparator(inventory([item]), policy())
        self.assertEqual([], instance.compare())
        self.assertEqual("inbound", instance.get_inbound_evidence()[0]["direction"])

    def test_missing_direction_does_not_imply_outbound_transmission(self):
        item = evidence("Personal Information", "Email")
        item["direction"] = None
        instance = PolicyComparator(inventory([item]), policy())

        self.assertEqual([], instance.get_observed_practices())
        self.assertEqual([], instance.compare())

    def test_repeated_occurrences_are_grouped_but_preserved(self):
        item = evidence(
            "Personal Information", "Phone", policy_scope="first_party"
        )
        instance = PolicyComparator(
            inventory([item, dict(item)]), policy([practice()])
        )
        practices = instance.get_observed_practices()
        self.assertEqual(1, len(practices))
        self.assertEqual(2, practices[0]["occurrence_count"])
        self.assertEqual(2, len(practices[0]["evidence"]))

    def test_verified_declared_domain_practice_not_seen_in_capture(self):
        domain = {"domain": "api.example.test", "include_subdomains": False}
        instance = PolicyComparator({}, policy([practice(domains=[domain])]))
        result = instance.compare()[0]
        self.assertEqual("NOT OBSERVED IN CAPTURE", result["status"])

    def test_declared_practice_without_observation_is_not_observed(self):
        instance = PolicyComparator({}, policy([practice(domains=[])]))
        result = instance.compare()[0]
        self.assertEqual("NOT OBSERVED IN CAPTURE", result["status"])

    def test_semantic_category_relationships_remain_exact(self):
        item = evidence(
            "Device Identifier", "Device ID", policy_scope="first_party"
        )
        instance = PolicyComparator(
            inventory([item]),
            policy([practice(
                category="Device Information", artifacts=["Device ID"]
            )]),
        )
        result = observed_results(instance)[0]
        self.assertEqual("INSUFFICIENT POLICY DETAIL", result["status"])
        self.assertEqual([], result["matching_policy_practices"])

    def test_legacy_inventory_without_evidence_cannot_create_practice_claim(self):
        instance = PolicyComparator(
            inventory([], categories=["Network Information"]), policy()
        )
        self.assertEqual([], instance.compare())
        category_result = instance.compare_categories()[0]
        self.assertEqual("CATEGORY NOT DECLARED", category_result["status"])

    def test_summary_keeps_legal_compliance_not_determined(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy([practice()]),
        )
        summary = instance.generate_summary(instance.compare())
        self.assertEqual("NOT DETERMINED", summary["compliance_determination"])
        self.assertEqual(1, summary["practice_disclosed"])
        self.assertEqual(
            "DISCLOSURE EVIDENCE FOUND",
            summary["overall_status"],
        )

    def test_print_report_does_not_claim_legal_compliance(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy([practice()]),
        )
        output = StringIO()

        with redirect_stdout(output):
            instance.print_report()

        self.assertIn(
            "Compliance Determination: NOT DETERMINED", output.getvalue()
        )
        self.assertNotIn(
            "Compliance Determination: COMPLIANT", output.getvalue()
        )

    def test_potential_non_disclosure_controls_overall_status(self):
        instance = PolicyComparator(
            inventory([evidence(
                "Personal Information", "Phone", policy_scope="first_party"
            )]),
            policy(coverage=[complete_coverage()]),
        )
        summary = instance.generate_summary(instance.compare())
        self.assertEqual(
            "POTENTIAL NON-DISCLOSURE IDENTIFIED",
            summary["overall_status"],
        )
        self.assertEqual(
            "NOT DETERMINED",
            summary["compliance_determination"],
        )
        self.assertEqual(1, summary["potential_non_disclosures"])

    def test_policy_quality_reports_specificity_and_coverage_gaps(self):
        instance = PolicyComparator(
            {},
            {
                "declared_categories": ["Location"],
                "policy_sources": ["https://example.test/privacy"],
            },
        )
        quality = instance.get_policy_quality()
        self.assertEqual(1, quality["source_count"])
        self.assertIn("POLICY_CATEGORY_LIST_ONLY", quality["issues"])
        self.assertIn("POLICY_PRACTICE_DETAIL_INCOMPLETE", quality["issues"])
        self.assertIn("POLICY_COVERAGE_UNKNOWN", quality["issues"])


if __name__ == "__main__":
    unittest.main()
