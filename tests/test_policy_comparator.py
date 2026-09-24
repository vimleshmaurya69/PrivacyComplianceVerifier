import unittest

from src.comparator.policy_comparator import PolicyComparator


def comparator(observed_categories, declared_categories, evidence=None):
    return PolicyComparator(
        {"Application": {
            "privacy_categories": observed_categories,
            "evidence": evidence or [],
        }},
        {"declared_categories": declared_categories},
    )


def result_by_category(comparator_instance):
    return {
        item["category"]: item
        for item in comparator_instance.compare()
    }


class PolicyComparatorSemanticMappingTests(unittest.TestCase):

    @staticmethod
    def evidence(category, artifact_type="Email"):
        return {
            "type": artifact_type,
            "privacy_category": category,
            "source": "Request Body",
            "direction": "outbound",
            "key": "profile.value",
            "domain": "api.example.test",
        }

    def test_security_remains_raw_evidence_but_is_not_a_mismatch(self):
        instance = comparator(["Security"], [], [self.evidence("Security", "CSRF Token")])
        self.assertEqual({"Security"}, instance.get_observed_categories())
        self.assertEqual([], instance.compare())
        self.assertEqual([{
            "observed_category": "Security", "artifact_type": "CSRF Token",
            "source": "Request Body", "direction": "outbound",
            "key": "profile.value", "domain": "api.example.test",
        }], instance.get_excluded_observed_evidence())

    def test_api_credentials_remain_raw_evidence_but_are_not_a_mismatch(self):
        instance = comparator(["API Credentials"], [], [
            self.evidence("API Credentials", "API Key")
        ])
        self.assertEqual({"API Credentials"}, instance.get_observed_categories())
        self.assertEqual([], instance.compare())
        self.assertEqual("API Credentials", instance.get_excluded_observed_evidence()[0]["observed_category"])

    def test_unknown_remains_raw_evidence_but_is_not_a_mismatch(self):
        instance = comparator(["Unknown"], [])
        self.assertEqual({"Unknown"}, instance.get_observed_categories())
        self.assertEqual([], instance.compare())

    def test_location_matches_location(self):
        results = result_by_category(comparator(
            ["Location"], ["Location"], [self.evidence("Location", "Latitude")]
        ))
        self.assertEqual("COMPLIANT", results["Location"]["status"])
        self.assertEqual([{
            "observed_category": "Location", "artifact_type": "Latitude",
            "source": "Request Body", "direction": "outbound",
            "key": "profile.value", "domain": "api.example.test",
        }], results["Location"]["observed_evidence"])

    def test_mismatch_includes_causing_evidence(self):
        results = result_by_category(comparator(
            ["Network Information"], [], [self.evidence("Network Information", "IP Address")]
        ))
        self.assertEqual("POTENTIAL MISMATCH", results["Network Information"]["status"])
        self.assertEqual("IP Address", results["Network Information"]["observed_evidence"][0]["artifact_type"])

    def test_declared_but_not_observed_has_no_observed_evidence(self):
        results = result_by_category(comparator([], ["Location"]))
        self.assertEqual("NOT OBSERVED", results["Location"]["status"])
        self.assertEqual([], results["Location"]["observed_evidence"])

    def test_authentication_matches_authentication(self):
        results = result_by_category(comparator(["Authentication"], ["Authentication"]))
        self.assertEqual("COMPLIANT", results["Authentication"]["status"])

    def test_device_identifier_matches_device_identifier(self):
        results = result_by_category(comparator(
            ["Device Identifier"], ["Device Identifier"]
        ))
        self.assertEqual("COMPLIANT", results["Device Identifier"]["status"])

    def test_device_identifier_does_not_match_device_information(self):
        results = result_by_category(comparator(
            ["Device Identifier"], ["Device Information"]
        ))
        self.assertEqual("POTENTIAL MISMATCH", results["Device Identifier"]["status"])
        self.assertEqual("NOT OBSERVED", results["Device Information"]["status"])

    def test_authentication_does_not_match_passwords(self):
        results = result_by_category(comparator(
            ["Authentication"], ["Passwords"]
        ))
        self.assertEqual("POTENTIAL MISMATCH", results["Authentication"]["status"])
        self.assertEqual("NOT OBSERVED", results["Passwords"]["status"])


if __name__ == "__main__":
    unittest.main()
