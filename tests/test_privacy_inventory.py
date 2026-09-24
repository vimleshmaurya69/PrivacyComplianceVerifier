import unittest

from src.analyzer.privacy_inventory import PrivacyInventoryGenerator
from src.models.request import Request


def request(domain, traffic_type, findings):
    return Request(
        method="POST",
        url=f"https://{domain}/submit",
        domain=domain,
        status=200,
        mime_type="application/json",
        traffic_type=traffic_type,
        sensitive_data=findings,
    )


class PrivacyInventoryTests(unittest.TestCase):

    def test_preserves_summary_fields_and_individual_normalized_evidence(self):
        email_finding = {
            "type": "Email",
            "privacy_category": "Personal Information",
            "source": "Request Body",
            "direction": "outbound",
            "key": "profile.email",
            "domain": "api.example.test",
            "traffic_type": "Application",
            "value_redacted": "sy...st",
        }
        token_finding = {
            "type": "CSRF Token",
            "privacy_category": "Security",
            "source": "Response Cookie",
            "direction": "inbound",
            "key": "XSRF-TOKEN",
            "domain": "api.example.test",
            "traffic_type": "Application",
            "value_redacted": "ab...yz",
        }
        inventory = PrivacyInventoryGenerator([
            request("api.example.test", "Application", [email_finding, token_finding]),
            request("cdn.example.test", "Application", []),
        ]).generate()

        section = inventory["Application"]
        self.assertEqual(2, section["request_count"])
        self.assertEqual(["api.example.test", "cdn.example.test"], section["domains"])
        self.assertEqual(["Personal Information", "Security"], section["privacy_categories"])
        self.assertEqual([
            {
                "type": "Email",
                "privacy_category": "Personal Information",
                "source": "Request Body",
                "direction": "outbound",
                "key": "profile.email",
                "domain": "api.example.test",
            },
            {
                "type": "CSRF Token",
                "privacy_category": "Security",
                "source": "Response Cookie",
                "direction": "inbound",
                "key": "XSRF-TOKEN",
                "domain": "api.example.test",
            },
        ], section["evidence"])
        self.assertTrue(all("value_redacted" not in item for item in section["evidence"]))

    def test_preserves_duplicate_finding_occurrences(self):
        finding = {
            "type": "Phone",
            "privacy_category": "Personal Information",
            "source": "Request Body",
            "direction": "outbound",
            "key": "phone",
            "domain": "api.example.test",
        }
        inventory = PrivacyInventoryGenerator([
            request("api.example.test", "Application", [finding, finding.copy()]),
        ]).generate()

        self.assertEqual(2, len(inventory["Application"]["evidence"]))
        self.assertEqual(
            inventory["Application"]["evidence"][0],
            inventory["Application"]["evidence"][1],
        )


if __name__ == "__main__":
    unittest.main()
