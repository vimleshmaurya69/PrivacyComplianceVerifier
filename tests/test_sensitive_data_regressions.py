"""Synthetic regression contracts for extraction, detection, and normalization.

Run: python -B -m unittest discover -s tests -v
No captured traffic, files, network, mocks, or production changes are required.
Missing functionality deliberately produces ordinary assertion failures.
Credentials are generated per test and have no association with any service.
"""

import base64
import gzip
import json
import secrets
import unittest
import zlib
from urllib.parse import urlencode

from src.analyzer.privacy_inventory import PrivacyInventoryGenerator
from src.analyzer.privacy_normalizer import PrivacyNormalizer
from src.analyzer.sensitive_data_detector import SensitiveDataDetector
from src.models.request import Request
from src.parser.request_extractor import RequestExtractor
from src.utils.protobuf_scanner import ProtobufScanner


EMAIL = "synthetic.person@example.test"
PHONE = "+1 (202) 555-0147"
DEVICE_ID = "00000000-0000-4000-8000-000000000123"


def credential():
    """Generate an inert test value rather than hardcoding credentials."""
    return secrets.token_urlsafe(24)


def request(**overrides):
    fields = dict(method="POST", url="https://example.test/submit",
                  domain="example.test", status=200, mime_type="application/json")
    fields.update(overrides)
    return Request(**fields)


def extracted(request_fields=None, response_fields=None):
    """Exercise the real extractor using a minimal, in-memory synthetic entry."""
    outgoing = {"method": "POST", "url": "https://example.test/submit"}
    incoming = {"status": 200}
    outgoing.update(request_fields or {})
    incoming.update(response_fields or {})
    return RequestExtractor({"log": {"entries": [
        {"request": outgoing, "response": incoming}
    ]}}).extract_requests()[0]


def multipart(fields, quoted_boundary=False):
    boundary = "synthetic-boundary-123"
    body = "".join(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n'
        f"\r\n{value}\r\n" for key, value in fields
    ) + f"--{boundary}--\r\n"
    parameter = f'"{boundary}"' if quoted_boundary else boundary
    return extracted({"postData": {
        "mimeType": f"multipart/form-data; boundary={parameter}", "text": body
    }})


def protobuf_string(field_number, value):
    data = value.encode("utf-8")
    if len(data) >= 128:
        raise ValueError("Test helper supports one-byte protobuf lengths only")
    return bytes([(field_number << 3) | 2, len(data)]) + data


def multipart_container(subtype, parts):
    boundary = "phase-3a-boundary"
    body = "".join(
        f"--{boundary}\r\nContent-Type: {content_type}\r\n\r\n{payload}\r\n"
        for content_type, payload in parts
    ) + f"--{boundary}--\r\n"
    return body, f"multipart/{subtype}; boundary={boundary}"


def multipart_form_part(disposition, payload, part_content_type=None):
    boundary = "filename-form-boundary"
    content_type_header = (
        f"Content-Type: {part_content_type}\r\n" if part_content_type else ""
    )
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: {disposition}\r\n"
        f"{content_type_header}\r\n"
        f"{payload}\r\n"
        f"--{boundary}--\r\n"
    )
    return request(
        body=body,
        body_type="multipart",
        content_type=f"multipart/form-data; boundary={boundary}",
    )


class SensitiveDataRegressions(unittest.TestCase):
    """Assert public findings, including the exact synthetic value's redaction."""

    def assert_artifact(self, sample, artifact, category, value, source,
                        direction="outbound", key=None):
        detector = SensitiveDataDetector([sample])
        detector.analyze()
        PrivacyNormalizer([sample]).normalize()
        # Explicit expectations, not values obtained from the production taxonomy.
        redacted = "****" if len(str(value)) <= 4 else str(value)[:2] + "..." + str(value)[-2:]
        matches = [finding for finding in sample.sensitive_data
                   if finding.get("type") == artifact
                   and finding.get("privacy_category") == category
                   and finding.get("value_redacted") == redacted
                   and finding.get("source") == source
                   and finding.get("direction") == direction
                   and (key is None or finding.get("key") == key)]
        self.assertTrue(matches, f"Missing {artifact} / {category} in {source} ({direction})")
        self.assertTrue(any(item["type"] == artifact
                            and item["value_redacted"] == redacted
                            for item in detector.get_unique_findings()),
                        "Detected artifact must also reach the unique-artifact inventory")
        for finding in sample.sensitive_data:
            self.assertNotIn("_raw_value", finding)
        self.assertNotIn(str(value), json.dumps(sample.sensitive_data))
        self.assertNotIn(str(value), json.dumps(detector.get_unique_findings()))

    def assert_clean(self, sample):
        detector = SensitiveDataDetector([sample])
        detector.analyze()
        self.assertEqual([], sample.sensitive_data)
        self.assertEqual([], detector.get_unique_findings())

    def test_form_json_array_preserves_both_phone_artifacts(self):
        """_extract_body_pairs does not descend into form field JSON arrays."""
        other_phone = "+1 (202) 555-0198"
        body = urlencode({"variables": json.dumps([
            {"phone": PHONE}, {"phone": other_phone}
        ])})
        for value in (PHONE, other_phone):
            with self.subTest(value=value):
                self.assert_artifact(request(body=body, body_type="form"),
                                     "Phone", "Personal Information", value, "Request Body")

    def test_query_generic_key_embedded_email(self):
        """Query analysis uses fullmatch email detection, not substring extraction."""
        self.assert_artifact(extracted({"url": "https://example.test/search?" + urlencode({
            "q": f"contact {EMAIL} please"
        })}), "Email", "Personal Information", EMAIL, "Query Parameter")

    def test_query_generic_key_formatted_phone(self):
        """An explicit internationally formatted phone is missed without a phone key."""
        self.assert_artifact(extracted({"url": "https://example.test/search?" + urlencode({
            "q": PHONE
        })}), "Phone", "Personal Information", PHONE, "Query Parameter")

    def test_query_application_contact_point_phone(self):
        self.assert_artifact(extracted({"url": "https://example.test/lookup?" + urlencode({
            "contact_point": PHONE
        })}), "Phone", "Personal Information", PHONE, "Query Parameter")

    def test_query_json_value_phone(self):
        self.assert_artifact(extracted({"url": "https://example.test/search?" + urlencode({
            "variables": json.dumps({"phone": PHONE})
        })}), "Phone", "Personal Information", PHONE, "Query Parameter")

    def test_query_duplicate_key_retains_later_email(self):
        """RequestExtractor.extract_requests keeps only the first query value."""
        url = "https://example.test/search?" + urlencode([("q", "ordinary"), ("q", EMAIL)])
        self.assert_artifact(extracted({"url": url}), "Email", "Personal Information",
                             EMAIL, "Query Parameter")

    def test_json_string_nested_inside_json_phone(self):
        """_extract_json_pairs treats serialized JSON strings as terminal values."""
        self.assert_artifact(request(body=json.dumps({
            "payload": json.dumps({"phone": PHONE})
        }), body_type="json"), "Phone", "Personal Information", PHONE, "Request Body")

    def test_json_phone_array_preserves_parent_field_context(self):
        """The numeric array index becomes the leaf instead of phone."""
        self.assert_artifact(request(body=json.dumps({"phone": [PHONE]})),
                             "Phone", "Personal Information", PHONE, "Request Body")

    def test_top_level_name_remains_personal_information(self):
        value = "Synthetic Person"
        self.assert_artifact(
            request(body=json.dumps({"name": value})),
            "Name", "Personal Information", value, "Request Body", key="name"
        )

    def test_nested_name_requires_person_context(self):
        value = "Synthetic Person"
        cases = [
            ({"profile": {"name": value}}, "profile.name"),
            ({"events": [{"user": {"name": value}}]}, "events[0].user.name"),
        ]
        for body, key in cases:
            with self.subTest(key=key):
                self.assert_artifact(
                    request(body=json.dumps(body)),
                    "Name", "Personal Information", value, "Request Body", key=key
                )

    def test_explicit_nested_name_aliases_remain_supported(self):
        value = "Synthetic Person"
        for field in ("full_name", "fullname", "first_name", "last_name"):
            with self.subTest(field=field):
                self.assert_artifact(
                    request(body=json.dumps({"profile": {field: value}})),
                    "Name", "Personal Information", value, "Request Body",
                    key=f"profile.{field}"
                )

    def test_non_person_nested_names_are_clean(self):
        value = "Synthetic Person"
        cases = [
            {"feature_gates": {"13203271": {"name": value}}},
            {"metadata": {"markers": [{"error": {"name": value}}]}},
            {"items": [{"name": value}]},
            {"config": {"name": value}},
            {"event": {"name": value}},
            {"venue": {"name": value}},
        ]
        for body in cases:
            with self.subTest(body=body):
                self.assert_clean(request(body=json.dumps(body)))

    def test_array_uses_nearest_exact_parent_field(self):
        cases = [
            ("device_id", DEVICE_ID, "Device ID", "Device Identifier"),
            ("access_token", credential(), "Authorization Token", "Authentication"),
            ("latitude", "12.3456", "Latitude", "Location"),
        ]
        for field, value, artifact, category in cases:
            with self.subTest(field=field):
                self.assert_artifact(
                    request(body=json.dumps({field: [value]}), body_type="json"),
                    artifact, category, value, "Request Body", key=f"{field}[0]",
                )

    def test_array_does_not_promote_arbitrary_ancestor_or_generic_id(self):
        self.assert_clean(request(
            body=json.dumps({"device_id_container": [{"id": DEVICE_ID}]}),
            body_type="json",
        ))

    def test_structured_json_query_value_is_classified(self):
        value = json.dumps({"profile": {"device_id": DEVICE_ID}})
        self.assert_artifact(
            request(query_param_pairs=[("variables", value)]),
            "Device ID", "Device Identifier", DEVICE_ID, "Query Parameter",
            key="variables.profile.device_id",
        )

    def test_unpadded_standard_base64_json_uses_normal_classification(self):
        payload = json.dumps(
            {"device_id": DEVICE_ID}, separators=(",", ":")
        ).encode("utf-8")
        encoded = base64.b64encode(payload).decode("ascii").rstrip("=")
        self.assert_artifact(
            request(query_param_pairs=[("payload", encoded)]),
            "Device ID", "Device Identifier", DEVICE_ID, "Query Parameter",
            key="payload.__base64__.device_id",
        )

    def test_unpadded_base64url_json_uses_normal_classification(self):
        payload = json.dumps(
            {"device_id": DEVICE_ID, "m": "\u083e"},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        self.assertRegex(encoded, r"[-_]")
        self.assert_artifact(
            request(cookie_pairs=[("payload", encoded)]),
            "Device ID", "Device Identifier", DEVICE_ID, "Cookie",
            key="payload.__base64__.device_id",
        )

    def test_random_opaque_urlsafe_value_remains_clean(self):
        self.assert_clean(request(
            query_param_pairs=[("opaque", credential())],
            cookie_pairs=[("opaque", credential())],
        ))

    def test_bounded_recursive_stringified_json(self):
        nested = json.dumps({"device_id": DEVICE_ID})
        for key in ("third", "second", "first"):
            nested = json.dumps({key: nested})
        self.assert_artifact(
            request(body=json.dumps({"payload": nested}), body_type="json"),
            "Device ID", "Device Identifier", DEVICE_ID, "Request Body",
            key="payload.first.second.third.device_id",
        )

    def test_stringified_json_recursion_limit_preserves_sibling_detection(self):
        nested = json.dumps({"device_id": DEVICE_ID})
        for index in range(8):
            nested = json.dumps({f"level_{index}": nested})
        sample = request(body=json.dumps({
            "deep": nested,
            "latitude": "12.3456",
        }), body_type="json")
        detector = SensitiveDataDetector([sample])
        detector.analyze()
        PrivacyNormalizer([sample]).normalize()

        self.assertTrue(any(
            finding.get("type") == "Latitude"
            for finding in sample.sensitive_data
        ))
        self.assertFalse(any(
            finding.get("type") == "Device ID"
            for finding in sample.sensitive_data
        ))

    def test_deep_json_carrier_does_not_abort_remaining_request_analysis(self):
        deeply_nested = "[" * 1500 + '"ordinary"' + "]" * 1500
        self.assert_artifact(
            request(query_param_pairs=[
                ("deep", deeply_nested),
                ("device_id", DEVICE_ID),
            ]),
            "Device ID", "Device Identifier", DEVICE_ID, "Query Parameter",
            key="device_id",
        )

    def test_post_data_params_only_value_and_text_occurrence_do_not_duplicate(self):
        sample = extracted({"postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "text": urlencode({"phone": PHONE}),
            "params": [
                {"name": "phone", "value": PHONE},
                {"name": "device_id", "value": DEVICE_ID},
            ],
        }})
        detector = SensitiveDataDetector([sample])
        detector.analyze()
        PrivacyNormalizer([sample]).normalize()

        self.assertEqual(1, sum(
            finding.get("type") == "Phone"
            for finding in sample.sensitive_data
        ))
        self.assertEqual(1, sum(
            finding.get("type") == "Device ID"
            for finding in sample.sensitive_data
        ))

    def test_reconciled_form_params_preserve_excess_identical_occurrence(self):
        sample = extracted({"postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "text": urlencode({"email": EMAIL}),
            "params": [
                {"name": "email", "value": EMAIL},
                {"name": "email", "value": EMAIL},
            ],
        }})
        SensitiveDataDetector([sample]).analyze()

        self.assertTrue(sample.body_param_pairs_reconciled)
        self.assertEqual(2, sum(
            finding.get("type") == "Email"
            and finding.get("source") == "Request Body"
            for finding in sample.sensitive_data
        ))

    def test_identical_query_and_cookie_occurrences_reach_inventory(self):
        sample = request(
            query_param_pairs=[("email", EMAIL), ("email", EMAIL)],
            cookie_pairs=[("device_id", DEVICE_ID), ("device_id", DEVICE_ID)],
            traffic_type="Application",
        )
        SensitiveDataDetector([sample]).analyze()
        PrivacyNormalizer([sample]).normalize()
        evidence = PrivacyInventoryGenerator([sample]).generate()["Application"]["evidence"]

        self.assertEqual(2, sum(
            item.get("source") == "Query Parameter"
            and item.get("type") == "Email"
            for item in evidence
        ))
        self.assertEqual(2, sum(
            item.get("source") == "Cookie"
            and item.get("type") == "Device ID"
            for item in evidence
        ))

    def test_compatibility_query_view_does_not_duplicate_pair_evidence(self):
        sample = request(
            query_param_pairs=[("email", EMAIL)],
            query_params={"email": EMAIL},
        )
        SensitiveDataDetector([sample]).analyze()

        self.assertEqual(1, sum(
            finding.get("source") == "Query Parameter"
            and finding.get("type") == "Email"
            for finding in sample.sensitive_data
        ))

    def test_structured_json_cookie_values_preserve_direction(self):
        outbound_token = credential()
        inbound_device = DEVICE_ID
        sample = request(
            cookie_pairs=[("payload", json.dumps({"access_token": outbound_token}))],
            response_cookie_pairs=[("state", json.dumps({"device_id": inbound_device}))],
        )
        self.assert_artifact(
            sample, "Authorization Token", "Authentication", outbound_token,
            "Cookie", "outbound", key="payload.access_token",
        )
        self.assert_artifact(
            sample, "Device ID", "Device Identifier", inbound_device,
            "Response Cookie", "inbound", key="state.device_id",
        )

    def test_malformed_json_carrier_falls_back_to_text_signals(self):
        malformed = '{"broken":"' + EMAIL
        self.assert_artifact(
            request(query_param_pairs=[("payload", malformed)]),
            "Email", "Personal Information", EMAIL, "Query Parameter",
        )

    def test_non_json_prefixed_carrier_is_not_structurally_classified(self):
        value = "prefix " + json.dumps({"device_id": DEVICE_ID})
        self.assert_clean(request(
            query_param_pairs=[("payload", value)],
            cookie_pairs=[("payload", value)],
        ))

    def test_multipart_mixed_application_http_uses_embedded_body_only(self):
        embedded = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "X-Contact: header-only@example.test\r\n\r\n"
            + json.dumps({"device_id": DEVICE_ID})
        )
        body, content_type = multipart_container(
            "mixed", [("application/http", embedded)]
        )
        sample = request(
            response_body=body,
            response_body_type="binary",
            response_content_type=content_type,
        )
        detector = SensitiveDataDetector([sample])
        detector.analyze()
        PrivacyNormalizer([sample]).normalize()

        self.assertTrue(any(
            finding.get("type") == "Device ID"
            and finding.get("source") == "Response Body"
            and finding.get("direction") == "inbound"
            for finding in sample.sensitive_data
        ))
        self.assertFalse(any(
            finding.get("type") == "Email"
            for finding in sample.sensitive_data
        ))

    def test_multipart_related_skips_arbitrary_binary_parts(self):
        hidden_email = "hidden.person@example.test"
        body, content_type = multipart_container("related", [
            ("application/json", json.dumps({"device_id": DEVICE_ID})),
            ("application/octet-stream", "binary-prefix " + hidden_email),
        ])
        sample = request(body=body, body_type="binary", content_type=content_type)
        detector = SensitiveDataDetector([sample])
        detector.analyze()
        PrivacyNormalizer([sample]).normalize()

        self.assertTrue(any(
            finding.get("type") == "Device ID"
            and finding.get("source") == "Request Body"
            and finding.get("direction") == "outbound"
            for finding in sample.sensitive_data
        ))
        self.assertFalse(any(
            finding.get("type") == "Email"
            for finding in sample.sensitive_data
        ))

    def test_binary_part_internal_boundary_text_does_not_create_part(self):
        boundary = "phase-3a-boundary"
        hidden_email = "hidden.boundary@example.test"
        binary_payload = (
            "binary-prefix--" + boundary
            + "\r\nContent-Type: text/plain\r\n\r\n"
            + hidden_email
        )
        body, content_type = multipart_container("mixed", [
            ("application/octet-stream", binary_payload),
            ("application/json", json.dumps({"device_id": DEVICE_ID})),
        ])
        sample = request(body=body, body_type="binary", content_type=content_type)
        detector = SensitiveDataDetector([sample])
        detector.analyze()
        PrivacyNormalizer([sample]).normalize()

        self.assertTrue(any(
            finding.get("type") == "Device ID"
            for finding in sample.sensitive_data
        ))
        self.assertFalse(any(
            finding.get("type") == "Email"
            for finding in sample.sensitive_data
        ))

    def test_form_data_binary_without_filename_is_not_text_scanned(self):
        boundary = "binary-form-boundary"
        hidden_email = "hidden.binary@example.test"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="blob"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
            f"binary-prefix {hidden_email}\r\n"
            f"--{boundary}--\r\n"
        )
        self.assert_clean(request(
            body=body,
            body_type="multipart",
            content_type=f"multipart/form-data; boundary={boundary}",
        ))

    def test_form_data_quoted_filename_preserves_binary_and_text_behavior(self):
        binary_email = "quoted.binary@example.test"
        self.assert_clean(multipart_form_part(
            'form-data; name="upload"; filename="photo.jpg"',
            "binary-prefix " + binary_email,
        ))

        text_email = "quoted.text@example.test"
        self.assert_artifact(
            multipart_form_part(
                'form-data; name="upload"; filename="contacts.txt"',
                text_email,
                "text/plain",
            ),
            "Email", "Personal Information", text_email, "Request Body",
        )

    def test_form_data_unquoted_filename_is_binary_protected(self):
        hidden_email = "unquoted.binary@example.test"
        self.assert_clean(multipart_form_part(
            'form-data; name="upload"; filename=photo.jpg',
            "binary-prefix " + hidden_email,
        ))

    def test_form_data_malformed_filename_fails_closed(self):
        hidden_email = "malformed.binary@example.test"
        self.assert_clean(multipart_form_part(
            'form-data; name="upload"; filename="photo.jpg',
            "binary-prefix " + hidden_email,
        ))

    def test_form_data_text_parts_remain_analyzable(self):
        boundary = "text-form-boundary"
        named_email = "named.person@example.test"
        unnamed_email = "unnamed.person@example.test"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="contact"\r\n\r\n'
            f"{named_email}\r\n"
            f"--{boundary}\r\n"
            "Content-Type: text/plain\r\n\r\n"
            f"{unnamed_email}\r\n"
            f"--{boundary}--\r\n"
        )
        sample = request(
            body=body,
            body_type="multipart",
            content_type=f'multipart/form-data; boundary="{boundary}"',
        )
        for email in (named_email, unnamed_email):
            with self.subTest(email=email):
                self.assert_artifact(
                    sample, "Email", "Personal Information", email, "Request Body"
                )

    def test_multipart_boundary_parameter_accepts_safe_spacing_and_quotes(self):
        boundary = "spaced-boundary"
        body = (
            f"--{boundary}\r\nContent-Type: application/json\r\n\r\n"
            + json.dumps({"device_id": DEVICE_ID})
            + f"\r\n--{boundary}--\r\n"
        )
        content_types = [
            f"multipart/mixed; boundary={boundary}",
            f'multipart/mixed; boundary = "{boundary}" ; type=application/json',
        ]
        for content_type in content_types:
            with self.subTest(content_type=content_type):
                self.assert_artifact(
                    request(body=body, body_type="binary", content_type=content_type),
                    "Device ID", "Device Identifier", DEVICE_ID, "Request Body",
                )

    def test_multipart_boundary_parameter_rejects_partial_or_wrong_names(self):
        boundary = "actual-boundary"
        body = (
            f"--{boundary}\r\nContent-Type: application/json\r\n\r\n"
            + json.dumps({"device_id": DEVICE_ID})
            + f"\r\n--{boundary}--\r\n"
        )
        for content_type in (
            f"multipart/mixed; notboundary={boundary}",
            "multipart/mixed; boundary",
            f'multipart/mixed; boundary="{boundary}',
        ):
            with self.subTest(content_type=content_type):
                self.assert_clean(request(
                    body=body, body_type="binary", content_type=content_type
                ))

    def test_multipart_mixed_without_boundary_is_safe_and_clean(self):
        self.assert_clean(request(
            body="synthetic.person@example.test",
            body_type="binary",
            content_type="multipart/mixed",
        ))

    def test_multipart_part_limit_counts_malformed_parts(self):
        boundary = "bounded-part-count"
        body = f"--{boundary}\r\n"
        body += (f"invalid\r\n--{boundary}\r\n" * 256)
        body += (
            "Content-Type: text/plain\r\n\r\n"
            "beyond.limit@example.test\r\n"
            f"--{boundary}--\r\n"
        )
        self.assert_clean(request(
            body=body,
            body_type="binary",
            content_type=f"multipart/mixed; boundary={boundary}",
        ))

    def test_html_visible_email_is_not_discarded_with_inline_script(self):
        """Response JavaScript heuristic drops the entire HTML document."""
        body = ('<html><script>function ready(){var flag=1;return flag;}</script>'
                f'<p>Contact: {EMAIL}</p></html>')
        self.assert_artifact(request(response_body=body, response_content_type="text/html"),
                             "Email", "Personal Information", EMAIL, "Response Body", "inbound")

    def test_grpc_second_frame_email(self):
        """ProtobufScanner._decode_grpc_frame returns only the first frame."""
        def frame(text):
            data = text.encode("utf-8")
            message = bytes([0x0A, len(data)]) + data
            return b"\x00" + len(message).to_bytes(4, "big") + message
        body = (frame("ordinary") + frame(EMAIL)).decode("latin-1")
        self.assert_artifact(request(body=body, body_type="grpc"),
                             "Email", "Personal Information", EMAIL, "gRPC Body")

    def test_grpc_compressed_frame_email(self):
        data = EMAIL.encode("utf-8")
        message = bytes([0x0A, len(data)]) + data
        compressed = gzip.compress(message)
        body = (b"\x01" + len(compressed).to_bytes(4, "big") + compressed).decode("latin-1")
        self.assert_artifact(request(body=body, body_type="grpc"),
                             "Email", "Personal Information", EMAIL, "gRPC Body")

    def test_base64_grpc_preserves_utf8_bytes_before_email(self):
        unicode_value = "café".encode("utf-8")
        email_value = EMAIL.encode("utf-8")
        message = (
            bytes([0x0A, len(unicode_value)]) + unicode_value
            + bytes([0x12, len(email_value)]) + email_value
        )
        frame = b"\x00" + len(message).to_bytes(4, "big") + message
        body = base64.b64encode(frame).decode("ascii")
        self.assert_artifact(
            request(
                body=body,
                body_type="grpc",
                body_encoding="base64",
                content_type="application/grpc",
            ),
            "Email", "Personal Information", EMAIL, "gRPC Body",
        )

    def test_raw_protobuf_request_email(self):
        body = protobuf_string(1, EMAIL).decode("latin-1")
        self.assert_artifact(
            request(
                body=body,
                body_type="binary",
                content_type="Application/X-Protobuf; charset=binary",
            ),
            "Email", "Personal Information", EMAIL, "Protobuf Body",
        )

    def test_raw_protobuf_response_email(self):
        body = protobuf_string(1, EMAIL).decode("latin-1")
        self.assert_artifact(
            request(
                response_body=body,
                response_body_type="binary",
                response_content_type="application/x-protobuf",
            ),
            "Email", "Personal Information", EMAIL, "Response Protobuf Body", "inbound",
        )

    def test_base64_raw_protobuf_response_email(self):
        body = base64.b64encode(protobuf_string(1, EMAIL)).decode("ascii")
        self.assert_artifact(
            request(
                response_body=body,
                response_body_type="binary",
                response_content_type="APPLICATION/X-PROTOBUF; version=1",
                response_body_encoding="base64",
            ),
            "Email", "Personal Information", EMAIL, "Response Protobuf Body", "inbound",
        )

    def test_http_toolkit_request_content_reaches_raw_protobuf_detector(self):
        body = base64.b64encode(protobuf_string(1, EMAIL)).decode("ascii")
        sample = extracted({
            "headers": [{
                "name": "Content-Type",
                "value": "application/x-protobuf",
            }],
            "_content": {
                "text": body,
                "size": len(body),
                "encoding": "base64",
            },
        })
        self.assert_artifact(
            sample,
            "Email", "Personal Information", EMAIL, "Protobuf Body",
        )

    def test_utf16_declared_charset_request_and_response_json(self):
        request_body = base64.b64encode(
            json.dumps({"device_id": DEVICE_ID}).encode("utf-16le")
        ).decode("ascii")
        response_email = "utf16.person@example.test"
        response_body = base64.b64encode(
            json.dumps({"email": response_email}).encode("utf-16be")
        ).decode("ascii")
        sample = request(
            body=request_body,
            body_type="json",
            body_encoding="base64",
            content_type="application/json; charset=utf-16le",
            response_body=response_body,
            response_body_type="json",
            response_body_encoding="base64",
            response_content_type='application/json; charset="utf-16be"',
        )
        self.assert_artifact(
            sample, "Device ID", "Device Identifier", DEVICE_ID, "Request Body"
        )
        self.assert_artifact(
            sample, "Email", "Personal Information", response_email,
            "Response Body", "inbound",
        )

    def test_decoded_unicode_string_is_not_reinterpreted_as_bytes(self):
        person_name = "Zoë 🚀"
        self.assert_artifact(
            request(
                body=json.dumps({"name": person_name}, ensure_ascii=False),
                body_type="json",
                content_type="application/json; charset=utf-8",
            ),
            "Name", "Personal Information", person_name, "Request Body",
        )

    def test_decoded_json_ignores_stale_charset_declaration(self):
        self.assert_artifact(
            request(
                body=json.dumps({"email": EMAIL}),
                body_type="json",
                content_type="application/json; charset=utf-16",
            ),
            "Email", "Personal Information", EMAIL, "Request Body",
        )

    def test_genuine_text_bytes_use_declared_charset(self):
        cases = [
            (
                "utf-8",
                json.dumps({"email": EMAIL}).encode("utf-8"),
                "Email",
                "Personal Information",
                EMAIL,
            ),
            (
                "utf-16le",
                json.dumps({"device_id": DEVICE_ID}).encode("utf-16le"),
                "Device ID",
                "Device Identifier",
                DEVICE_ID,
            ),
        ]
        for charset, body, artifact, category, value in cases:
            with self.subTest(charset=charset):
                self.assert_artifact(
                    request(
                        body=body,
                        body_type="json",
                        content_type=f"application/json; charset={charset}",
                    ),
                    artifact, category, value, "Request Body",
                )

    def test_unsupported_charset_falls_back_to_utf8(self):
        body = json.dumps({"device_id": DEVICE_ID}).encode("utf-8")
        self.assert_artifact(
            request(
                body=body,
                body_type="json",
                content_type="application/json; charset=x-unsupported",
            ),
            "Device ID", "Device Identifier", DEVICE_ID, "Request Body",
        )

    def test_gzip_and_deflate_body_decoding_remains_supported(self):
        payload = json.dumps({"device_id": DEVICE_ID}).encode("utf-8")
        cases = [
            ("gzip", gzip.compress(payload)),
            ("deflate", zlib.compress(payload)),
        ]
        for encoding, body in cases:
            with self.subTest(encoding=encoding):
                self.assert_artifact(
                    request(
                        body=body,
                        body_type="json",
                        body_encoding=encoding,
                        content_type="application/json",
                    ),
                    "Device ID", "Device Identifier", DEVICE_ID, "Request Body",
                )

    def test_oversized_decompression_is_rejected_without_aborting_response(self):
        oversized = gzip.compress(b"x" * (8 * 1024 * 1024 + 1))
        response_email = "continued.person@example.test"
        self.assert_artifact(
            request(
                body=oversized,
                body_type="text",
                body_encoding="gzip",
                content_type="text/plain",
                response_body=response_email,
                response_content_type="text/plain",
            ),
            "Email", "Personal Information", response_email,
            "Response Body", "inbound",
        )

    def test_already_decoded_unknown_content_encoding_is_not_redecoded(self):
        for encoding in ("br", "zstd"):
            with self.subTest(encoding=encoding):
                self.assert_artifact(
                    request(
                        body=json.dumps({"device_id": DEVICE_ID}),
                        body_type="json",
                        body_encoding=encoding,
                        content_type="application/json",
                    ),
                    "Device ID", "Device Identifier", DEVICE_ID, "Request Body",
                )

    def test_raw_protobuf_is_not_mistaken_for_grpc_envelope(self):
        # A valid fixed32 field makes bytes 1:5 look like a one-byte gRPC
        # payload length. Raw parsing must not strip those first five bytes.
        message = b"\x0d\x00\x00\x00\x01" + protobuf_string(2, EMAIL)
        self.assertEqual([EMAIL], ProtobufScanner.extract_raw_strings(message))
        self.assert_artifact(
            request(
                body=message.decode("latin-1"),
                body_type="binary",
                content_type="application/x-protobuf",
            ),
            "Email", "Personal Information", EMAIL, "Protobuf Body",
        )

    def test_raw_protobuf_extracts_multiple_top_level_strings(self):
        message = protobuf_string(1, "ordinary") + protobuf_string(2, EMAIL)
        self.assertEqual(
            ["ordinary", EMAIL],
            ProtobufScanner.extract_raw_strings(message),
        )

    def test_malformed_raw_protobuf_fails_safely(self):
        malformed = b"\x0a\xff"
        self.assertEqual([], ProtobufScanner.extract_raw_strings(malformed))
        self.assert_clean(request(
            body=malformed.decode("latin-1"),
            body_type="binary",
            content_type="application/x-protobuf",
        ))

    def test_octet_stream_is_not_dispatched_as_raw_protobuf(self):
        body = protobuf_string(1, EMAIL).decode("latin-1")
        sample = request(
            body=body,
            body_type="binary",
            content_type="application/octet-stream",
        )
        SensitiveDataDetector([sample]).analyze()

        self.assertFalse(any(
            finding.get("source") == "Protobuf Body"
            or finding.get("key") == "protobuf_string"
            for finding in sample.sensitive_data
        ))

    # Passing controls prevent fixing false negatives by indiscriminate flagging.
    def test_control_generic_query_exact_email(self):
        self.assert_artifact(extracted({"url": "https://example.test/?" + urlencode({"q": EMAIL})}),
                             "Email", "Personal Information", EMAIL, "Query Parameter")

    def test_control_email_key_with_non_email_value(self):
        self.assert_clean(request(
            body=json.dumps({"email": "not provided"}),
            body_type="json",
            content_type="application/json",
        ))

    def test_control_flat_form_phone(self):
        self.assert_artifact(request(body=urlencode({"phone": PHONE}), body_type="form"),
                             "Phone", "Personal Information", PHONE, "Request Body")

    def test_control_nested_json_phone(self):
        self.assert_artifact(request(body=json.dumps({"profile": {"phone": PHONE}})),
                             "Phone", "Personal Information", PHONE, "Request Body")

    def test_control_large_structured_json_email(self):
        self.assert_artifact(request(response_body=json.dumps({"padding": " " * 250001,
                                                               "email": EMAIL})),
                             "Email", "Personal Information", EMAIL, "Response Body", "inbound")

    def test_control_plaintext_email(self):
        self.assert_artifact(request(response_body=f"Contact: {EMAIL}"),
                             "Email", "Personal Information", EMAIL, "Response Body", "inbound")

    def test_large_free_text_email_scanning_uses_chunk_overlap(self):
        crossing_email = "crossing.person@example.test"
        ending_email = "ending.person@example.test"
        boundary = SensitiveDataDetector._FREE_TEXT_CHUNK_SIZE
        body = (
            "x" * (boundary - 8)
            + " " + crossing_email + " "
            + "x" * (3 * 1024 * 1024 - boundary)
            + " " + ending_email
        )
        sample = request(response_body=body, response_content_type="text/plain")
        for email in (crossing_email, ending_email):
            with self.subTest(email=email):
                self.assert_artifact(
                    sample, "Email", "Personal Information", email,
                    "Response Body", "inbound",
                )

    def test_large_free_text_negative_control_remains_clean(self):
        self.assert_clean(request(
            response_body="ordinary text " * 180000,
            response_content_type="text/plain",
        ))

    def test_email_scanning_is_bounded_with_many_markers_below_threshold(self):
        detector = SensitiveDataDetector([])
        body = ("a@" * 600000) + " " + EMAIL
        self.assertEqual([EMAIL], detector._find_emails_in_body(body))

    def test_email_scanning_is_bounded_with_millions_of_markers(self):
        detector = SensitiveDataDetector([])
        body = ("@" * (2 * 1024 * 1024 + 1024)) + " " + EMAIL
        self.assertEqual([EMAIL], detector._find_emails_in_body(body))

    def test_email_scanning_is_bounded_for_long_pathological_text(self):
        detector = SensitiveDataDetector([])
        body = ("a" * (2 * 1024 * 1024 - 256)) + "@invalid " + EMAIL
        self.assertEqual([EMAIL], detector._find_emails_in_body(body))

    def test_bounded_email_scanning_in_structured_json(self):
        sample = request(
            body=json.dumps({"note": ("a" * 100000) + " " + EMAIL}),
            body_type="json",
            content_type="application/json",
        )
        self.assert_artifact(
            sample, "Email", "Personal Information", EMAIL, "Request Body",
            key="note",
        )

    def test_bounded_email_scanning_in_query_and_cookie_values(self):
        adversarial = ("a" * 100000) + " " + EMAIL
        sample = request(
            query_param_pairs=[("payload", adversarial)],
            cookie_pairs=[("payload", adversarial)],
        )
        self.assert_artifact(
            sample, "Email", "Personal Information", EMAIL, "Query Parameter",
            key="payload",
        )
        self.assert_artifact(
            sample, "Email", "Personal Information", EMAIL, "Cookie",
            key="payload",
        )

    def test_bounded_email_scanning_in_protobuf_strings(self):
        detector = SensitiveDataDetector([])
        findings = []
        detector._analyze_protobuf_strings(
            [("a" * 100000) + " " + EMAIL],
            findings,
            "Protobuf Body",
        )

        self.assertEqual([EMAIL], [
            finding.get("_raw_value")
            for finding in findings
            if finding.get("type") == "Email"
        ])

    def test_control_grpc_single_frame_email(self):
        data = EMAIL.encode("utf-8")
        message = bytes([0x0A, len(data)]) + data
        body = (b"\x00" + len(message).to_bytes(4, "big") + message).decode("latin-1")
        self.assert_artifact(request(body=body, body_type="grpc"),
                             "Email", "Personal Information", EMAIL, "gRPC Body")

    def test_control_benign_generic_query_values(self):
        # Neither arbitrary numbers, UUIDs nor opaque strings establish a type.
        self.assert_clean(request(query_params={"q": "ordinary search", "count": "1234567890",
                                                "value": DEVICE_ID, "opaque": credential()}))

    def test_control_benign_cookies(self):
        self.assert_clean(request(cookies={"theme": "dark", "locale": "en-US"},
                                  response_cookies={"theme": "light"}))

    def test_lossless_header_and_body_parameter_pairs_are_consumed(self):
        """Detector uses Phase-1 pairs when compatibility dictionaries are lossy."""
        sample = request(
            headers={"X-Trace": "ordinary"},
            header_pairs=[("X-Trace", "ordinary"), ("X-CSRF-Token", credential())],
            body_param_pairs=[("phone", PHONE)],
        )
        detector = SensitiveDataDetector([sample])
        detector.analyze()
        PrivacyNormalizer([sample]).normalize()

        self.assertEqual({"CSRF Token", "Phone"}, {
            finding["type"] for finding in sample.sensitive_data
        })

    def test_control_benign_multipart(self):
        self.assert_clean(multipart([("theme", "dark"), ("count", "1234567890")]))

    def test_control_source_code_identifiers_are_not_credentials(self):
        self.assert_clean(request(response_body=
                                  "function ready(){var csrf_token=null;return csrf_token;}"))

    def test_control_malformed_embedded_json_is_safe(self):
        self.assert_clean(request(body=urlencode({"variables": '{"theme":'}), body_type="form"))


def install_case(name, description, build, artifact, category, source, direction="outbound"):
    """Give each matrix case its own discoverable test and failure report."""
    def test(self):
        sample, value = build()
        self.assert_artifact(sample, artifact, category, value, source, direction)
    test.__name__ = "test_" + name
    test.__doc__ = description + f" Expected: {artifact} / {category}."
    setattr(SensitiveDataRegressions, test.__name__, test)


# JSON-in-form: percent encoding prevents a raw email regex from hiding the gap.
for field, factory, artifact, category in [
    ("email", lambda: EMAIL, "Email", "Personal Information"),
    ("phone", lambda: PHONE, "Phone", "Personal Information"),
    ("device_id", lambda: DEVICE_ID, "Device ID", "Device Identifier"),
    ("latitude", lambda: "12.3456", "Latitude", "Location"),
    ("csrf_token", credential, "CSRF Token", "Security"),
]:
    def build(field=field, factory=factory):
        value = factory()
        body = urlencode({"variables": json.dumps({field: value})})
        return request(body=body, body_type="form"), value
    install_case("form_json_" + field, "Form values need recursive JSON parsing.",
                 build, artifact, category, "Request Body")


# No new artifact taxonomy is invented: use existing device/auth/security types.
# xs is an application-specific authentication-session cookie; datr identifies
# the browser, not an authentication session. Neither name contains 'session'.
for field, factory, artifact, category in [
    ("device_id", lambda: DEVICE_ID, "Device ID", "Device Identifier"),
    ("datr", lambda: DEVICE_ID, "Device ID", "Device Identifier"),
    ("access_token", credential, "Authorization Token", "Authentication"),
    ("xs", credential, "Session Cookie", "Authentication"),
    ("csrf_token", credential, "CSRF Token", "Security"),
]:
    for inbound in (False, True):
        def build(field=field, factory=factory, inbound=inbound):
            value = factory()
            return request(**{"response_cookies" if inbound else "cookies": {field: value}}), value
        install_case(("response" if inbound else "request") + "_cookie_" + field,
                     "analyze only recognizes cookie names containing session.", build,
                     artifact, category, "Response Cookie" if inbound else "Cookie",
                     "inbound" if inbound else "outbound")


for transport in ("query", "form", "json"):
    def build(transport=transport):
        value = credential()
        fields = {"fb_dtsg": value}
        if transport == "query":
            sample = extracted({"url": "https://example.test/?" + urlencode(fields)})
        else:
            sample = request(body=urlencode(fields) if transport == "form" else json.dumps(fields),
                             body_type=transport)
        return sample, value
    install_case("fb_dtsg_" + transport, "_classify_key_value lacks the fb_dtsg CSRF alias.",
                 build, "CSRF Token", "Security",
                 "Query Parameter" if transport == "query" else "Request Body")


for field, factory, artifact, category in [
    ("phone", lambda: PHONE, "Phone", "Personal Information"),
    ("device_id", lambda: DEVICE_ID, "Device ID", "Device Identifier"),
    ("csrf_token", credential, "CSRF Token", "Security"),
]:
    for quoted in (False, True):
        def build(field=field, factory=factory, quoted=quoted):
            value = factory()
            return multipart([("theme", "dark"), (field, value)], quoted), value
        install_case("multipart_" + field + ("_quoted_boundary" if quoted else ""),
                     "_extract_body_pairs has no multipart parser; MIME metadata must be honored.",
                     build, artifact, category, "Request Body")


# Compound leaf names are incorrectly split at underscores before classification.
for field, factory, artifact, category in [
    ("full_name", lambda: "Synthetic Person", "Name", "Personal Information"),
    ("date_of_birth", lambda: "1990-01-02", "Date of Birth", "Personal Information"),
    ("phone_number", lambda: PHONE, "Phone", "Personal Information"),
    ("device_id", lambda: DEVICE_ID, "Device ID", "Device Identifier"),
    ("api_key", credential, "API Key", "API Credentials"),
    ("ip_address", lambda: "192.0.2.123", "IP Address", "Network Information"),
]:
    def build(field=field, factory=factory):
        value = factory()
        return request(body=json.dumps({"profile": {field: value}})), value
    install_case("nested_compound_key_" + field,
                 "_classify_key_value loses compound leaf names; full paths are not aliases.",
                 build, artifact, category, "Request Body")


for mime in ("application/x-www-form-urlencoded", "multipart/form-data"):
    def build(mime=mime):
        return extracted({"postData": {"mimeType": mime, "params": [
            {"name": "phone", "value": PHONE}
        ]}}), PHONE
    install_case("post_data_params_" + ("form" if "urlencoded" in mime else "multipart"),
                 "_extract_request_body ignores postData.params when text is absent.",
                 build, "Phone", "Personal Information", "Request Body")


for inbound in (False, True):
    def cookie_header(inbound=inbound):
        value = credential()
        headers = [{"name": "Set-Cookie" if inbound else "Cookie",
                    "value": f"session={value}" + ("; Path=/; HttpOnly" if inbound else "")}]
        return extracted(response_fields={"headers": headers}) if inbound else extracted(
            {"headers": headers}), value
    install_case(("response" if inbound else "request") + "_raw_cookie_header",
                 "_extract_cookies ignores cookie headers when HAR cookie arrays are absent.",
                 cookie_header, "Session Cookie", "Authentication",
                 "Response Cookie" if inbound else "Cookie", "inbound" if inbound else "outbound")

    def encoded_body(inbound=inbound):
        content = {"mimeType": "application/json", "encoding": "base64",
                   "text": base64.b64encode(json.dumps({"phone": PHONE}).encode()).decode()}
        return extracted(response_fields={"content": content}) if inbound else extracted(
            {"postData": content}), PHONE
    install_case(("response" if inbound else "request") + "_base64_json",
                 "Extractor retains encoding metadata but detector never decodes it.",
                 encoded_body, "Phone", "Personal Information",
                 "Response Body" if inbound else "Request Body", "inbound" if inbound else "outbound")

    def session_control(inbound=inbound):
        value = credential()
        return request(**{"response_cookies" if inbound else "cookies": {"session": value}}), value
    install_case("control_" + ("response" if inbound else "request") + "_session_cookie",
                 "Existing session-cookie recognition remains supported.", session_control,
                 "Session Cookie", "Authentication", "Response Cookie" if inbound else "Cookie",
                 "inbound" if inbound else "outbound")

    def auth_control(inbound=inbound):
        value = "Bearer " + credential()
        return request(**{"response_headers" if inbound else "headers": {"Authorization": value}}), value
    install_case("control_" + ("response" if inbound else "request") + "_authorization",
                 "Existing Authorization header recognition remains supported.", auth_control,
                 "Authorization Token", "Authentication", "Response Header" if inbound else "Header",
                 "inbound" if inbound else "outbound")


for field, artifact, category in [("X-API-Key", "API Key", "API Credentials"),
                                  ("X-CSRF-Token", "CSRF Token", "Security")]:
    def build(field=field):
        value = credential()
        return request(headers={field: value}), value
    install_case("header_" + field.lower().replace("-", "_"),
                 "analyze header handling only recognizes authorization.",
                 build, artifact, category, "Header")


for position in ("prefix", "suffix"):
    def build(position=position):
        # Whitespace separates words to avoid pathological regex backtracking.
        padding = "ordinary " * 28000
        body = f"Contact: {EMAIL} {padding}" if position == "prefix" else f"{padding} Contact: {EMAIL}"
        return request(response_body=body), EMAIL
    install_case("large_plaintext_email_" + position,
                 "_find_emails returns [] above 250000 characters, even at body edges.",
                 build, "Email", "Personal Information", "Response Body", "inbound")


if __name__ == "__main__":
    unittest.main()
