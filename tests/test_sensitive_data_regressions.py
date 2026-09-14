"""Synthetic regression contracts for extraction, detection, and normalization.

Run: python -B -m unittest discover -s tests -v
No captured traffic, files, network, mocks, or production changes are required.
Missing functionality deliberately produces ordinary assertion failures.
Credentials are generated per test and have no association with any service.
"""

import base64
import json
import secrets
import unittest
from urllib.parse import urlencode

from src.analyzer.privacy_normalizer import PrivacyNormalizer
from src.analyzer.sensitive_data_detector import SensitiveDataDetector
from src.models.request import Request
from src.parser.request_extractor import RequestExtractor


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

    # Passing controls prevent fixing false negatives by indiscriminate flagging.
    def test_control_generic_query_exact_email(self):
        self.assert_artifact(extracted({"url": "https://example.test/?" + urlencode({"q": EMAIL})}),
                             "Email", "Personal Information", EMAIL, "Query Parameter")

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
