import unittest

from src.parser.request_extractor import RequestExtractor


def extract(request_fields=None, response_fields=None):
    request = {
        "method": "POST",
        "url": "https://example.test/submit",
    }
    response = {"status": 200}
    request.update(request_fields or {})
    response.update(response_fields or {})
    return RequestExtractor({"log": {"entries": [{
        "request": request,
        "response": response,
    }]}}).extract_requests()[0]


class RequestExtractorTests(unittest.TestCase):

    def test_preserves_duplicate_headers_and_har_cookies(self):
        sample = extract(
            {"headers": [
                {"name": "X-Trace", "value": "one"},
                {"name": "X-Trace", "value": "two"},
            ], "cookies": [
                {"name": "session", "value": "one"},
                {"name": "session", "value": "two"},
            ]},
            {"headers": [
                {"name": "Set-Cookie", "value": "a=one"},
                {"name": "Set-Cookie", "value": "a=two"},
            ], "cookies": [
                {"name": "token", "value": "one"},
                {"name": "token", "value": "two"},
            ]},
        )

        self.assertEqual([("X-Trace", "one"), ("X-Trace", "two")], sample.header_pairs)
        self.assertEqual("two", sample.headers["X-Trace"])
        self.assertEqual([("session", "one"), ("session", "two")], sample.cookie_pairs)
        self.assertEqual([("Set-Cookie", "a=one"), ("Set-Cookie", "a=two")], sample.response_header_pairs)
        self.assertEqual([
            ("token", "one"),
            ("token", "two"),
            ("a", "one"),
            ("a", "two"),
        ], sample.response_cookie_pairs)

    def test_parses_raw_cookie_headers_when_har_cookie_arrays_are_absent(self):
        sample = extract(
            {"headers": [{"name": "Cookie", "value": "a=one; a=two; theme=dark"}]},
            {"headers": [
                {"name": "Set-Cookie", "value": "sid=one; Path=/"},
                {"name": "Set-Cookie", "value": "sid=two; Expires=Wed, 21 Oct 2015 07:28:00 GMT"},
            ]},
        )

        self.assertEqual([("a", "one"), ("a", "two"), ("theme", "dark")], sample.cookie_pairs)
        self.assertEqual("two", sample.cookies["a"])
        self.assertEqual([("sid", "one"), ("sid", "two")], sample.response_cookie_pairs)
        self.assertEqual("two", sample.response_cookies["sid"])

    def test_merges_partial_har_cookie_arrays_with_raw_headers(self):
        sample = extract(
            {
                "headers": [{
                    "name": "Cookie",
                    "value": "theme=dark; xs=first; xs=second; duplicate=same; duplicate=same",
                }],
                "cookies": [
                    {"name": "theme", "value": "dark"},
                    {"name": "duplicate", "value": "same"},
                ],
            },
            {
                "headers": [
                    {"name": "Set-Cookie", "value": "theme=light; Path=/"},
                    {"name": "Set-Cookie", "value": "sid=one; HttpOnly"},
                    {"name": "Set-Cookie", "value": "sid=two; HttpOnly"},
                ],
                "cookies": [{"name": "theme", "value": "light"}],
            },
        )

        self.assertEqual([
            ("theme", "dark"),
            ("duplicate", "same"),
            ("xs", "first"),
            ("xs", "second"),
            ("duplicate", "same"),
        ], sample.cookie_pairs)
        self.assertEqual("second", sample.cookies["xs"])
        self.assertEqual([
            ("theme", "light"),
            ("sid", "one"),
            ("sid", "two"),
        ], sample.response_cookie_pairs)
        self.assertEqual("two", sample.response_cookies["sid"])

    def test_preserves_duplicate_query_parameters(self):
        sample = extract({"url": "https://example.test/search?q=one&q=two&empty="})

        self.assertEqual([("q", "one"), ("q", "two"), ("empty", "")], sample.query_param_pairs)
        self.assertEqual({"q": ["one", "two"], "empty": [""]}, sample.query_param_values)
        self.assertEqual({"q": "one", "empty": ""}, sample.query_params)

    def test_merges_har_query_string_by_occurrence(self):
        sample = extract({
            "url": "https://example.test/search?q=one&q=one",
            "queryString": [
                {"name": "q", "value": "one"},
                {"name": "q", "value": "one"},
                {"name": "q", "value": "array-only"},
                {"name": "device_id", "value": "params-only"},
            ],
        })

        self.assertEqual([
            ("q", "one"),
            ("q", "one"),
            ("q", "array-only"),
            ("device_id", "params-only"),
        ], sample.query_param_pairs)

    def test_extracts_post_data_params_without_text(self):
        sample = extract({"postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "phone", "value": "111"},
                {"name": "phone", "value": "222"},
            ],
        }})

        self.assertIsNone(sample.body)
        self.assertEqual([("phone", "111"), ("phone", "222")], sample.body_param_pairs)
        self.assertEqual("form", sample.body_type)

    def test_merges_post_data_params_with_text_by_occurrence(self):
        sample = extract({"postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "text": "theme=dark&phone=111&phone=111",
            "params": [
                {"name": "theme", "value": "dark"},
                {"name": "phone", "value": "111"},
                {"name": "phone", "value": "111"},
                {"name": "phone", "value": "222"},
                {"name": "device_id", "value": "params-only"},
            ],
        }})

        self.assertEqual("theme=dark&phone=111&phone=111", sample.body)
        self.assertEqual([
            ("phone", "222"),
            ("device_id", "params-only"),
        ], sample.body_param_pairs)

    def test_reconciles_params_using_header_content_type_fallback(self):
        sample = extract({
            "headers": [{
                "name": "Content-Type",
                "value": "application/x-www-form-urlencoded",
            }],
            "postData": {
                "text": "phone=111",
                "params": [
                    {"name": "phone", "value": "111"},
                    {"name": "device_id", "value": "params-only"},
                ],
            },
        })

        self.assertEqual("application/x-www-form-urlencoded", sample.content_type)
        self.assertEqual([("device_id", "params-only")], sample.body_param_pairs)

    def test_preserves_base64_body_encoding_metadata(self):
        sample = extract(
            {"postData": {
                "mimeType": "application/json",
                "encoding": "base64",
                "text": "eyJwaG9uZSI6IjEyMyJ9",
            }},
            {"content": {
                "mimeType": "application/json",
                "encoding": "base64",
                "text": "eyJwaG9uZSI6IjQ1NiJ9",
            }},
        )

        self.assertEqual("base64", sample.body_encoding)
        self.assertEqual("base64", sample.response_body_encoding)
        self.assertEqual("eyJwaG9uZSI6IjEyMyJ9", sample.body)
        self.assertEqual("eyJwaG9uZSI6IjQ1NiJ9", sample.response_body)

    def test_extracts_raw_protobuf_request_body(self):
        body = "\x0a\x08ordinary"
        sample = extract({"postData": {
            "mimeType": "application/x-protobuf",
            "text": body,
        }})

        self.assertEqual(body, sample.body)
        self.assertEqual("application/x-protobuf", sample.content_type)
        self.assertEqual("binary", sample.body_type)

    def test_extracts_http_toolkit_base64_request_content(self):
        body = "CghvcmRpbmFyeQ=="
        sample = extract({
            "headers": [{
                "name": "Content-Type",
                "value": "application/x-protobuf",
            }],
            "_content": {
                "text": body,
                "size": 10,
                "encoding": "base64",
            },
        })

        self.assertEqual(body, sample.body)
        self.assertEqual("base64", sample.body_encoding)
        self.assertEqual("application/x-protobuf", sample.content_type)
        self.assertEqual("binary", sample.body_type)

    def test_post_data_text_takes_precedence_over_toolkit_content(self):
        sample = extract({
            "postData": {
                "mimeType": "application/json",
                "text": '{"source":"postData"}',
            },
            "_content": {
                "text": "ignored",
                "encoding": "base64",
            },
        })

        self.assertEqual('{"source":"postData"}', sample.body)
        self.assertIsNone(sample.body_encoding)

    def test_extracts_raw_protobuf_response_body_and_encoding(self):
        body = "CghvcmRpbmFyeQ=="
        sample = extract(response_fields={"content": {
            "mimeType": "application/x-protobuf",
            "encoding": "base64",
            "text": body,
        }})

        self.assertEqual(body, sample.response_body)
        self.assertEqual("application/x-protobuf", sample.response_content_type)
        self.assertEqual("binary", sample.response_body_type)
        self.assertEqual("base64", sample.response_body_encoding)


if __name__ == "__main__":
    unittest.main()
