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
        self.assertEqual([("token", "one"), ("token", "two")], sample.response_cookie_pairs)

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

    def test_preserves_duplicate_query_parameters(self):
        sample = extract({"url": "https://example.test/search?q=one&q=two&empty="})

        self.assertEqual([("q", "one"), ("q", "two"), ("empty", "")], sample.query_param_pairs)
        self.assertEqual({"q": ["one", "two"], "empty": [""]}, sample.query_param_values)
        self.assertEqual({"q": "one", "empty": ""}, sample.query_params)

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


if __name__ == "__main__":
    unittest.main()
