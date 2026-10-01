import json

from src.exporter.json_exporter import JSONExporter
from src.models.request import Request


def test_classified_request_export_redacts_raw_traffic(tmp_path):
    secret = "synthetic-secret-value"
    sample = Request(
        method="POST",
        url=f"https://api.example.test/private/{secret}?token={secret}",
        domain="api.example.test",
        status=200,
        mime_type="application/json",
        headers={"Authorization": secret},
        header_pairs=[("Authorization", secret), ("X-Trace", secret)],
        query_params={"token": secret},
        query_param_pairs=[("token", secret), ("token", secret)],
        query_param_values={"token": [secret, secret]},
        body=f'{{"token":"{secret}"}}',
        body_param_pairs=[("token", secret)],
        cookies={"session": secret},
        cookie_pairs=[("session", secret)],
        response_headers={"Set-Cookie": secret},
        response_header_pairs=[("Set-Cookie", secret)],
        response_cookies={"session": secret},
        response_cookie_pairs=[("session", secret)],
        response_body=secret,
        sensitive_data=[{
            "type": "Authorization Token",
            "source": "Header",
            "direction": "outbound",
            "key": "Authorization",
            "value_redacted": "sy...ue",
            "privacy_category": "Authentication",
            "domain": "api.example.test",
            "traffic_type": "Application",
        }],
    )

    JSONExporter(tmp_path).export_requests([sample])
    exported_text = (tmp_path / "classified_requests.json").read_text(
        encoding="utf-8"
    )
    exported = json.loads(exported_text)[0]

    assert secret not in exported_text
    assert exported["url"] == "https://api.example.test/"
    assert exported["headers"]["Authorization"] == "[REDACTED]"
    assert exported["query_param_pairs"] == [
        ["token", "[REDACTED]"],
        ["token", "[REDACTED]"],
    ]
    assert exported["body"] == "[REDACTED]"
    assert exported["response_body"] == "[REDACTED]"
    assert exported["sensitive_data"][0]["value_redacted"] == "sy...ue"
    assert exported["raw_fields_redacted"] is True


def test_export_strips_url_userinfo_and_value_shaped_evidence_keys(tmp_path):
    email = "person@example.test"
    sample = Request(
        method="GET",
        url="https://person:secret@example.test/private",
        domain="example.test",
        status=200,
        mime_type="text/plain",
        query_params={email: "ordinary"},
        query_param_pairs=[(email, "ordinary")],
        query_param_values={email: ["ordinary"]},
        sensitive_data=[{
            "type": "Email",
            "source": "Request Body",
            "direction": "outbound",
            "key": email,
            "value_redacted": "pe...st",
        }],
    )

    exporter = JSONExporter(tmp_path)
    exporter.export_requests([sample])
    exported_text = (tmp_path / "classified_requests.json").read_text(
        encoding="utf-8"
    )
    exported = json.loads(exported_text)[0]

    assert "person:secret" not in exported_text
    assert email not in exported_text
    assert exported["url"] == "https://example.test/"
    assert exported["sensitive_data"][0]["key"] == "[REDACTED_DYNAMIC_KEY]"
