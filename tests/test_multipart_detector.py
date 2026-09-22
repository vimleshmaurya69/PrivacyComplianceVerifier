import json

from src.analyzer.sensitive_data_detector import SensitiveDataDetector
from src.models.request import Request


def main():
    boundary = "----WebKitFormBoundaryTest123"

    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="contact_point"\r\n'
        "\r\n"
        "9372558849\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="payload"\r\n'
        "Content-Type: application/json\r\n"
        "\r\n"
        '{"email":"nested@example.com","contact_point":"9876543210"}\r\n'
        f"--{boundary}--\r\n"
    )

    request = Request(
        method="POST",
        url="https://example.com/upload",
        domain="example.com",
        status=200,
        mime_type="multipart/form-data",
        headers={
            "Content-Type": f'multipart/form-data; boundary="{boundary}"'
        },
        query_params={},
        body=body,
        cookies={},
        response_headers={},
        response_cookies={},
        response_body=None,
        body_type="multipart",
        content_type=f'multipart/form-data; boundary="{boundary}"',
    )
    detector = SensitiveDataDetector([request])
    print(
        "Multipart pairs:",
        detector._extract_multipart_pairs(body, request.content_type)
    )

    pairs = detector._extract_multipart_pairs(body, request.content_type)

    for key, value in pairs:
        print(
            "CLASSIFY:",
            key,
            value,
            "=>",
            detector._classify_key_value(key, value)
        )

        signal_findings = []
        detector._analyze_text_signals(
            value,
            signal_findings,
            "Request Body",
            key
        )
        print("SIGNALS:", signal_findings)

    detector.analyze()

    findings = request.sensitive_data

    print("Findings:")
    for finding in findings:
        print(finding)

    types = [finding["type"] for finding in findings]

    assert "Phone" in types, "Multipart phone was not detected"
    assert "Email" in types, "Embedded JSON email was not detected"

    # Make sure raw sensitive values never escape.
    for finding in findings:
        assert "_raw_value" not in finding

    print("\nSTAGE 4 MULTIPART REGRESSION PASS")


if __name__ == "__main__":
    main()