# Sensitive-data regression contracts

Run from the repository root with Python's standard library:

```console
python -B -m unittest discover -s tests -v
```

The repository had an empty `tests/` directory, no tracked tests or test-runner
configuration, and an empty `requirements.txt` when this suite was introduced.
No new dependency is necessary. `-B` avoids creating Python bytecode caches.

## Scope and assertions

All inputs are synthetic `Request` objects or minimal in-memory extractor inputs.
No HAR file, captured traffic, policy file, network service, or exported report is
read. Credential-like test values are generated at runtime and are never valid
service credentials. Hosts use `example.test`, the phone fixtures use the fictional
202-555-01xx range, and the IP fixture uses the documentation-only 192.0.2.0/24 range.

Every positive contract explicitly specifies both artifact type and privacy
category, as well as value redaction, source, and direction. It exercises the real
`SensitiveDataDetector.analyze()` and `PrivacyNormalizer.normalize()` methods and
checks unique-artifact inventory inclusion and absence of raw values in output.
Expected categories are literal test expectations, not copied at runtime from the
production taxonomy. Negative controls expect no sensitive artifact/category.

Tests use existing taxonomy terms. The `xs` cookie contract expects `Session
Cookie / Authentication`; the `datr` browser identifier contract uses `Device ID /
Device Identifier`. These are application-specific desired detection semantics,
not observations from a real capture. Generic opaque values, numeric counts, and
UUIDs without identifying key context are deliberately not assumed sensitive.
The generic-phone tests use explicit international phone formatting, not bare
ambiguous digit strings.

Matrix cases are installed as individually named unittest methods so a missing
field/transport combination cannot be hidden by another case passing. No tests
are skipped or marked `expectedFailure`. Source and key parsing are not mocked.

## Verified baseline against the unchanged implementation

**65 test methods: 16 pass, 49 fail; 0 errors, 0 skips.** Unittest reports **50
failure records**, because `test_form_json_array_preserves_both_phone_artifacts`
has two failing subtests within one test method. Failures are ordinary missing
artifact assertions, not import errors or unavailable dependencies.

All names below have the `test_` prefix in `test_sensitive_data_regressions.py`.

| Failing tests | Missing behavior and responsible production path |
| --- | --- |
| `form_json_email`, `form_json_phone`, `form_json_device_id`, `form_json_latitude`, `form_json_csrf_token`, `form_json_array_preserves_both_phone_artifacts` | `_extract_body_pairs()` returns form pairs without recursively parsing JSON field values. Raw free-form email scanning cannot recover percent-encoded email values. |
| `query_generic_key_embedded_email` | `analyze()` only calls `_classify_key_value()` for each query value; `_is_email()` requires a whole-value match. |
| `query_generic_key_formatted_phone`, `query_application_contact_point_phone` | `_classify_key_value()` only invokes phone recognition for its recognized phone keys. |
| `query_json_value_phone` | Query values are not recursively parsed as structured data. |
| `query_duplicate_key_retains_later_email` | `RequestExtractor.extract_requests()` retains only `value[0]` for repeated query keys. |
| `request_cookie_*`, `response_cookie_*` (each: `device_id`, `datr`, `access_token`, `xs`, `csrf_token`) | Both cookie branches of `analyze()` only recognize session-related names; they do not use generic field classification or these application-specific aliases. |
| `fb_dtsg_form`, `fb_dtsg_json`, `fb_dtsg_query` | `_classify_key_value()` does not recognize the `fb_dtsg` CSRF alias. |
| `multipart_phone`, `multipart_device_id`, `multipart_csrf_token`, and their `_quoted_boundary` variants | `_extract_body_pairs()` only tries JSON and URL-encoded forms. The extractor labels multipart as binary, and the detector does not use the boundary metadata to parse parts. |
| `nested_compound_key_date_of_birth`, `nested_compound_key_phone_number`, `nested_compound_key_device_id`, `nested_compound_key_api_key`, `nested_compound_key_ip_address` | `_classify_key_value()` splits normalized paths at underscores, losing compound leaf names. Whole-path alias matching also fails; `_looks_like_api_key()` requires a whole-key match. |
| `json_phone_array_preserves_parent_field_context` | `_extract_json_pairs()` appends an array index; `_classify_key_value()` treats that index as the leaf, losing the phone context. |
| `json_string_nested_inside_json_phone` | `_extract_json_pairs()` does not deserialize nested string-valued JSON. |
| `post_data_params_form`, `post_data_params_multipart` | `_extract_request_body()` reads `postData.text` but ignores `postData.params`. |
| `request_raw_cookie_header`, `response_raw_cookie_header` | `_extract_cookies()` reads cookie arrays only; neither extractor nor detector parses raw `Cookie` / `Set-Cookie` headers. These tests use the already-supported `session` name to isolate extraction from alias recognition. |
| `request_base64_json`, `response_base64_json` | The extractor preserves encoding metadata, but the detector never decodes the bodies before parsing. |
| `header_x_api_key`, `header_x_csrf_token` | Header handling in `analyze()` recognizes only `Authorization`. |
| `large_plaintext_email_prefix`, `large_plaintext_email_suffix` | `_find_emails()` returns an empty list above 250,000 characters, even for an email at either edge. These cases specify coverage, not an unbounded-regex implementation. |
| `html_visible_email_is_not_discarded_with_inline_script` | `_analyze_body()` discards an entire non-JSON response when `_looks_like_javascript_source()` matches its inline script, including visible personal data outside the script. |
| `grpc_second_frame_email` | `ProtobufScanner._decode_grpc_frame()` returns only the first frame, so the second frame never reaches string detection. |

## Passing controls

The 15 `control_*` cases preserve existing exact-email query detection, flat form
and nested JSON phone detection, structured large-JSON and small plaintext email
detection, single-frame gRPC detection, request/response Authorization headers,
and request/response session cookies. They also reject benign generic query
values, ordinary cookies, benign multipart fields, source-code identifiers, and
malformed nonsensitive nested JSON.

`nested_compound_key_full_name` also passes: the current implementation reduces
`profile.full_name` to leaf `name`, and the `profile` context is enough to classify
it. It remains a positive control; it was not turned into an artificial failure.

Only test-suite files are added. No production implementation or existing test
expectations are changed. These are desired future behavior contracts, not a
claim that a fix has been implemented.
