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

## Current verification

The earlier failure inventory has been resolved. The suite now covers HAR
extraction, multipart and structured bodies, protobuf/gRPC, bounded decoding and
email scanning, policy parsing/comparison, privacy inventory evidence, aggregate
results, dashboard launching, and the synthetic end-to-end application.

Run the current authoritative suite rather than relying on a hard-coded pass
count:

```console
python -m pytest -q
```

No test is intentionally skipped or marked as an expected failure.
