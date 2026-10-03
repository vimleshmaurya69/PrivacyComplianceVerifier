# Privacy Compliance Verification Framework

A college research project that compares sensitive information observed in HAR
network traffic with explicit information-type statements in reviewed privacy
policies. It also reports transmission risks, such as personal data or
credentials appearing in URLs.

## Scope

- Results are capture-scoped: information not observed in one run may still be
  used by the application outside the tested workflow.
- `POTENTIALLY_NON_COMPLIANT` means an observed, policy-comparable information
  type was not found in the reviewed policy representation. It is not a legal
  determination.
- Authorization tokens, session cookies, CSRF/security artifacts, API
  credentials, and unknown artifacts remain technical evidence. The dashboard
  does not treat routine authentication artifacts as privacy-policy gaps.
- URL risk signals are independent from policy disclosure results.

## Running an application analysis

Python 3.10 or newer is recommended. The production framework uses the Python
standard library; `requirements.txt` adds Pytest for repository verification.

```powershell
python -m pip install -r requirements.txt
```

```powershell
python main.py --app Truecaller
python aggregate_results.py
```

Application configuration is stored under `data/apps/<app>/`. Real HAR and
Frida captures are intentionally excluded from Git because they may contain
personal information. Generated results are written to `data/output/` and are
also kept local.

## Dashboard

The dashboard is a local presentation tool. Install its Node dependencies once,
then use the launcher from the repository root:

```powershell
cd dashboard
npm install
cd ..
python run_dashboard.py
```

The dashboard reads local sanitized files from `data/analysis/` and
`data/output/`. It does not expose raw files stored under `data/apps/`.

## Tests

```powershell
python -m pytest -q
cd dashboard
npm run verify
npm run build
```

The tracked `DummyTestApp` HAR is synthetic, contains no real user data, and is
excluded automatically from aggregate research totals.

## Experimental dataset converters

Utilities in `tools/` are separate from the production framework:

- `ovrseen_to_har.py` requires `dpkt==1.9.8` in an isolated environment.
- `parrot_to_har.py` requires an external TShark executable.
- `antshield_to_har.py` uses the Python standard library.

OVRseen, PARROT, AntShield, raw captures, generated outputs, and real HAR files
must remain outside Git.
