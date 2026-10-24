# Controlled Synthetic Validation Suite

These six fixtures validate known framework outcomes with deliberately
constructed HAR traffic and policy documents. They are not real applications
and are excluded from `master_results.json` by `exclude_from_aggregate: true`.

| Folder | Scenario | Expected dashboard result |
| --- | --- | --- |
| `synthetic_disclosed` | Observed email and latitude are explicitly disclosed | All comparable types disclosed |
| `synthetic_nondisclosure` | Contact phone upload is absent from a completely reviewed policy | Potentially non-compliant |
| `synthetic_partial_policy` | User ID is observed but the policy review is incomplete | Cannot determine |
| `synthetic_url_risk` | Phone is disclosed but placed in a URL | Disclosed with a separate URL risk |
| `synthetic_technical` | Authorization token is visible in a header | Technical evidence; no dashboard policy gap |
| `synthetic_limited_capture` | Policy declares email but the HAR has no requests | Cannot determine / not observed |

Generate all controlled-validation outputs with:

```powershell
python tools/run_synthetic_validation.py
```

Run one fixture with:

```powershell
python main.py --app synthetic_disclosed
```

Recommended demonstration order:

1. Controlled synthetic validation.
2. External public datasets (AntShield, PARROT and OVRseen samples).
3. Original 30-app captured dataset.
