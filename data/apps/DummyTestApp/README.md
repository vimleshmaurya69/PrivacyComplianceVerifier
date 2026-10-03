# Dummy Test App

This is a deliberately synthetic end-to-end validation fixture. It is not a
real application and must not be included in research totals.

Run it with:

```powershell
python main.py --app DummyTestApp
```

The unchanged framework should report:

- `Phone` as **PRACTICE DISCLOSED** and separately flag its URL placement.
- `Email` as **INFORMATION DISCLOSED** because collection is declared but the
  full transmission/recipient practice is not.
- `Device ID` as **POTENTIAL NON-DISCLOSURE** because this synthetic policy
  contains an explicit `VERIFIED_COMPLETE` review record for that exact scope.
- `Latitude` as **INSUFFICIENT POLICY DETAIL**.
- the declared `Authorization Token` as **NOT OBSERVED IN CAPTURE**.
- the declared `Camera` practice as **NOT ASSESSABLE FROM HAR**.
- `compliance_determination` as **NOT DETERMINED**.

The app configuration marks this fixture with `exclude_from_aggregate`, so its
generated output is never included in research totals.
