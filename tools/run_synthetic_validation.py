"""Generate outputs for the controlled synthetic validation suite."""

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CASES = (
    "synthetic_disclosed",
    "synthetic_nondisclosure",
    "synthetic_partial_policy",
    "synthetic_url_risk",
    "synthetic_technical",
    "synthetic_limited_capture",
)


def main():
    for case_id in CASES:
        print(f"\n=== Generating {case_id} ===")
        result = subprocess.run(
            [sys.executable, "main.py", "--app", case_id],
            cwd=PROJECT_ROOT,
            check=False,
        )
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
