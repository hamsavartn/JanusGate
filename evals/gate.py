"""CI regression gate — fail the build if held-out F1 drops below the floor.

Run:  .venv/Scripts/python.exe -m evals.gate --min-f1 0.9
Reads evals/report.json (written by evals.run_eval).
"""
import argparse
import json
import sys
from pathlib import Path

REPORT_JSON = Path(__file__).parent / "report.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-f1", type=float, default=0.9)
    args = ap.parse_args()

    if not REPORT_JSON.exists():
        print("gate: report.json missing — run `python -m evals.run_eval` first")
        return 2
    data = json.loads(REPORT_JSON.read_text())
    f1 = data.get("held_out", {}).get("full_ensemble", {}).get("f1")
    if f1 is None:
        print("gate: no held-out F1 found in report.json")
        return 2
    if f1 >= args.min_f1:
        print(f"gate: PASS — held-out F1 {f1} >= floor {args.min_f1}")
        return 0
    print(f"gate: FAIL — held-out F1 {f1} < floor {args.min_f1} (detection regressed?)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
