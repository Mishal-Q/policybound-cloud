#!/usr/bin/env python3
"""
Runs COST-001 (policies/cost/cost_001.rego) against an Infracost
breakdown. Reuses remediation/exceptions.py to load exceptions the exact
same way the drift Lambda does, so a COST-001 exception approved by
finance covers a PR's cost gate in CI the same way it would cover a
runtime drift classification -- one exception file, one validity check,
used in two places instead of two copies of "is this exception valid"
logic that could disagree with each other.

This intentionally shells out to `opa eval` rather than reimplementing
the delta math in Python, so the CI gate and the Rego policy can never
disagree about what counts as over-threshold -- there is exactly one
place the 25% number is written down.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "drift" / "classifier"))
import exceptions as exceptions_module  # noqa: E402


def load_baseline_cost(infracost_json: dict) -> float:
    # Infracost's pastBreakdown/diff structure varies by version; this
    # reads the field our reference Infracost config actually produces.
    # If the Infracost version emits a different structure, update this
    # field mapping only after verifying it against actual Infracost output.
    return float(infracost_json.get("pastTotalMonthlyCost", 0) or 0)


def load_projected_cost(infracost_json: dict) -> float:
    return float(infracost_json.get("totalMonthlyCost", 0) or 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--infracost", required=True)
    parser.add_argument("--exceptions", required=True)
    parser.add_argument("--policy-dir", required=True)
    parser.add_argument("--absolute-ceiling", type=float, default=200.0)
    parser.add_argument(
        "--resource-urn",
        default=None,
        help="Identifies the PR/change being evaluated, e.g. 'pr/184'. "
        "Required so an exception approved for one PR can't silently cover "
        "an unrelated one -- see the comment in policies/cost/cost_001.rego "
        "for the bug this closes.",
    )
    args = parser.parse_args()

    if not args.resource_urn:
        print("ERROR: --resource-urn is required (e.g. 'pr/<number>'). "
              "Without it there is nothing to scope an exception match "
              "against, and this gate must not silently pass.", file=sys.stderr)
        sys.exit(2)

    with open(args.infracost) as f:
        infracost_json = json.load(f)

    baseline = load_baseline_cost(infracost_json)
    projected = load_projected_cost(infracost_json)

    exc_records = exceptions_module.load_exceptions(args.exceptions)
    now = int(time.time())
    exceptions_for_opa = [
        {
            "policy_id": e.policy_id,
            "resource_urn": e.resource_urn,
            "approved": e.approved,
            "approver_authorized": e.approver_authorized,
            "expires_at_epoch": e.expires_at_epoch,
        }
        for e in exc_records
    ]

    opa_input = {
        "cost": {
            "baseline_monthly_usd": baseline,
            "projected_monthly_usd": projected,
            "absolute_ceiling_usd": args.absolute_ceiling,
            "resource_urn": args.resource_urn,
        },
        "exceptions": exceptions_for_opa,
        "context": {"evaluation_time_ns": now * 1_000_000_000},
    }

    proc = subprocess.run(
        ["opa", "eval", "-d", args.policy_dir, "-I", "-f", "json", "data.sentinel.cost.cost_001.deny"],
        input=json.dumps(opa_input),
        capture_output=True,
        text=True,
    )

    if proc.returncode != 0:
        print("opa eval failed:", proc.stderr, file=sys.stderr)
        sys.exit(1)

    result = json.loads(proc.stdout)
    deny_messages = result.get("result", [{}])[0].get("expressions", [{}])[0].get("value", [])

    delta_pct = ((projected - baseline) / baseline * 100) if baseline > 0 else float("inf")
    print(f"baseline=${baseline:.2f} projected=${projected:.2f} delta={delta_pct:.1f}%")

    if deny_messages:
        for msg in deny_messages:
            print(f"FAIL  {msg}")
        sys.exit(1)

    print("COST-001: within threshold or covered by a valid exception.")
    sys.exit(0)


if __name__ == "__main__":
    main()
