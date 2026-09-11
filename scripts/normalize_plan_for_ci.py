#!/usr/bin/env python3
"""
CI glue script. Loads a `terraform show -json` plan, runs it through the
same desired_state.normalize() the drift Lambda uses (see ADR 0007 --
one normalizer, used in both places, not two copies that can drift
apart), and writes out a canonical-schema JSON document OPA can evaluate
directly with `opa eval -i normalized.json data.sentinel`.

Also writes the route_table -> db_subnet_map lookup NET-DB-002 needs,
since that relationship (which subnets a given db_instance's subnet
group actually contains) isn't itself a canonical-resource attribute --
it's a join between two resources the caller has to compute once,
rather than something baked into the schema. Keeping it out of the
schema was a deliberate choice: db_subnet_map is CI/runtime-context
data, not a property of either resource on its own.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "drift" / "detector"))
import desired_state  # noqa: E402


def build_db_subnet_map(plan_json: dict) -> dict:
    """Best-effort: only resolvable for db_subnet_group resources whose
    subnet_ids are already known (i.e. not "(known after apply)"). See
    docs/limitations.md for the from-scratch-deployment gap this leaves."""
    subnet_map = {}
    for change in plan_json.get("resource_changes", []):
        if change.get("type") != "aws_db_subnet_group":
            continue
        after = (change.get("change", {}) or {}).get("after") or {}
        subnet_ids = after.get("subnet_ids")
        if not subnet_ids or any("known after apply" in str(s) for s in subnet_ids):
            continue
        # Matching this subnet group back to the db_instance that uses it
        # requires a second pass over aws_db_instance resources referencing
        # this subnet group by name -- left as a TODO because our reference
        # environment only has one db_instance and one subnet group, so a
        # general n-to-n resolver wasn't worth the complexity yet.
        subnet_map[change["address"]] = subnet_ids
    return subnet_map


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, help="path to terraform show -json output")
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    with open(args.plan) as f:
        plan_json = json.load(f)

    resources = desired_state.normalize(plan_json, account_id=args.account_id, region=args.region)
    db_subnet_map = build_db_subnet_map(plan_json)

    output = {
        "resources": resources,
        "db_subnet_map": db_subnet_map,
    }

    with open(args.out, "w") as f:
        json.dump(output, f, indent=2)

    print(f"normalized {len(resources)} resources -> {args.out}")


if __name__ == "__main__":
    main()
