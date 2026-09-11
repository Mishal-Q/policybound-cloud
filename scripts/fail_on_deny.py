#!/usr/bin/env python3
"""
Reads the JSON output of `opa eval -f json data.sentinel` and fails the
build with an exit code and a readable message if any package's `deny`
set is non-empty. This exists because opa eval's raw JSON output is not
something a CI log should force a human to parse by hand -- the whole
point of naming every policy (see policy-metadata/catalog.yaml) is that
a failed build should say "NET-DB-001: ..." not "job failed, see logs."
"""
import json
import sys


def _find_deny_lists(node, path=""):
    """Recursively walks the OPA eval value tree looking for `deny` keys
    at any depth -- packages nest as category.policy_id (e.g.
    sentinel.network.net_db_001), which is two levels below the
    `data.sentinel` root we evaluate against, not one. The first version
    of this script assumed one level and silently reported "all passed"
    on a real, confirmed NET-DB-001 violation until this was caught by
    testing it against actual opa eval output instead of trusting the
    shape I assumed it had."""
    if isinstance(node, dict):
        if "deny" in node and isinstance(node["deny"], list):
            for msg in node["deny"]:
                yield path, msg
        for key, value in node.items():
            if key == "deny":
                continue
            yield from _find_deny_lists(value, f"{path}.{key}" if path else key)


def main():
    if len(sys.argv) != 2:
        print("usage: fail_on_deny.py <opa-eval-output.json>", file=sys.stderr)
        sys.exit(2)

    with open(sys.argv[1]) as f:
        data = json.load(f)

    results = data.get("result", [])
    if not results:
        print("No OPA evaluation result -- treating as a failure, not a silent pass.")
        sys.exit(1)

    expressions = results[0].get("expressions", [])
    if not expressions:
        print("OPA returned no expressions -- treating as a failure, not a silent pass.")
        sys.exit(1)

    value = expressions[0].get("value", {})
    total_violations = 0

    for package_path, msg in _find_deny_lists(value):
        print(f"FAIL  [{package_path}]  {msg}")
        total_violations += 1

    if total_violations == 0:
        print("All organizational invariants passed.")
        sys.exit(0)

    print(f"\n{total_violations} policy violation(s). See named failures above.")
    sys.exit(1)


if __name__ == "__main__":
    main()
