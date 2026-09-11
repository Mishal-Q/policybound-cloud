"""
Compares two canonical resource snapshots (desired vs observed) and emits
structured divergence events. Operates purely on the canonical schema, so
it has no idea whether the data originally came from Terraform or AWS
Config -- that's the point.
"""

from __future__ import annotations

from typing import Any


def _flatten(d: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dict/list attributes into dotted paths so we can
    diff field-by-field instead of doing a blunt whole-object compare
    (which would flag a divergence any time key ORDER differs, etc.)."""
    out: dict[str, Any] = {}
    if isinstance(d, dict):
        for k, v in d.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(d, list):
        # Order-independent comparison for rule lists: sort by repr.
        normalized = sorted(d, key=lambda x: str(x)) if d and isinstance(d[0], dict) else sorted(d, key=str)
        out[prefix] = normalized
    else:
        out[prefix] = d
    return out


def diff_resource(desired: dict[str, Any], observed: dict[str, Any]) -> list[dict[str, Any]]:
    """Returns a list of field-level divergence events for one resource
    pair. Empty list means no drift."""
    if desired["resource_urn"] != observed["resource_urn"]:
        raise ValueError("diff_resource called on mismatched resource_urn")

    flat_desired = _flatten(desired["attributes"])
    flat_observed = _flatten(observed["attributes"])

    events = []
    all_fields = set(flat_desired) | set(flat_observed)
    for field in sorted(all_fields):
        old = flat_desired.get(field, "<absent>")
        new = flat_observed.get(field, "<absent>")
        if old != new:
            events.append(
                {
                    "resource_urn": desired["resource_urn"],
                    "resource_type": desired["resource_type"],
                    "field_changed": field,
                    "old_value": old,
                    "new_value": new,
                    "managed_by": observed.get("metadata", {}).get("managed_by", "unknown"),
                }
            )
    return events


def diff_snapshots(desired_list: list[dict], observed_list: list[dict]) -> list[dict[str, Any]]:
    """Diffs two full canonical snapshots keyed by resource_urn. Resources
    present in one snapshot but not the other are their own event kind
    (created-out-of-band / deleted-out-of-band) rather than a field diff."""
    desired_by_urn = {r["resource_urn"]: r for r in desired_list}
    observed_by_urn = {r["resource_urn"]: r for r in observed_list}

    events: list[dict[str, Any]] = []

    for urn in desired_by_urn.keys() & observed_by_urn.keys():
        events.extend(diff_resource(desired_by_urn[urn], observed_by_urn[urn]))

    for urn in observed_by_urn.keys() - desired_by_urn.keys():
        r = observed_by_urn[urn]
        events.append(
            {
                "resource_urn": urn,
                "resource_type": r["resource_type"],
                "field_changed": "__resource_existence__",
                "old_value": "<absent>",
                "new_value": "created_out_of_band",
                "managed_by": r.get("metadata", {}).get("managed_by", "unknown"),
            }
        )

    for urn in desired_by_urn.keys() - observed_by_urn.keys():
        r = desired_by_urn[urn]
        events.append(
            {
                "resource_urn": urn,
                "resource_type": r["resource_type"],
                "field_changed": "__resource_existence__",
                "old_value": "expected_to_exist",
                "new_value": "<absent>",
                "managed_by": r.get("metadata", {}).get("managed_by", "unknown"),
            }
        )

    return events
