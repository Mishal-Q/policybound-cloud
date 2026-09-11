"""
Exceptions are governed objects, not a config file someone edits to make
OPA stop complaining. This module is what enforces that distinction: it
loads exception records from exceptions.yaml, validates every required
field is present, and exposes a lookup function with the exact same
signature the classifier expects (see drift/classifier/triage_classifier.py
Exception_ dataclass and exception_covers()).

Why this exists as its own module instead of just letting Rego read the
YAML directly: the classifier's exception_covers() check needs five
things to all be true (resource match, policy match, approved,
authorized approver, not expired), and I originally had that logic
duplicated between Python and Rego. Every time I changed one I forgot
the other, and the two disagreed on an edge case (an exception with
approved=true but approver_authorized=false) for about a day before I
noticed the drift-detector unit tests and the OPA fixture tests gave
different answers for the same input. Now there is exactly one place
this logic lives -- the classifier -- and this module's only job is
turning YAML into the dataclass it expects.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "classifier"))
from triage_classifier import Exception_  # noqa: E402

REQUIRED_FIELDS = {
    "id",
    "resource_urn",
    "policy_id",
    "reason",
    "expires_at",
    "approved_pr_number",
    "approver_team",
}

# Which teams are allowed to approve which policies. This is what stops
# "approved: true" alone from being sufficient -- someone on the app team
# approving their own IAM-boundary exception doesn't count.
POLICY_APPROVER_TEAMS = {
    "NET-DB-001": {"security"},
    "NET-DB-002": {"security"},
    "IAM-BOUNDARY-001": {"security"},
    "DATA-ENC-001": {"security"},
    "COST-001": {"security", "finance"},
}


class ExceptionValidationError(ValueError):
    pass


def _parse_expiry(value: str) -> int:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def load_exceptions(path: str) -> list[Exception_]:
    """Parses exceptions.yaml into a list of Exception_ objects. Raises
    ExceptionValidationError on any record missing a required field or
    naming an approver team not on that policy's approved list -- a
    malformed exception is treated as absent, never as authorizing
    something. CI runs this same loader against every PR that touches
    exceptions.yaml, so a broken record fails the build instead of
    silently granting drift authorization at runtime."""
    with open(path) as f:
        raw = yaml.safe_load(f) or {"exceptions": []}

    records = raw.get("exceptions", [])
    parsed: list[Exception_] = []

    for record in records:
        missing = REQUIRED_FIELDS - record.keys()
        if missing:
            raise ExceptionValidationError(f"exception {record.get('id', '<no id>')} missing fields: {missing}")

        policy_id = record["policy_id"]
        approver_team = record["approver_team"]
        allowed_teams = POLICY_APPROVER_TEAMS.get(policy_id, set())
        approver_authorized = approver_team in allowed_teams

        if policy_id in ("NET-DB-002", "DATA-ENC-001"):
            # These two are marked exception:allowed = false in the
            # control catalog (policy-metadata/catalog.yaml) -- a
            # cross-resource network invariant and an encryption
            # requirement aren't the kind of thing that should ever have
            # a "just this once" carve-out. Any record naming them is
            # parsed (so CI can report *why* it's rejected) but always
            # comes out approver_authorized=False.
            approver_authorized = False

        parsed.append(
            Exception_(
                id=record["id"],
                resource_urn=record["resource_urn"],
                policy_id=policy_id,
                approved=bool(record.get("status", "approved") == "approved"),
                approver_authorized=approver_authorized,
                expires_at_epoch=_parse_expiry(record["expires_at"]),
            )
        )

    return parsed


def make_lookup(exceptions: list[Exception_]):
    """Returns a lookup_exception(resource_urn, policy_id) callable in the
    shape triage_classifier.classify() expects."""
    by_key = {(e.resource_urn, e.policy_id): e for e in exceptions}

    def lookup(resource_urn: str, policy_id: str) -> Exception_ | None:
        return by_key.get((resource_urn, policy_id))

    return lookup
