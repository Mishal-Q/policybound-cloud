"""
Risk classifier for drift events.

Taxonomy (5 states -- see docs/architecture.md for the full decision
diagram):

  OUT_OF_SCOPE   resource isn't managed_by=sentinel-iac; not ours to govern
  BENIGN         metadata-only change (tags/description); no policy relevance
  AUTHORIZED_DRIFT   diverges from desired state but a valid, matching,
                      unexpired, security-approved exception covers it
  POLICY_VIOLATING   diverges and violates a Control, no valid exception
  SECURITY_CRITICAL  POLICY_VIOLATING AND the changed field is in the
                      security-critical set (network exposure, encryption,
                      IAM boundary/trust)
  UNDETERMINED   evidence is incomplete or evaluation itself failed --
                 the system never guesses a classification, it fails
                 closed and asks for human investigation instead

Explicitly the *opposite* of "does this look like drift" -- classification
only ever happens for a real field-level divergence event (see diff.py).
Whether a divergence is *also* a policy violation is delegated to a
`policy_eval` callable so this module stays independent of OPA/Rego.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

SECURITY_CRITICAL_FIELDS = {
    "publicly_accessible",
    "ingress_rules",
    "storage_encrypted",
    "kms_key_arn",
    "permissions_boundary_arn",
    "trust_policy_has_mfa_condition",
    "public_access_block.block_public_acls",
    "public_access_block.block_public_policy",
    "public_access_block.ignore_public_acls",
    "public_access_block.restrict_public_buckets",
    "encryption_algorithm",
}

BENIGN_FIELDS = {"tags", "description", "name_prefix_suffix"}

ACTIONS = {
    "OUT_OF_SCOPE": "log-only",
    "BENIGN": "log-only",
    "AUTHORIZED_DRIFT": "governance-ticket",
    "POLICY_VIOLATING": "propose-remediation-pr",
    "SECURITY_CRITICAL": "propose-remediation-pr+page-on-call",
    "UNDETERMINED": "alert+human-investigation",
}


@dataclass
class Exception_:  # trailing underscore: avoid shadowing builtin
    id: str
    resource_urn: str
    policy_id: str
    approved: bool
    approver_authorized: bool
    expires_at_epoch: int


def _field_is_security_critical(field_changed: str) -> bool:
    base = field_changed.split(".")[0]
    return field_changed in SECURITY_CRITICAL_FIELDS or base in SECURITY_CRITICAL_FIELDS


def _field_is_benign(field_changed: str) -> bool:
    base = field_changed.split(".")[0]
    return base in BENIGN_FIELDS


def exception_covers(
    exc: Optional[Exception_],
    resource_urn: str,
    policy_id: str,
    now_epoch: int,
) -> bool:
    """An exception only authorizes drift if EVERY one of these holds.
    This is what stops the exception mechanism from becoming a bypass:
    matching resource + matching policy + actually approved + approver
    was allowed to approve it + not expired. Missing any one field is a
    fail-closed 'no'."""
    if exc is None:
        return False
    return (
        exc.resource_urn == resource_urn
        and exc.policy_id == policy_id
        and exc.approved
        and exc.approver_authorized
        and now_epoch < exc.expires_at_epoch
    )


def classify(
    event: dict,
    *,
    policy_eval: Callable[[dict], Optional[str]],
    lookup_exception: Callable[[str, str], Optional[Exception_]],
    now_epoch: int,
    evaluation_error: bool = False,
) -> dict:
    """
    event: one divergence event from diff.diff_snapshots()
    policy_eval(event) -> policy_id string if the NEW value violates a
        Control, else None. Raises should be caught by the caller and
        surfaced via evaluation_error=True rather than propagating --
        a policy-engine failure must never silently pass a violation.
    lookup_exception(resource_urn, policy_id) -> matching Exception_ or None
    """
    if evaluation_error:
        return _result(event, "UNDETERMINED", None, reason="policy evaluation failed")

    if event.get("managed_by") not in ("sentinel-iac",):
        return _result(event, "OUT_OF_SCOPE", None, reason="resource not managed by sentinel-iac")

    field = event["field_changed"]

    if field == "__resource_existence__":
        # Existence changes are always at least policy-relevant; never benign.
        violated_policy = policy_eval(event)
        if violated_policy is None:
            return _result(event, "POLICY_VIOLATING", None, reason="unexpected resource existence change")
        return _classify_violation(event, violated_policy, lookup_exception, now_epoch, force_critical=True)

    if _field_is_benign(field):
        return _result(event, "BENIGN", None, reason="metadata-only field")

    violated_policy = policy_eval(event)
    if violated_policy is None:
        return _result(event, "AUTHORIZED_DRIFT", None, reason="diverges but violates no known control")

    return _classify_violation(event, violated_policy, lookup_exception, now_epoch)


def _classify_violation(event, policy_id, lookup_exception, now_epoch, force_critical=False):
    exc = lookup_exception(event["resource_urn"], policy_id)
    if exception_covers(exc, event["resource_urn"], policy_id, now_epoch):
        return _result(event, "AUTHORIZED_DRIFT", policy_id, reason=f"covered by exception {exc.id}")

    critical = force_critical or _field_is_security_critical(event["field_changed"])
    state = "SECURITY_CRITICAL" if critical else "POLICY_VIOLATING"
    return _result(event, state, policy_id, reason="violates control, no valid exception")


def _result(event, classification, policy_id, reason):
    return {
        "resource_urn": event["resource_urn"],
        "field_changed": event["field_changed"],
        "classification": classification,
        "policy_id": policy_id,
        "action": ACTIONS[classification],
        "reason": reason,
    }
