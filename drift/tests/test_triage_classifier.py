import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "classifier"))

from triage_classifier import classify, Exception_  # noqa: E402

NOW = int(time.time())


def base_event(**overrides):
    e = {
        "resource_urn": "aws:us-east-1:111111111111:db_instance/app_db",
        "resource_type": "db_instance",
        "field_changed": "publicly_accessible",
        "old_value": False,
        "new_value": True,
        "managed_by": "sentinel-iac",
    }
    e.update(overrides)
    return e


def no_violation(_event):
    return None


def violates_net_db_001(_event):
    return "NET-DB-001"


def no_exception(_urn, _policy_id):
    return None


def test_out_of_scope_when_not_managed_by_sentinel():
    event = base_event(managed_by="hand-created-by-someone-else")
    result = classify(event, policy_eval=violates_net_db_001, lookup_exception=no_exception, now_epoch=NOW)
    assert result["classification"] == "OUT_OF_SCOPE"
    assert result["action"] == "log-only"


def test_benign_tag_change():
    event = base_event(field_changed="tags.owner", old_value="team-a", new_value="team-b")
    result = classify(event, policy_eval=violates_net_db_001, lookup_exception=no_exception, now_epoch=NOW)
    assert result["classification"] == "BENIGN"


def test_authorized_drift_when_no_policy_violated():
    event = base_event(field_changed="subnet_group", old_value="sg-a", new_value="sg-b")
    result = classify(event, policy_eval=no_violation, lookup_exception=no_exception, now_epoch=NOW)
    assert result["classification"] == "AUTHORIZED_DRIFT"
    assert result["policy_id"] is None


def test_security_critical_when_violation_and_field_is_critical():
    event = base_event()  # publicly_accessible True, which is security-critical
    result = classify(event, policy_eval=violates_net_db_001, lookup_exception=no_exception, now_epoch=NOW)
    assert result["classification"] == "SECURITY_CRITICAL"
    assert result["policy_id"] == "NET-DB-001"
    assert result["action"] == "propose-remediation-pr+page-on-call"


def test_policy_violating_when_field_not_security_critical():
    event = base_event(field_changed="subnet_group", old_value="sg-a", new_value="sg-c")
    result = classify(event, policy_eval=violates_net_db_001, lookup_exception=no_exception, now_epoch=NOW)
    assert result["classification"] == "POLICY_VIOLATING"


def test_authorized_drift_when_valid_exception_covers_violation():
    exc = Exception_(
        id="EXC-1",
        resource_urn="aws:us-east-1:111111111111:db_instance/app_db",
        policy_id="NET-DB-001",
        approved=True,
        approver_authorized=True,
        expires_at_epoch=NOW + 3600,
    )
    event = base_event()
    result = classify(
        event,
        policy_eval=violates_net_db_001,
        lookup_exception=lambda urn, pid: exc,
        now_epoch=NOW,
    )
    assert result["classification"] == "AUTHORIZED_DRIFT"


def test_expired_exception_does_not_authorize():
    exc = Exception_(
        id="EXC-2",
        resource_urn="aws:us-east-1:111111111111:db_instance/app_db",
        policy_id="NET-DB-001",
        approved=True,
        approver_authorized=True,
        expires_at_epoch=NOW - 10,  # already expired
    )
    event = base_event()
    result = classify(
        event,
        policy_eval=violates_net_db_001,
        lookup_exception=lambda urn, pid: exc,
        now_epoch=NOW,
    )
    assert result["classification"] == "SECURITY_CRITICAL"


def test_unauthorized_approver_does_not_authorize():
    exc = Exception_(
        id="EXC-3",
        resource_urn="aws:us-east-1:111111111111:db_instance/app_db",
        policy_id="NET-DB-001",
        approved=True,
        approver_authorized=False,  # approver wasn't allowed to approve this policy
        expires_at_epoch=NOW + 3600,
    )
    event = base_event()
    result = classify(
        event,
        policy_eval=violates_net_db_001,
        lookup_exception=lambda urn, pid: exc,
        now_epoch=NOW,
    )
    assert result["classification"] == "SECURITY_CRITICAL"


def test_undetermined_on_evaluation_error_fails_closed():
    event = base_event()
    result = classify(
        event,
        policy_eval=violates_net_db_001,
        lookup_exception=no_exception,
        now_epoch=NOW,
        evaluation_error=True,
    )
    assert result["classification"] == "UNDETERMINED"
    assert result["action"] == "alert+human-investigation"


def test_resource_existence_change_forces_critical_when_violating():
    event = base_event(field_changed="__resource_existence__", old_value="<absent>", new_value="created_out_of_band")
    result = classify(event, policy_eval=violates_net_db_001, lookup_exception=no_exception, now_epoch=NOW)
    assert result["classification"] == "SECURITY_CRITICAL"
