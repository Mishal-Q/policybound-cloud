import os
import sys
import time
import yaml
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "remediation"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "classifier"))

from exceptions import load_exceptions, make_lookup, ExceptionValidationError  # noqa: E402
from triage_classifier import classify, exception_covers  # noqa: E402

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "remediation", "exceptions.yaml")


def test_loads_real_exceptions_file():
    exceptions = load_exceptions(FIXTURE_PATH)
    assert len(exceptions) == 2
    ids = {e.id for e in exceptions}
    assert ids == {"EXC-2026-001", "EXC-2026-002"}


def test_cost_exception_from_finance_is_authorized():
    exceptions = load_exceptions(FIXTURE_PATH)
    cost_exc = next(e for e in exceptions if e.id == "EXC-2026-001")
    assert cost_exc.approver_authorized is True


def test_iam_boundary_exception_from_security_is_authorized_but_expired():
    exceptions = load_exceptions(FIXTURE_PATH)
    iam_exc = next(e for e in exceptions if e.id == "EXC-2026-002")
    assert iam_exc.approver_authorized is True
    # This exception's own file comment says it's meant to be expired --
    # verify that against a "now" clearly after its expires_at instead
    # of relying on wall-clock time when the test happens to run.
    now_after_expiry = int(1893456000)  # 2029-12-31, well past 2026-08-01
    assert exception_covers(iam_exc, iam_exc.resource_urn, "IAM-BOUNDARY-001", now_after_expiry) is False


def test_missing_required_field_raises():
    bad_record = {
        "exceptions": [
            {
                "id": "EXC-BAD",
                "resource_urn": "urn:x",
                "policy_id": "COST-001",
                # missing: reason, expires_at, approved_pr_number, approver_team
            }
        ]
    }
    path = "/tmp/bad_exceptions.yaml"
    with open(path, "w") as f:
        yaml.dump(bad_record, f)
    with pytest.raises(ExceptionValidationError):
        load_exceptions(path)


def test_net_db_002_exception_never_authorized_regardless_of_approver():
    record = {
        "exceptions": [
            {
                "id": "EXC-SHOULD-NOT-WORK",
                "resource_urn": "urn:db",
                "policy_id": "NET-DB-002",
                "reason": "someone really wants this",
                "status": "approved",
                "expires_at": "2099-01-01T00:00:00Z",
                "approved_pr_number": 1,
                "approver_team": "security",  # even the right team, still not allowed
            }
        ]
    }
    path = "/tmp/net_db_002_exception.yaml"
    with open(path, "w") as f:
        yaml.dump(record, f)
    exceptions = load_exceptions(path)
    assert exceptions[0].approver_authorized is False


def test_end_to_end_classify_with_real_exceptions_file():
    """Wires the real exceptions.yaml into classify() to prove the whole
    chain (YAML -> Exception_ -> lookup -> classify) behaves the same
    way the standalone classifier tests already proved in isolation."""
    exceptions = load_exceptions(FIXTURE_PATH)
    lookup = make_lookup(exceptions)

    event = {
        "resource_urn": "aws:us-east-1:111111111111:s3_bucket/quarterly-data-export",
        "resource_type": "s3_bucket",
        "field_changed": "instance_class",
        "old_value": "t3.micro",
        "new_value": "t3.xlarge",
        "managed_by": "sentinel-iac",
    }
    result = classify(
        event,
        policy_eval=lambda _e: "COST-001",
        lookup_exception=lookup,
        now_epoch=int(time.mktime(time.strptime("2026-09-06", "%Y-%m-%d"))),
    )
    assert result["classification"] == "AUTHORIZED_DRIFT"
    assert result["reason"].startswith("covered by exception")
