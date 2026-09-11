import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))

from diff import diff_resource, diff_snapshots  # noqa: E402


def make_resource(urn, publicly_accessible=False, ingress=None, tag_owner="team-a"):
    return {
        "resource_urn": urn,
        "resource_type": "db_instance",
        "attributes": {
            "publicly_accessible": publicly_accessible,
            "storage_encrypted": True,
            "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/abc",
            "subnet_group": "data-tier",
        },
        "metadata": {"managed_by": "sentinel-iac", "tags": {"owner": tag_owner}},
    }


def test_no_drift_when_identical():
    r = make_resource("urn:a")
    assert diff_resource(r, r) == []


def test_detects_single_field_divergence():
    desired = make_resource("urn:a", publicly_accessible=False)
    observed = make_resource("urn:a", publicly_accessible=True)
    events = diff_resource(desired, observed)
    assert len(events) == 1
    assert events[0]["field_changed"] == "publicly_accessible"
    assert events[0]["old_value"] is False
    assert events[0]["new_value"] is True


def test_raises_on_mismatched_urn():
    a = make_resource("urn:a")
    b = make_resource("urn:b")
    try:
        diff_resource(a, b)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_snapshot_diff_detects_out_of_band_creation():
    desired = []
    observed = [make_resource("urn:new")]
    events = diff_snapshots(desired, observed)
    assert len(events) == 1
    assert events[0]["field_changed"] == "__resource_existence__"
    assert events[0]["new_value"] == "created_out_of_band"


def test_snapshot_diff_detects_missing_expected_resource():
    desired = [make_resource("urn:gone")]
    observed = []
    events = diff_snapshots(desired, observed)
    assert len(events) == 1
    assert events[0]["new_value"] == "<absent>"


def test_ingress_rule_list_order_independence():
    r1 = {
        "resource_urn": "urn:sg",
        "resource_type": "security_group",
        "attributes": {"ingress_rules": [{"port": 443}, {"port": 22}], "egress_rules": [], "vpc_id": "vpc-1"},
        "metadata": {"managed_by": "sentinel-iac"},
    }
    r2 = {
        "resource_urn": "urn:sg",
        "resource_type": "security_group",
        "attributes": {"ingress_rules": [{"port": 22}, {"port": 443}], "egress_rules": [], "vpc_id": "vpc-1"},
        "metadata": {"managed_by": "sentinel-iac"},
    }
    # Same rules, different order -> should NOT be flagged as drift.
    assert diff_resource(r1, r2) == []
