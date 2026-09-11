"""
Tests for the region/tags/encryption_key_ref additions to both
normalizers (Phase 3A/3B/4 of the Azure cross-cloud work). These exist
specifically to prove the ordering bug caught while writing
desired_state.py doesn't come back: region and tags must be populated
BEFORE missing_required_fields() runs, not after, since both are part of
every resource type's contract now.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))

import desired_state  # noqa: E402
import aws_normalizer  # noqa: E402


def test_desired_state_populates_region_and_tags():
    plan = {
        "resource_changes": [
            {
                "address": "aws_db_instance.app_db",
                "type": "aws_db_instance",
                "change": {
                    "after": {
                        "publicly_accessible": False,
                        "storage_encrypted": True,
                        "kms_key_id": "arn:aws:kms:us-east-1:111111111111:key/abc",
                        "db_subnet_group_name": "data",
                        "tags": {"ManagedBy": "sentinel-iac", "owner": "team-a"},
                    }
                },
            }
        ]
    }
    resources = desired_state.normalize(plan, account_id="111111111111", region="us-east-1")
    assert len(resources) == 1
    attrs = resources[0]["attributes"]
    assert attrs["region"] == "us-east-1"
    assert attrs["tags"] == {"ManagedBy": "sentinel-iac", "owner": "team-a"}


def test_desired_state_encryption_key_ref_mirrors_kms_key_arn():
    plan = {
        "resource_changes": [
            {
                "address": "aws_db_instance.app_db",
                "type": "aws_db_instance",
                "change": {
                    "after": {
                        "publicly_accessible": False,
                        "storage_encrypted": True,
                        "kms_key_id": "arn:aws:kms:us-east-1:111111111111:key/abc",
                        "db_subnet_group_name": "data",
                        "tags": {},
                    }
                },
            }
        ]
    }
    resources = desired_state.normalize(plan, account_id="111111111111", region="us-east-1")
    attrs = resources[0]["attributes"]
    assert attrs["encryption_key_ref"] == attrs["kms_key_arn"]
    assert attrs["encryption_key_ref"] == "arn:aws:kms:us-east-1:111111111111:key/abc"


def test_desired_state_missing_tags_key_does_not_drop_resource():
    """Terraform's 'after' block can legitimately omit tags entirely
    (untagged resource) -- that should normalize to an empty tags dict,
    not silently drop the whole resource the way a missing REQUIRED
    field would."""
    plan = {
        "resource_changes": [
            {
                "address": "aws_db_instance.untagged",
                "type": "aws_db_instance",
                "change": {
                    "after": {
                        "publicly_accessible": False,
                        "storage_encrypted": True,
                        "kms_key_id": "arn:x",
                        "db_subnet_group_name": "data",
                        # no "tags" key at all
                    }
                },
            }
        ]
    }
    resources = desired_state.normalize(plan, account_id="111111111111", region="us-east-1")
    assert len(resources) == 1
    assert resources[0]["attributes"]["tags"] == {}


def test_security_group_also_gets_region_and_tags():
    """Not just db_instance -- every resource type must get region/tags,
    since GOV-REGION-001/GOV-TAG-001 evaluate any resource type."""
    plan = {
        "resource_changes": [
            {
                "address": "aws_security_group.app",
                "type": "aws_security_group",
                "change": {
                    "after": {
                        "ingress": [],
                        "egress": [],
                        "vpc_id": "vpc-1",
                        "tags": {"ManagedBy": "sentinel-iac"},
                    }
                },
            }
        ]
    }
    resources = desired_state.normalize(plan, account_id="111111111111", region="us-east-1")
    assert len(resources) == 1
    assert resources[0]["attributes"]["region"] == "us-east-1"
    assert resources[0]["attributes"]["tags"] == {"ManagedBy": "sentinel-iac"}
    # security_group has no encryption_key_ref in its contract -- confirm
    # it's genuinely absent, not silently set to None, since only
    # db_instance/s3_bucket carry that field.
    assert "encryption_key_ref" not in resources[0]["attributes"]


def test_aws_normalizer_populates_region_and_tags():
    ci = {
        "resourceType": "AWS::RDS::DBInstance",
        "awsRegion": "us-west-2",
        "accountId": "222222222222",
        "resourceId": "db-abc123",
        "tags": [{"key": "ManagedBy", "value": "sentinel-iac"}, {"key": "owner", "value": "team-b"}],
        "configuration": {
            "publiclyAccessible": False,
            "storageEncrypted": True,
            "kmsKeyId": "arn:aws:kms:us-west-2:222222222222:key/def",
            "dbSubnetGroup": {"dbSubnetGroupName": "data-subnets"},
        },
    }
    resource = aws_normalizer.normalize_one(ci)
    assert resource is not None
    attrs = resource["attributes"]
    assert attrs["region"] == "us-west-2"
    assert attrs["tags"] == {"ManagedBy": "sentinel-iac", "owner": "team-b"}
    assert attrs["encryption_key_ref"] == "arn:aws:kms:us-west-2:222222222222:key/def"
    assert attrs["encryption_key_ref"] == attrs["kms_key_arn"]


def test_aws_normalizer_missing_region_falls_back_to_unknown_not_dropped():
    """awsRegion absent from a Config item is unusual but not fatal --
    normalize_one() should still emit the resource with region='unknown'
    rather than dropping it, since 'unknown' is itself useful signal to
    GOV-REGION-001 (an unknown region should fail an approved-region
    check, not silently vanish from evaluation)."""
    ci = {
        "resourceType": "AWS::RDS::DBInstance",
        "accountId": "222222222222",
        "resourceId": "db-abc123",
        "tags": [],
        "configuration": {
            "publiclyAccessible": False,
            "storageEncrypted": True,
            "kmsKeyId": "arn:x",
            "dbSubnetGroup": {"dbSubnetGroupName": "data-subnets"},
        },
    }
    resource = aws_normalizer.normalize_one(ci)
    assert resource is not None
    assert resource["attributes"]["region"] == "unknown"
