"""
Observed-state normalizer.

Input: an AWS Config "configurationItem" dict (the shape returned by
boto3 config.get_resource_config_history / select_resource_config, or
delivered via the Config -> EventBridge -> Lambda fast path).
Output: same canonical schema as desired_state.normalize().

AWS Config's field names/casing (ipPermissions, cidrIp, kmsKeyId ARNs
buried under different keys per resource type, etc.) are intentionally
never allowed past this module. Everything downstream -- the diff,
the classifier, OPA -- only ever sees the canonical schema.
"""

from __future__ import annotations

from typing import Any

from schema import CanonicalResource, missing_required_fields


def _extract_security_group(ci: dict[str, Any]) -> dict[str, Any]:
    cfg = ci.get("configuration", {})

    def _rule(p: dict) -> dict:
        return {
            "protocol": p.get("ipProtocol"),
            "from_port": p.get("fromPort"),
            "to_port": p.get("toPort"),
            "cidr_blocks": sorted(r.get("cidrIp") for r in p.get("ipv4Ranges", []) if r.get("cidrIp")),
            "source_security_group_ids": sorted(
                g.get("groupId") for g in p.get("userIdGroupPairs", []) if g.get("groupId")
            ),
        }

    return {
        "ingress_rules": [_rule(p) for p in cfg.get("ipPermissions", [])],
        "egress_rules": [_rule(p) for p in cfg.get("ipPermissionsEgress", [])],
        "vpc_id": cfg.get("vpcId", "unknown"),
    }


def _extract_db_instance(ci: dict[str, Any]) -> dict[str, Any]:
    cfg = ci.get("configuration", {})
    return {
        "publicly_accessible": cfg.get("publiclyAccessible", False),
        "storage_encrypted": cfg.get("storageEncrypted", False),
        "kms_key_arn": cfg.get("kmsKeyId"),
        "subnet_group": (cfg.get("dbSubnetGroup", {}) or {}).get("dbSubnetGroupName", "unknown"),
    }


def _extract_s3_bucket(ci: dict[str, Any]) -> dict[str, Any]:
    supp = ci.get("supplementaryConfiguration", {})
    sse_cfg = supp.get("ServerSideEncryptionConfiguration", {}) or {}
    rules = sse_cfg.get("rules", [{}])
    default = (rules[0] if rules else {}).get("applyServerSideEncryptionByDefault", {}) or {}
    pab = supp.get("PublicAccessBlockConfiguration", {}) or {}
    return {
        "encryption_algorithm": default.get("sseAlgorithm", "NONE"),
        "kms_key_arn": default.get("kmsMasterKeyID"),
        "public_access_block": {
            "block_public_acls": pab.get("blockPublicAcls", False),
            "block_public_policy": pab.get("blockPublicPolicy", False),
            "ignore_public_acls": pab.get("ignorePublicAcls", False),
            "restrict_public_buckets": pab.get("restrictPublicBuckets", False),
        },
    }


def _extract_iam_role(ci: dict[str, Any]) -> dict[str, Any]:
    cfg = ci.get("configuration", {})
    tags = {t["key"]: t["value"] for t in ci.get("tags", []) or []}
    assume_doc = str(cfg.get("assumeRolePolicyDocument", ""))
    return {
        "permissions_boundary_arn": (cfg.get("permissionsBoundary", {}) or {}).get("permissionsBoundaryArn"),
        "privilege_tag": tags.get("privilege", "standard"),
        "trust_policy_has_mfa_condition": "MultiFactorAuthPresent" in assume_doc,
    }


EXTRACTORS = {
    "AWS::EC2::SecurityGroup": ("security_group", _extract_security_group),
    "AWS::RDS::DBInstance": ("db_instance", _extract_db_instance),
    "AWS::S3::Bucket": ("s3_bucket", _extract_s3_bucket),
    "AWS::IAM::Role": ("iam_role", _extract_iam_role),
}


def normalize_one(ci: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a single AWS Config configuration item. Returns None if
    the resource type isn't covered or required fields can't be populated
    -- caller treats that as UNDETERMINED, never as 'compliant'."""
    resource_type = ci.get("resourceType")
    if resource_type not in EXTRACTORS:
        return None

    canon_type, extractor = EXTRACTORS[resource_type]
    attrs = extractor(ci)

    # Same ordering requirement as desired_state.py: region/tags must be
    # added to attrs BEFORE the missing_required_fields check below, not
    # after, since both are now part of every type's contract in
    # schema.py. Extracting `tags` here (not inside each `_extract_*`
    # function) also means it's reused for `metadata.managed_by` below
    # instead of parsing the AWS Config tag list twice.
    region = ci.get("awsRegion", "unknown")
    tags = {t["key"]: t["value"] for t in ci.get("tags", []) or []}
    attrs["region"] = region
    attrs["tags"] = tags

    if canon_type in ("db_instance", "s3_bucket"):
        attrs["encryption_key_ref"] = attrs.get("kms_key_arn")

    missing = missing_required_fields(canon_type, attrs)
    if missing:
        return None

    account_id = ci.get("accountId", "unknown")
    resource_id = ci.get("resourceId", ci.get("resourceName", "unknown"))

    resource = CanonicalResource(
        resource_urn=f"aws:{region}:{account_id}:{canon_type}/{resource_id}",
        resource_type=canon_type,
        attributes=attrs,
        metadata={
            "managed_by": tags.get("ManagedBy", tags.get("managed-by", "unknown")),
            "source": "aws_config",
            "config_capture_time": ci.get("configurationItemCaptureTime"),
        },
    ).to_dict()
    return resource


def normalize(config_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for ci in config_items:
        resource = normalize_one(ci)
        if resource is not None:
            out.append(resource)
    return out
