"""
Desired-state normalizer.

Input: `terraform show -json <plan>` output (a Terraform plan, already
parsed into a Python dict).
Output: list[CanonicalResource.to_dict()] -- the same canonical schema
the AWS Config normalizer produces in aws_normalizer.py.

This is deliberately narrow: it only extracts the resource types and
attributes listed in schema.ATTRIBUTE_CONTRACTS, because those are the
only attributes any Control currently evaluates. Extending coverage means
adding to ATTRIBUTE_CONTRACTS *and* a corresponding extraction function
here, on purpose -- that keeps the two in sync instead of drifting apart.
"""

from __future__ import annotations

from typing import Any

from schema import CanonicalResource, missing_required_fields


def _account_and_region(root_module_address: str, provider_config: dict) -> tuple[str, str]:
    # In real Terraform plan JSON this is derivable from provider config /
    # planned values; for the reference implementation we accept it as
    # already-resolved context passed in by the caller (see normalize()).
    return provider_config.get("account_id", "unknown"), provider_config.get("region", "unknown")


def _extract_security_group(change: dict[str, Any]) -> dict[str, Any]:
    after = change["change"]["after"] or {}
    ingress = after.get("ingress", []) or []
    egress = after.get("egress", []) or []

    def _rule(r: dict) -> dict:
        return {
            "protocol": r.get("protocol"),
            "from_port": r.get("from_port"),
            "to_port": r.get("to_port"),
            "cidr_blocks": sorted(r.get("cidr_blocks", []) or []),
            "source_security_group_ids": sorted(r.get("security_groups", []) or []),
        }

    return {
        "ingress_rules": [_rule(r) for r in ingress],
        "egress_rules": [_rule(r) for r in egress],
        "vpc_id": after.get("vpc_id", "(known after apply)"),
    }


def _extract_db_instance(change: dict[str, Any]) -> dict[str, Any]:
    after = change["change"]["after"] or {}
    return {
        "publicly_accessible": after.get("publicly_accessible", False),
        "storage_encrypted": after.get("storage_encrypted", False),
        "kms_key_arn": after.get("kms_key_id"),
        "subnet_group": after.get("db_subnet_group_name", "(known after apply)"),
    }


def _extract_s3_bucket_family(bucket_change: dict, sse_change: dict | None, pab_change: dict | None) -> dict[str, Any]:
    sse_after = (sse_change or {}).get("change", {}).get("after") or {}
    pab_after = (pab_change or {}).get("change", {}).get("after") or {}
    rule = (sse_after.get("rule") or [{}])[0]
    apply_sse = rule.get("apply_server_side_encryption_by_default", {}) or {}
    return {
        "encryption_algorithm": apply_sse.get("sse_algorithm", "NONE"),
        "kms_key_arn": apply_sse.get("kms_master_key_id"),
        "public_access_block": {
            "block_public_acls": pab_after.get("block_public_acls", False),
            "block_public_policy": pab_after.get("block_public_policy", False),
            "ignore_public_acls": pab_after.get("ignore_public_acls", False),
            "restrict_public_buckets": pab_after.get("restrict_public_buckets", False),
        },
    }


def _extract_iam_role(change: dict[str, Any]) -> dict[str, Any]:
    after = change["change"]["after"] or {}
    tags = after.get("tags", {}) or {}
    assume_policy = after.get("assume_role_policy", "") or ""
    return {
        "permissions_boundary_arn": after.get("permissions_boundary"),
        "privilege_tag": tags.get("privilege", "standard"),
        "trust_policy_has_mfa_condition": "MultiFactorAuthPresent" in assume_policy,
    }


EXTRACTORS = {
    "aws_security_group": ("security_group", _extract_security_group),
    "aws_db_instance": ("db_instance", _extract_db_instance),
    "aws_iam_role": ("iam_role", _extract_iam_role),
}


def normalize(plan_json: dict[str, Any], account_id: str, region: str) -> list[dict[str, Any]]:
    """Turn a parsed `terraform show -json` plan into canonical resources."""
    resource_changes = plan_json.get("resource_changes", [])
    by_address = {c["address"]: c for c in resource_changes}
    out: list[dict[str, Any]] = []

    for change in resource_changes:
        rtype = change.get("type")

        if rtype == "aws_s3_bucket":
            sse = by_address.get(change["address"] + "_sse")  # convention: caller wires related addresses; see tests
            pab = by_address.get(change["address"] + "_pab")
            attrs = _extract_s3_bucket_family(change, sse, pab)
            canon_type = "s3_bucket"
        elif rtype in EXTRACTORS:
            canon_type, extractor = EXTRACTORS[rtype]
            attrs = extractor(change)
        else:
            continue

        # region and tags added centrally here, not per-extractor, so
        # every resource type gets them uniformly and GOV-REGION-001 /
        # GOV-TAG-001 can evaluate any canonical resource without a
        # resource-type-specific extraction function having to remember
        # to include them. `change["change"]["after"]` is always the
        # primary resource's post-apply attributes regardless of which
        # branch above produced `attrs` -- for the s3_bucket branch,
        # `change` is still the aws_s3_bucket resource itself (the sse/pab
        # lookups are separate related resources), so tags read from here
        # are always the bucket's own tags, not the encryption config's.
        #
        # This MUST happen before the missing_required_fields check below,
        # not after -- region/tags are now part of every type's contract
        # in schema.py, so checking completeness before adding them would
        # make every single resource look incomplete and get silently
        # dropped. Caught this ordering mistake while writing this same
        # function, before it ever ran against a real test.
        primary_after = (change.get("change", {}) or {}).get("after") or {}
        attrs["region"] = region
        attrs["tags"] = primary_after.get("tags", {}) or {}

        # encryption_key_ref mirrors kms_key_arn for AWS resources that
        # have one -- see schema.py's comment on ATTRIBUTE_CONTRACTS and
        # docs/decisions/0009-encryption-key-ref-semantic-field.md. This
        # does NOT change what DATA-ENC-001 checks (it still reads
        # kms_key_arn, untouched, tests unchanged) -- it adds a second,
        # cloud-neutral field alongside it for cross-cloud comparison.
        if canon_type in ("db_instance", "s3_bucket"):
            attrs["encryption_key_ref"] = attrs.get("kms_key_arn")

        missing = missing_required_fields(canon_type, attrs)
        if missing:
            # Don't emit a partial resource -- caller treats absence as
            # UNDETERMINED rather than us guessing at values.
            continue

        urn = f"aws:{region}:{account_id}:{canon_type}/{change['address']}"
        resource = CanonicalResource(
            resource_urn=urn,
            resource_type=canon_type,
            attributes=attrs,
            metadata={
                "managed_by": "sentinel-iac",
                "source": "terraform_plan",
                "terraform_address": change["address"],
            },
        ).to_dict()
        out.append(resource)

    return out
