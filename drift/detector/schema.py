"""
Canonical resource schema.

Both the Terraform-plan normalizer (desired_state.py) and the AWS Config
normalizer (aws_normalizer.py) must emit resources in this exact shape
before anything is diffed or handed to OPA. This is the fix for the
"comparing incompatible state models" problem: Terraform plan JSON and
AWS Config configuration items use completely different field names,
nesting, and casing for the same real-world fact, so nothing upstream is
allowed to compare them directly.

A resource dict conforming to this schema always has exactly these top
level keys. Unknown/irrelevant provider fields are dropped during
normalization -- we intentionally do not carry every provider attribute
forward, only the ones a Control actually evaluates. That keeps the
diff surface meaningful instead of noisy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


CANONICAL_RESOURCE_TYPES = {
    # AWS
    "security_group",
    "db_instance",
    "s3_bucket",
    "iam_role",
    "route_table",
    # Azure -- deliberately separate type names rather than force-fitting
    # onto the AWS ones above (e.g. an Azure Storage Account is not
    # semantically an "s3_bucket", it's a different product with
    # different defaults). See docs/decisions/0010-azure-resource-type-naming.md
    # for why GOV-REGION-001 and GOV-TAG-001 don't need this distinction
    # (they read region/tags generically, regardless of resource_type)
    # while the four resource-specific invariants each get their own
    # AWS and Azure policy file instead of one shared file pretending
    # the underlying resources are the same shape.
    "azure_storage_account",
    "azure_network_security_group",
    "azure_role_assignment",
}


@dataclass
class CanonicalResource:
    resource_urn: str            # stable identity, e.g. "aws:us-east-1:123456789012:security_group/sg-0123"
    resource_type: str           # one of CANONICAL_RESOURCE_TYPES
    attributes: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_urn": self.resource_urn,
            "resource_type": self.resource_type,
            "attributes": self.attributes,
            "metadata": self.metadata,
        }

    @staticmethod
    def validate(d: dict[str, Any]) -> None:
        required = {"resource_urn", "resource_type", "attributes", "metadata"}
        missing = required - d.keys()
        if missing:
            raise ValueError(f"canonical resource missing keys: {missing}")
        if d["resource_type"] not in CANONICAL_RESOURCE_TYPES:
            raise ValueError(f"unknown canonical resource_type: {d['resource_type']}")
        if "managed_by" not in d["metadata"]:
            raise ValueError("canonical resource metadata must include 'managed_by'")


# Per-type attribute contracts. This is what a Control is allowed to depend
# on. If a normalizer can't populate a required field it must omit the
# resource entirely and let the caller mark it UNDETERMINED rather than
# emit a partially-populated resource that looks complete.
#
# `region` and `tags` are required on every type, AWS or Azure. That's
# deliberate: GOV-REGION-001 and GOV-TAG-001 (policies/governance/) read
# these two fields generically off any resource without checking
# resource_type at all, which is what lets the same two policy files
# evaluate both clouds unmodified -- the actual portability claim this
# project can back up with a real test, not just an architecture diagram.
#
# `encryption_key_ref` appears only on db_instance and s3_bucket (AWS)
# and azure_storage_account (Azure) -- the resource types that actually
# hold customer data at rest. It's a cloud-neutral semantic field
# populated alongside (not instead of) the AWS-specific `kms_key_arn`,
# so DATA-ENC-001's existing, tested AWS-specific check is untouched.
# See docs/decisions/0009-encryption-key-ref-semantic-field.md.
ATTRIBUTE_CONTRACTS: dict[str, set[str]] = {
    "security_group": {"ingress_rules", "egress_rules", "vpc_id", "region", "tags"},
    "db_instance": {
        "publicly_accessible",
        "storage_encrypted",
        "kms_key_arn",
        "encryption_key_ref",
        "subnet_group",
        "region",
        "tags",
    },
    "s3_bucket": {
        "encryption_algorithm",
        "kms_key_arn",
        "encryption_key_ref",
        "public_access_block",
        "region",
        "tags",
    },
    "iam_role": {"permissions_boundary_arn", "privilege_tag", "trust_policy_has_mfa_condition", "region", "tags"},
    "route_table": {"routes", "associated_subnet_ids", "region", "tags"},
    "azure_storage_account": {
        "public_network_access_enabled",
        "encryption_key_ref",
        "region",
        "tags",
    },
    "azure_network_security_group": {"rules", "region", "tags"},
    "azure_role_assignment": {"scope", "role_definition_name", "principal_type", "region", "tags"},
}


def missing_required_fields(resource_type: str, attributes: dict[str, Any]) -> set[str]:
    contract = ATTRIBUTE_CONTRACTS.get(resource_type, set())
    return contract - attributes.keys()
