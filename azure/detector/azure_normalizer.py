"""
Azure normalizer.

Input: a dict shaped like `terraform show -json` output from the
`azurerm` provider, OR an Azure Resource Graph query result item -- both
are accepted since, same as the AWS side (desired_state.py vs.
aws_normalizer.py), Azure has a desired-state path (Terraform plan) and
an observed-state path (real Azure resource state). This module handles
both, functions prefixed `_from_plan_` vs `_from_observed_`, since the
two input shapes genuinely differ the same way Terraform plan JSON
differs from an AWS Config configuration item.

Output: the same canonical schema as drift/detector/schema.py -- this
module imports directly from there rather than duplicating the schema,
so `CanonicalResource`, `ATTRIBUTE_CONTRACTS`, and `missing_required_fields`
are the single shared definition, not an Azure-side copy that could
drift out of sync with the AWS-side one.

HONESTY NOTE: the exact JSON shape `terraform show -json` produces for
azurerm resources, and the exact shape Azure Resource Graph query
results take, have NOT been verified against a real `terraform` binary
or a real Azure subscription -- neither was available while building
this. The field names below (`public_network_access_enabled`,
`network_rule_set`, etc.) are the real azurerm provider argument names
as documented, but the exact plan-JSON nesting is modeled on the same
pattern the AWS extractors use, not confirmed against real Azure output.
This is the Azure-side equivalent of the AWS normalizer fixture gap
already documented in tests/fixtures/README.md -- flagged here rather
than silently assumed correct.
"""

from __future__ import annotations

import sys
import os
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "drift", "detector"))
from schema import CanonicalResource, missing_required_fields  # noqa: E402


# --- desired state (Terraform plan) extractors ---


def _from_plan_storage_account(change: dict[str, Any]) -> dict[str, Any]:
    after = change["change"]["after"] or {}
    # azurerm_storage_account's customer_managed_key is usually a
    # separate azurerm_storage_account_customer_managed_key resource
    # referencing the storage account by ID, similar in spirit to how
    # aws_s3_bucket_server_side_encryption_configuration is a separate
    # resource from aws_s3_bucket on the AWS side. Modeled the same way
    # here: the caller wires the related CMK resource by naming
    # convention, same pattern as desired_state.py's "_sse"/"_pab"
    # convention for S3.
    return {
        "public_network_access_enabled": after.get("public_network_access_enabled", True),
        "encryption_key_ref": None,  # filled in by caller if a CMK resource is wired
    }


def _from_plan_cmk_ref(cmk_change: dict[str, Any] | None) -> str | None:
    if cmk_change is None:
        return None
    after = (cmk_change.get("change", {}) or {}).get("after") or {}
    return after.get("key_vault_key_id")


def _from_plan_nsg(change: dict[str, Any]) -> dict[str, Any]:
    after = change["change"]["after"] or {}
    security_rules = after.get("security_rule", []) or []

    def _rule(r: dict) -> dict:
        return {
            "direction": r.get("direction"),  # "Inbound" | "Outbound"
            "access": r.get("access"),  # "Allow" | "Deny"
            "protocol": r.get("protocol"),
            "destination_port_range": r.get("destination_port_range"),
            "source_address_prefix": r.get("source_address_prefix"),
            "priority": r.get("priority"),
        }

    return {"rules": [_rule(r) for r in security_rules]}


def _from_plan_role_assignment(change: dict[str, Any]) -> dict[str, Any]:
    after = change["change"]["after"] or {}
    return {
        "scope": after.get("scope", "unknown"),
        "role_definition_name": after.get("role_definition_name", "unknown"),
        "principal_type": after.get("principal_type", "unknown"),
    }


PLAN_EXTRACTORS = {
    "azurerm_storage_account": ("azure_storage_account", _from_plan_storage_account),
    "azurerm_network_security_group": ("azure_network_security_group", _from_plan_nsg),
    "azurerm_role_assignment": ("azure_role_assignment", _from_plan_role_assignment),
}


def normalize_plan(plan_json: dict[str, Any], subscription_id: str, region: str) -> list[dict[str, Any]]:
    """Azure-side equivalent of desired_state.normalize(). Same
    region/tags-before-missing-check ordering as the AWS version --
    this is not incidental, it's the same bug class avoided the same
    way, in a different file."""
    resource_changes = plan_json.get("resource_changes", [])
    by_address = {c["address"]: c for c in resource_changes}
    out: list[dict[str, Any]] = []

    for change in resource_changes:
        rtype = change.get("type")
        if rtype not in PLAN_EXTRACTORS:
            continue

        canon_type, extractor = PLAN_EXTRACTORS[rtype]
        attrs = extractor(change)

        if canon_type == "azure_storage_account":
            cmk_change = by_address.get(change["address"] + "_cmk")
            attrs["encryption_key_ref"] = _from_plan_cmk_ref(cmk_change)

        primary_after = (change.get("change", {}) or {}).get("after") or {}
        attrs["region"] = primary_after.get("location", region)
        attrs["tags"] = primary_after.get("tags", {}) or {}

        missing = missing_required_fields(canon_type, attrs)
        if missing:
            continue

        urn = f"azure:{attrs['region']}:{subscription_id}:{canon_type}/{change['address']}"
        resource = CanonicalResource(
            resource_urn=urn,
            resource_type=canon_type,
            attributes=attrs,
            metadata={
                "managed_by": attrs["tags"].get("ManagedBy", "unknown"),
                "source": "azure_terraform_plan",
                "terraform_address": change["address"],
            },
        ).to_dict()
        out.append(resource)

    return out


# --- observed state (Azure Resource Graph) extractors ---
# Modeled on the shape an Azure Resource Graph `Resources` query
# returns: {id, name, type, location, tags, properties}. Same honesty
# caveat as above -- not confirmed against a real query result.


def _from_observed_storage_account(properties: dict[str, Any]) -> dict[str, Any]:
    network_rules = properties.get("networkAcls", {}) or {}
    encryption = properties.get("encryption", {}) or {}
    key_vault_props = encryption.get("keyVaultProperties", {}) or {}
    return {
        "public_network_access_enabled": properties.get("publicNetworkAccess", "Enabled") == "Enabled",
        "encryption_key_ref": key_vault_props.get("keyVaultUri"),
    }


def _from_observed_nsg(properties: dict[str, Any]) -> dict[str, Any]:
    rules = properties.get("securityRules", []) or []

    def _rule(r: dict) -> dict:
        p = r.get("properties", {}) or {}
        return {
            "direction": p.get("direction"),
            "access": p.get("access"),
            "protocol": p.get("protocol"),
            "destination_port_range": p.get("destinationPortRange"),
            "source_address_prefix": p.get("sourceAddressPrefix"),
            "priority": p.get("priority"),
        }

    return {"rules": [_rule(r) for r in rules]}


def _from_observed_role_assignment(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "scope": properties.get("scope", "unknown"),
        "role_definition_name": properties.get("roleDefinitionName", "unknown"),
        "principal_type": properties.get("principalType", "unknown"),
    }


OBSERVED_EXTRACTORS = {
    "microsoft.storage/storageaccounts": ("azure_storage_account", _from_observed_storage_account),
    "microsoft.network/networksecuritygroups": ("azure_network_security_group", _from_observed_nsg),
    "microsoft.authorization/roleassignments": ("azure_role_assignment", _from_observed_role_assignment),
}


def normalize_observed(resource_graph_item: dict[str, Any]) -> dict[str, Any] | None:
    """Azure-side equivalent of aws_normalizer.normalize_one()."""
    azure_type = (resource_graph_item.get("type") or "").lower()
    if azure_type not in OBSERVED_EXTRACTORS:
        return None

    canon_type, extractor = OBSERVED_EXTRACTORS[azure_type]
    properties = resource_graph_item.get("properties", {}) or {}
    attrs = extractor(properties)

    tags = resource_graph_item.get("tags", {}) or {}
    attrs["region"] = resource_graph_item.get("location", "unknown")
    attrs["tags"] = tags

    missing = missing_required_fields(canon_type, attrs)
    if missing:
        return None

    subscription_id = resource_graph_item.get("subscriptionId", "unknown")
    resource_id = resource_graph_item.get("name", resource_graph_item.get("id", "unknown"))

    resource = CanonicalResource(
        resource_urn=f"azure:{attrs['region']}:{subscription_id}:{canon_type}/{resource_id}",
        resource_type=canon_type,
        attributes=attrs,
        metadata={
            "managed_by": tags.get("ManagedBy", "unknown"),
            "source": "azure_resource_graph",
        },
    ).to_dict()
    return resource


def normalize_observed_batch(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for item in items:
        resource = normalize_observed(item)
        if resource is not None:
            out.append(resource)
    return out
