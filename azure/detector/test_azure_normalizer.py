"""
Tests for azure/detector/azure_normalizer.py. Fixtures here are
hand-constructed to match the documented (not confirmed-real) shape of
`terraform show -json` output for azurerm resources and Azure Resource
Graph query results -- see the honesty note at the top of
azure_normalizer.py. These tests prove the normalizer's own logic is
correct given that shape; they do not prove the shape itself matches
real Azure output, since no real Terraform or Azure access was available
to confirm that.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))

import azure_normalizer  # noqa: E402


# --- desired state (plan) tests ---


def test_normalize_plan_storage_account_with_cmk():
    plan = {
        "resource_changes": [
            {
                "address": "azurerm_storage_account.data",
                "type": "azurerm_storage_account",
                "change": {
                    "after": {
                        "public_network_access_enabled": False,
                        "location": "eastus",
                        "tags": {"ManagedBy": "sentinel-iac", "owner": "platform-team", "cost-center": "eng-infra"},
                    }
                },
            },
            {
                "address": "azurerm_storage_account.data_cmk",
                "type": "azurerm_storage_account_customer_managed_key",
                "change": {"after": {"key_vault_key_id": "https://kv-sentinel.vault.azure.net/keys/storage-key/abc123"}},
            },
        ]
    }
    resources = azure_normalizer.normalize_plan(plan, subscription_id="sub-123", region="eastus")
    assert len(resources) == 1
    attrs = resources[0]["attributes"]
    assert attrs["public_network_access_enabled"] is False
    assert attrs["encryption_key_ref"] == "https://kv-sentinel.vault.azure.net/keys/storage-key/abc123"
    assert attrs["region"] == "eastus"
    assert attrs["tags"]["ManagedBy"] == "sentinel-iac"
    assert resources[0]["resource_type"] == "azure_storage_account"
    assert resources[0]["resource_urn"].startswith("azure:eastus:sub-123:azure_storage_account/")


def test_normalize_plan_storage_account_without_cmk_resource_wired():
    """No matching _cmk resource in the plan -- encryption_key_ref should
    end up None, not crash and not silently omit the resource (unlike a
    genuinely missing REQUIRED field, encryption_key_ref being None is a
    valid, checkable state a policy can act on)."""
    plan = {
        "resource_changes": [
            {
                "address": "azurerm_storage_account.data",
                "type": "azurerm_storage_account",
                "change": {
                    "after": {
                        "public_network_access_enabled": True,
                        "location": "eastus",
                        "tags": {},
                    }
                },
            }
        ]
    }
    resources = azure_normalizer.normalize_plan(plan, subscription_id="sub-123", region="eastus")
    assert len(resources) == 1
    assert resources[0]["attributes"]["encryption_key_ref"] is None


def test_normalize_plan_nsg_rules():
    plan = {
        "resource_changes": [
            {
                "address": "azurerm_network_security_group.data_tier",
                "type": "azurerm_network_security_group",
                "change": {
                    "after": {
                        "location": "eastus",
                        "tags": {"ManagedBy": "sentinel-iac"},
                        "security_rule": [
                            {
                                "direction": "Inbound",
                                "access": "Deny",
                                "protocol": "*",
                                "destination_port_range": "*",
                                "source_address_prefix": "Internet",
                                "priority": 100,
                            }
                        ],
                    }
                },
            }
        ]
    }
    resources = azure_normalizer.normalize_plan(plan, subscription_id="sub-123", region="eastus")
    assert len(resources) == 1
    rules = resources[0]["attributes"]["rules"]
    assert len(rules) == 1
    assert rules[0]["access"] == "Deny"
    assert rules[0]["source_address_prefix"] == "Internet"


def test_normalize_plan_role_assignment():
    plan = {
        "resource_changes": [
            {
                "address": "azurerm_role_assignment.operator",
                "type": "azurerm_role_assignment",
                "change": {
                    "after": {
                        "scope": "/subscriptions/sub-123/resourceGroups/sentinel-iac-demo",
                        "role_definition_name": "Contributor",
                        "principal_type": "User",
                        "location": "eastus",
                        "tags": {},
                    }
                },
            }
        ]
    }
    resources = azure_normalizer.normalize_plan(plan, subscription_id="sub-123", region="eastus")
    assert len(resources) == 1
    attrs = resources[0]["attributes"]
    assert attrs["scope"] == "/subscriptions/sub-123/resourceGroups/sentinel-iac-demo"
    assert attrs["role_definition_name"] == "Contributor"


def test_normalize_plan_ignores_unrecognized_resource_types():
    plan = {
        "resource_changes": [
            {"address": "azurerm_resource_group.demo", "type": "azurerm_resource_group", "change": {"after": {}}}
        ]
    }
    resources = azure_normalizer.normalize_plan(plan, subscription_id="sub-123", region="eastus")
    assert resources == []


# --- observed state (Resource Graph) tests ---


def test_normalize_observed_storage_account():
    item = {
        "type": "microsoft.storage/storageaccounts",
        "name": "sentineldatastore",
        "location": "eastus",
        "subscriptionId": "sub-123",
        "tags": {"ManagedBy": "sentinel-iac", "owner": "platform-team", "cost-center": "eng-infra"},
        "properties": {
            "publicNetworkAccess": "Disabled",
            "encryption": {"keyvaultproperties": {"currentVersionedKeyIdentifier": "https://kv-sentinel.vault.azure.net/keys/storage-key/abc123"}},
        },
    }
    resource = azure_normalizer.normalize_observed(item)
    assert resource is not None
    attrs = resource["attributes"]
    assert attrs["public_network_access_enabled"] is False
    assert attrs["encryption_key_ref"] == "https://kv-sentinel.vault.azure.net/keys/storage-key/abc123"
    assert resource["metadata"]["managed_by"] == "sentinel-iac"


def test_normalize_observed_storage_account_public_access_enabled():
    item = {
        "type": "Microsoft.Storage/storageAccounts",  # mixed case, matching real ARM casing
        "name": "leakystore",
        "location": "eastus",
        "subscriptionId": "sub-123",
        "tags": {},
        "properties": {"publicNetworkAccess": "Enabled", "encryption": {}},
    }
    resource = azure_normalizer.normalize_observed(item)
    assert resource is not None
    assert resource["attributes"]["public_network_access_enabled"] is True
    assert resource["attributes"]["encryption_key_ref"] is None


def test_normalize_observed_unrecognized_type_returns_none():
    item = {"type": "microsoft.compute/virtualmachines", "name": "vm1", "properties": {}}
    assert azure_normalizer.normalize_observed(item) is None


def test_normalize_observed_batch_skips_unrecognized_and_keeps_valid():
    items = [
        {"type": "microsoft.compute/virtualmachines", "name": "vm1", "properties": {}},
        {
            "type": "microsoft.storage/storageaccounts",
            "name": "store1",
            "location": "eastus",
            "subscriptionId": "sub-123",
            "tags": {},
            "properties": {"publicNetworkAccess": "Disabled", "encryption": {}},
        },
    ]
    resources = azure_normalizer.normalize_observed_batch(items)
    assert len(resources) == 1
    assert resources[0]["resource_type"] == "azure_storage_account"
