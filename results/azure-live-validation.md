# Azure live validation

Real Azure validation was run against the student demo environment.

## What was checked

- Terraform deployment completed successfully in Azure.
- Storage public network access was disabled.
- Blob public access was disabled.
- Default authentication was set to OAuth.
- TLS 1.2 was enforced.
- Storage encryption used a customer-managed key from Azure Key Vault.
- The data-tier NSG contained an inbound deny rule for Internet traffic.
- Resource tags were visible on the deployed Azure resources.
- The operator role assignment was Contributor at resource-group scope.
- Azure Resource Graph output was normalized into the project canonical schema.
- The live normalized state passed the Azure public-access, encryption, network, and identity OPA checks.
- A local mutation of the real canonical storage state with public network access enabled was rejected by AZURE-PUBLIC-001.

## Things found during the live run

- Disabling Storage shared-key access caused AzureRM provider refresh to fail, so shared-key access was kept enabled for provider compatibility.
- Azure Storage customer-managed keys required Key Vault purge protection.
- Real Resource Graph output used keyvaultproperties.currentVersionedKeyIdentifier for the storage encryption key reference, so the observed-state normalizer was corrected.
- Key Vault public network access remained enabled because Terraform was being run locally without a private endpoint.
- The Key Vault uses purge protection, so after destroy it can remain soft-deleted until the retention period expires.

## Teardown

Terraform destroy completed successfully with 17 resources destroyed. Azure reported that the resource group no longer existed afterward, and Terraform state was empty. The Key Vault remained only in the expected soft-deleted, purge-protected state, with scheduled purge on 2026-09-18.
