output "storage_account_id" {
  value = azurerm_storage_account.data.id
}

output "storage_account_name" {
  value = azurerm_storage_account.data.name
}

output "storage_account_principal_id" {
  # The storage account's system-assigned managed identity object ID --
  # needed by the environment to grant this identity Key Vault access
  # BEFORE the environment-level azurerm_storage_account_customer_managed_key
  # resource can succeed. See azure/environments/student-demo/main.tf for
  # how this is sequenced to avoid the circular dependency that existed
  # when the CMK association lived inside this module.
  value = azurerm_storage_account.data.identity[0].principal_id
}
