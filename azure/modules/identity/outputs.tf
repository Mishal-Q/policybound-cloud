output "key_vault_id" {
  value = azurerm_key_vault.this.id
}

output "storage_cmk_id" {
  value = azurerm_key_vault_key.storage_cmk.id
}

output "storage_cmk_versionless_id" {
  value = azurerm_key_vault_key.storage_cmk.versionless_id
}
