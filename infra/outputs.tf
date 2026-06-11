# infra/outputs.tf

output "acr_login_server" {
  description = "URL do Azure Container Registry"
  value       = azurerm_container_registry.acr.login_server
}

output "acr_admin_username" {
  description = "Username do ACR"
  value       = azurerm_container_registry.acr.admin_username
  sensitive   = true
}

output "storage_account_name" {
  description = "Nome do Storage Account"
  value       = azurerm_storage_account.reports.name
}

output "resource_group_name" {
  description = "Nome do Resource Group criado"
  value       = azurerm_resource_group.main.name
}