# infra/main.tf

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Resource Group — o contentor de todos os recursos
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
}

# Azure Container Registry — guarda as imagens Docker
resource "azurerm_container_registry" "acr" {
  name                = var.acr_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = true
}

# Storage Account — guarda os relatórios PDF gerados
resource "azurerm_storage_account" "reports" {
  name                     = var.storage_account_name
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Storage Container — pasta dentro do Storage Account
resource "azurerm_storage_container" "reports" {
  name                  = "reports"
  storage_account_name  = azurerm_storage_account.reports.name
  container_access_type = "private"
}

# Dados da conta Azure atual
data "azurerm_client_config" "current" {}

# Key Vault — gestor de segredos
resource "azurerm_key_vault" "main" {
  name                = "secpipelinesebakv"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get", "List", "Set", "Delete"
    ]
  }
}

# Segredo de exemplo — DB password
resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  value        = "changeme-in-production"
  key_vault_id = azurerm_key_vault.main.id
}