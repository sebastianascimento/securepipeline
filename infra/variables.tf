# infra/variables.tf

variable "resource_group_name" {
  description = "Nome do Resource Group"
  type        = string
  default     = "securepipeline-rg"
}

variable "location" {
  description = "Região Azure"
  type        = string
  default     = "westeurope"
}

variable "acr_name" {
  description = "Nome do Azure Container Registry (único globalmente, só letras e números)"
  type        = string
  default     = "secpipelinesebaacr"
}

variable "storage_account_name" {
  description = "Nome do Storage Account (único globalmente, só letras e números, max 24 chars)"
  type        = string
  default     = "secpipelinesebastore"
}