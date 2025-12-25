data "azurerm_client_config" "current" {}

# Resource Group
resource "azurerm_resource_group" "ml_rg" {
  name     = "${var.project_name}-rg"
  location = var.location
}

# Virtual Network & Subnets
resource "azurerm_virtual_network" "ml_vnet" {
  name                = "${var.project_name}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.ml_rg.location
  resource_group_name = azurerm_resource_group.ml_rg.name
}

resource "azurerm_subnet" "private_endpoint_subnet" {
  name                                           = "pe-subnet"
  resource_group_name                            = azurerm_resource_group.ml_rg.name
  virtual_network_name                           = azurerm_virtual_network.ml_vnet.name
  address_prefixes                               = ["10.0.1.0/24"]
  enforce_private_link_endpoint_network_policies = true
}

resource "azurerm_subnet" "training_subnet" {
  name                 = "training-subnet"
  resource_group_name  = azurerm_resource_group.ml_rg.name
  virtual_network_name = azurerm_virtual_network.ml_vnet.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_subnet" "aks_subnet" {
  name                 = "aks-subnet"
  resource_group_name  = azurerm_resource_group.ml_rg.name
  virtual_network_name = azurerm_virtual_network.ml_vnet.name
  address_prefixes     = ["10.0.3.0/24"]
}

# Private DNS Zones (essential)
resource "azurerm_private_dns_zone" "kv" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.ml_rg.name
}

resource "azurerm_private_dns_zone" "storage_blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = azurerm_resource_group.ml_rg.name
}

resource "azurerm_private_dns_zone" "acr" {
  name                = "privatelink.azurecr.io"
  resource_group_name = azurerm_resource_group.ml_rg.name
}


# VNet Links (add for each zone as needed)
resource "azurerm_private_dns_zone_virtual_network_link" "kv_link" {
  name                  = "kv-link"
  resource_group_name   = azurerm_resource_group.ml_rg.name
  private_dns_zone_name = azurerm_private_dns_zone.kv.name
  virtual_network_id    = azurerm_virtual_network.ml_vnet.id
}


# Supporting Resources
resource "azurerm_application_insights" "ml_ai" {
  name                = "${var.project_name}-ai"
  location            = azurerm_resource_group.ml_rg.location
  resource_group_name = azurerm_resource_group.ml_rg.name
  application_type    = "web"
}

resource "azurerm_key_vault" "ml_kv" {
  name                     = substr("${replace(var.project_name, "-", "")}kv", 0, 24)
  location                 = azurerm_resource_group.ml_rg.location
  resource_group_name      = azurerm_resource_group.ml_rg.name
  tenant_id                = data.azurerm_client_config.current.tenant_id
  sku_name                 = "premium"
  purge_protection_enabled = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

resource "azurerm_storage_account" "ml_storage" {
  name                     = "${lower(replace(var.project_name, "-", ""))}stor"
  location                 = azurerm_resource_group.ml_rg.location
  resource_group_name      = azurerm_resource_group.ml_rg.name
  account_tier             = "Standard"
  account_replication_type = "GRS"

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

resource "azurerm_container_registry" "ml_acr" {
  name                          = "${lower(replace(var.project_name, "-", ""))}acr"
  location                      = azurerm_resource_group.ml_rg.location
  resource_group_name           = azurerm_resource_group.ml_rg.name
  sku                           = "Premium"
  admin_enabled                 = true
  public_network_access_enabled = false
}

# Private Endpoints for dependencies
resource "azurerm_private_endpoint" "kv_pe" {
  name                = "${var.project_name}-kv-pe"
  location            = azurerm_resource_group.ml_rg.location
  resource_group_name = azurerm_resource_group.ml_rg.name
  subnet_id           = azurerm_subnet.private_endpoint_subnet.id

  private_service_connection {
    name                           = "kv-psc"
    private_connection_resource_id = azurerm_key_vault.ml_kv.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "kv-dns"
    private_dns_zone_ids = [azurerm_private_dns_zone.kv.id]
  }
}

# Add similar PEs for storage_blob and acr...

# Machine Learning Workspace (Private)
resource "azurerm_machine_learning_workspace" "ml_workspace" {
  name                    = "${var.project_name}-mlw"
  location                = azurerm_resource_group.ml_rg.location
  resource_group_name     = azurerm_resource_group.ml_rg.name
  application_insights_id = azurerm_application_insights.ml_ai.id
  key_vault_id            = azurerm_key_vault.ml_kv.id
  storage_account_id      = azurerm_storage_account.ml_storage.id
  container_registry_id   = azurerm_container_registry.ml_acr.id

  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }
}

# Training Compute Cluster (AmlCompute - fixed scale_settings)
resource "azurerm_machine_learning_compute_cluster" "training" {
  name                          = "training-cluster"
  location                      = azurerm_resource_group.ml_rg.location
  machine_learning_workspace_id = azurerm_machine_learning_workspace.ml_workspace.id
  vm_priority                   = "LowPriority"
  vm_size                       = "Standard_DS3_v2"
  subnet_resource_id            = azurerm_subnet.training_subnet.id

  scale_settings {
    min_node_count                       = 0
    max_node_count                       = 3
    scale_down_nodes_after_idle_duration = "PT15M" # Required: 15 minutes idle before scale down
  }

  identity {
    type = "SystemAssigned"
  }
}

# AKS Cluster for Inference (private)
resource "azurerm_kubernetes_cluster" "inference_aks" {
  name                = "${var.project_name}-aks"
  location            = azurerm_resource_group.ml_rg.location
  resource_group_name = azurerm_resource_group.ml_rg.name
  dns_prefix          = "${var.project_name}-aks"

  default_node_pool {
    name           = "default"
    node_count     = 1
    vm_size        = "Standard_D2_v2"
    vnet_subnet_id = azurerm_subnet.aks_subnet.id
  }

  network_profile {
    network_plugin = "azure"
  }

  private_cluster_enabled = true # Fully private AKS

  identity {
    type = "SystemAssigned"
  }
}

# Attach AKS as Inference Cluster
resource "azurerm_machine_learning_inference_cluster" "inference" {
  name                          = "${var.project_name}-inference"
  location                      = azurerm_resource_group.ml_rg.location
  machine_learning_workspace_id = azurerm_machine_learning_workspace.ml_workspace.id
  kubernetes_cluster_id         = azurerm_kubernetes_cluster.inference_aks.id
  cluster_purpose               = "FastProd" # For production real-time inference
}