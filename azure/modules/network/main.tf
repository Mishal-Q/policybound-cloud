# Azure network module.
#
# This module passes local Terraform validation. Live Azure deployment and
# runtime behavior remain unverified.
#
# Deliberately small: one VNet, two subnets (app, data -- no separate
# public subnet, since this student-sandbox demo puts a Storage Account
# behind Azure's own public-endpoint control rather than fronting it
# with a load balancer the way the AWS side does with an ALB). This is
# not a landing zone, it's the minimum shape needed to demonstrate
# AZURE-NET-001.

resource "azurerm_virtual_network" "this" {
  name                = "${var.name_prefix}-vnet"
  address_space       = [var.vnet_cidr]
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_subnet" "app" {
  name                 = "${var.name_prefix}-app-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.app_subnet_cidr]
}

resource "azurerm_subnet" "data" {
  name                 = "${var.name_prefix}-data-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.data_subnet_cidr]
}

# The resource AZURE-NET-001 evaluates. Tagged Tier=data specifically so
# the policy (which reads attributes.tags.Tier) can identify it as
# governed -- see azure/policies/network/azure_net_001.rego.
resource "azurerm_network_security_group" "data_tier" {
  name                = "${var.name_prefix}-nsg-data"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "deny-inbound-internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  tags = merge(var.tags, { Tier = "data" })
}

resource "azurerm_subnet_network_security_group_association" "data_tier" {
  subnet_id                 = azurerm_subnet.data.id
  network_security_group_id = azurerm_network_security_group.data_tier.id
}

resource "azurerm_network_security_group" "app_tier" {
  name                = "${var.name_prefix}-nsg-app"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "allow-https-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  tags = merge(var.tags, { Tier = "app" })
}

resource "azurerm_subnet_network_security_group_association" "app_tier" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app_tier.id
}
