variable "name_prefix" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "vnet_cidr" {
  type    = string
  default = "10.1.0.0/16"
}

variable "app_subnet_cidr" {
  type    = string
  default = "10.1.1.0/24"
}

variable "data_subnet_cidr" {
  type    = string
  default = "10.1.2.0/24"
}

variable "tags" {
  type    = map(string)
  default = {}
}
