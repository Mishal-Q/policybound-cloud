variable "storage_account_name" {
  type        = string
  description = "Must be globally unique, lowercase alphanumeric, 3-24 chars -- Azure Storage Account naming constraint."
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
