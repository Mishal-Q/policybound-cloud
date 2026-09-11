variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "trusted_account_arn" {
  description = "ARN (account root or specific role) allowed to assume operator/break-glass roles"
  type        = string
}

variable "config_bucket_arn" {
  type = string
}

variable "app_secret_arn" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
