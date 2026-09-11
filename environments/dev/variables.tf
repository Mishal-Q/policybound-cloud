variable "account_id" {
  type = string
}

variable "trusted_account_arn" {
  type = string
}

variable "app_secret_arn" {
  type = string
}

variable "github_token_secret_arn" {
  description = "Secrets Manager ARN for the GitHub token the drift Lambda uses to open remediation PRs. Create this secret manually before applying -- Terraform doesn't manage the token value itself, only references it."
  type        = string
}

variable "db_master_username" {
  type      = string
  sensitive = true
}

variable "db_master_password" {
  type      = string
  sensitive = true
}

variable "owner_tag" {
  type    = string
  default = "platform-team"
}

variable "cost_center_tag" {
  type    = string
  default = "eng-infra"
}

variable "ami_id" {
  type = string
}

variable "acm_certificate_arn" {
  type = string
}
