variable "desired_state_bucket_arn" {
  type = string
}

variable "desired_state_bucket_name" {
  type = string
}

variable "github_token_secret_arn" {
  type = string
}

variable "security_mutations_event_rule_name" {
  type = string
}

variable "security_mutations_event_rule_arn" {
  type = string
}

variable "lambda_package_path" {
  description = <<-EOT
    Absolute or module-relative path to the zipped Lambda package (see
    `make lambda-package`). Left null by default and resolved in
    main.tf via path.module -- a plain relative-string default here
    would be interpreted relative to whatever directory `terraform
    apply` is run FROM, not relative to this module, which breaks the
    moment this module is called from environments/dev instead of run
    standalone. path.module is the correct way to make a module's
    default paths independent of the caller's working directory.
  EOT
  type        = string
  default     = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
