variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "data_subnet_ids" {
  type = list(string)
}

variable "db_security_group_id" {
  type = string
}

variable "instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "multi_az" {
  description = "Doubles RDS cost. Keep false for dev/demo; true for prod-like only."
  type        = bool
  default     = false
}

variable "master_username" {
  type      = string
  sensitive = true
}

variable "master_password" {
  type      = string
  sensitive = true
}

variable "owner_tag" {
  type = string
}

variable "cost_center_tag" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
