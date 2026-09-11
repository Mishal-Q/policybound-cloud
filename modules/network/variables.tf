variable "name_prefix" {
  type = string
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "map of AZ -> CIDR for the public (ALB) tier"
  type        = map(string)
  default = {
    "us-east-1a" = "10.0.0.0/24"
    "us-east-1b" = "10.0.1.0/24"
  }
}

variable "app_subnet_cidrs" {
  description = "map of AZ -> CIDR for the app (private, NAT egress) tier"
  type        = map(string)
  default = {
    "us-east-1a" = "10.0.10.0/24"
    "us-east-1b" = "10.0.11.0/24"
  }
}

variable "data_subnet_cidrs" {
  description = "map of AZ -> CIDR for the data (isolated) tier"
  type        = map(string)
  default = {
    "us-east-1a" = "10.0.20.0/24"
    "us-east-1b" = "10.0.21.0/24"
  }
}

variable "enable_nat_gateway" {
  description = "NAT Gateway costs ~$0.045/hr + per-GB. Off by default for the dev/demo environment; app tier has no outbound internet unless explicitly needed."
  type        = bool
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
