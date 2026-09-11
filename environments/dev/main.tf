terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  name_prefix = "sentinel-iac-dev"
  common_tags = {
    ManagedBy     = "sentinel-iac"
    environment   = "dev"
    owner         = var.owner_tag
    "cost-center" = var.cost_center_tag
  }
}

module "network" {
  source             = "../../modules/network"
  name_prefix        = local.name_prefix
  enable_nat_gateway = false # cost control: app tier has no outbound internet need in dev
  tags               = local.common_tags
}

module "identity" {
  source              = "../../modules/identity"
  name_prefix         = local.name_prefix
  environment         = "dev"
  trusted_account_arn = var.trusted_account_arn
  config_bucket_arn   = module.logging.log_bucket_arn
  app_secret_arn      = var.app_secret_arn
  tags                = local.common_tags
}

module "logging" {
  source      = "../../modules/logging"
  name_prefix = local.name_prefix
  account_id  = var.account_id
  tags        = local.common_tags
}

module "database" {
  source               = "../../modules/database"
  name_prefix          = local.name_prefix
  environment          = "dev"
  data_subnet_ids      = values(module.network.data_subnet_ids)
  db_security_group_id = module.network.db_security_group_id
  multi_az             = false # cost control: dev is single-AZ
  master_username      = var.db_master_username
  master_password      = var.db_master_password
  owner_tag            = var.owner_tag
  cost_center_tag      = var.cost_center_tag
  tags                 = local.common_tags
}

# Written at successful `terraform apply` time by a CI step that runs
# scripts/normalize_plan_for_ci.py against the applied plan and uploads
# the result here as desired-state.json (see docs/architecture.md). Not
# yet wired into apply-dev.yml -- that workflow isn't written yet, this
# bucket just needs to exist first so drift/detector/handler.py has
# somewhere to read from.
resource "aws_kms_key" "desired_state" {
  description             = "Customer-managed key for the desired-state snapshot bucket (DATA-ENC-001 requires a specific key ARN, not the AWS-managed default -- this bucket has to satisfy its own project's policy same as anything else)"
  deletion_window_in_days = 7
  tags                    = local.common_tags
}

resource "aws_s3_bucket" "desired_state" {
  bucket = "${local.name_prefix}-desired-state"
  tags   = local.common_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "desired_state" {
  bucket = aws_s3_bucket.desired_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.desired_state.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "desired_state" {
  bucket                  = aws_s3_bucket.desired_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "drift" {
  source = "../../drift/terraform"

  desired_state_bucket_arn           = aws_s3_bucket.desired_state.arn
  desired_state_bucket_name          = aws_s3_bucket.desired_state.id
  github_token_secret_arn            = var.github_token_secret_arn
  security_mutations_event_rule_name = module.logging.security_mutations_event_rule_name
  security_mutations_event_rule_arn  = module.logging.security_mutations_event_rule_arn
  tags                               = local.common_tags
}

module "compute" {
  source                = "../../modules/compute"
  name_prefix           = local.name_prefix
  environment           = "dev"
  vpc_id                = module.network.vpc_id
  public_subnet_ids     = values(module.network.public_subnet_ids)
  app_subnet_ids        = values(module.network.app_subnet_ids)
  alb_security_group_id = module.network.alb_security_group_id
  app_security_group_id = module.network.app_security_group_id
  instance_profile_name = module.identity.app_instance_profile_name
  ami_id                = var.ami_id
  acm_certificate_arn   = var.acm_certificate_arn
  tags                  = local.common_tags
}
