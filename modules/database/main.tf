# Database module.
#
# multi_az defaults to false: Multi-AZ roughly doubles RDS cost and adds
# nothing to the governance story we're demonstrating. Documented as the
# prod-like configuration toggle, not enabled for the demo environment.

resource "aws_kms_key" "db" {
  description             = "Customer-managed key for ${var.name_prefix} RDS encryption (DATA-ENC-001 requires this, not the AWS-managed default key)"
  deletion_window_in_days = 7
  tags                    = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

resource "aws_kms_alias" "db" {
  name          = "alias/${var.name_prefix}-db"
  target_key_id = aws_kms_key.db.key_id
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-db-subnets"
  subnet_ids = var.data_subnet_ids
  tags       = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

resource "aws_db_instance" "this" {
  identifier     = "${var.name_prefix}-db"
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.instance_class

  allocated_storage = 20
  storage_encrypted = true
  kms_key_id        = aws_kms_key.db.arn

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [var.db_security_group_id]

  # Hardcoded, not a variable: publicly_accessible is a policy-enforced
  # invariant (NET-DB-001), not a configuration toggle someone can flip.
  publicly_accessible = false

  multi_az                = var.multi_az
  backup_retention_period = 7
  skip_final_snapshot     = true # demo/dev only; prod-like should be false

  username = var.master_username
  password = var.master_password # sourced from a Secrets Manager-backed variable, never committed

  tags = merge(var.tags, {
    ManagedBy             = "sentinel-iac"
    owner                 = var.owner_tag
    environment           = var.environment
    "cost-center"         = var.cost_center_tag
    "data-classification" = "confidential"
  })
}
