# Logging module.
#
# AWS Config recorder is deliberately scoped to the resource types this
# project's Controls actually evaluate (security groups, RDS instances,
# S3 buckets, IAM roles, route tables) rather than "all resource types in
# the account." Config bills per configuration item recorded; recording
# everything is both a cost leak and noise the drift engine has to
# filter back out. Scope the recorder, don't filter downstream.

resource "aws_kms_key" "logs" {
  description             = "CloudTrail log encryption key"
  deletion_window_in_days = 7
  tags                    = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

resource "aws_s3_bucket" "logs" {
  bucket = "${var.name_prefix}-audit-logs-${var.account_id}"
  tags   = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "logs_deny_delete" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs_bucket_policy.json
}

data "aws_iam_policy_document" "logs_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid    = "DenyDeleteExceptLogDelivery"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    not_principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:DeleteObject", "s3:DeleteBucket"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
  }
}

resource "aws_cloudtrail" "org" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  kms_key_id                    = aws_kms_key.logs.arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  tags = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

resource "aws_iam_role" "config" {
  name               = "${var.name_prefix}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_trust.json
  tags               = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

data "aws_iam_policy_document" "config_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "this" {
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types = [
      "AWS::EC2::SecurityGroup",
      "AWS::RDS::DBInstance",
      "AWS::S3::Bucket",
      "AWS::IAM::Role",
      "AWS::EC2::RouteTable",
    ]
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.logs.id
  depends_on     = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

# Fast path per docs/architecture.md: drift detection reacts to CloudTrail
# API calls via EventBridge rather than waiting on Config's 2-15 minute
# delivery cadence. Config remains the periodic "sweeper" for anything
# the fast path misses.
resource "aws_cloudwatch_event_rule" "security_mutations" {
  name = "${var.name_prefix}-security-mutations"
  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.rds", "aws.iam", "aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "ModifyDBInstance",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutRolePolicy",
        "DeleteRolePermissionsBoundary",
        "CreateRoute",
        "ReplaceRoute",
      ]
    }
  })
  tags = merge(var.tags, { ManagedBy = "sentinel-iac" })
}
