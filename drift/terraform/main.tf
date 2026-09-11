locals {
  # See the comment on var.lambda_package_path in variables.tf for why
  # this is resolved here with path.module instead of as a plain string
  # default on the variable itself.
  lambda_package_path = coalesce(var.lambda_package_path, "${path.module}/../detector/build/drift_detector.zip")
}

resource "aws_dynamodb_table" "drift_events" {
  name         = "drift-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "resource_id"
  range_key    = "timestamp"

  attribute {
    name = "resource_id"
    type = "S"
  }
  attribute {
    name = "timestamp"
    type = "S"
  }

  tags = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "drift_lambda" {
  name               = "sentinel-iac-drift-detector"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

# Least-privilege: read-only Config access, write-only to the drift
# table, read-only to the desired-state snapshot bucket, and a scoped
# secret for the GitHub token used to open remediation PRs. Notably: no
# terraform:*, no iam:*, no ability to mutate the resources it observes.
data "aws_iam_policy_document" "lambda_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["config:SelectResourceConfig", "config:GetResourceConfigHistory"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.drift_events.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${var.desired_state_bucket_arn}/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.github_token_secret_arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role_policy" "drift_lambda" {
  role   = aws_iam_role.drift_lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

resource "aws_lambda_function" "drift_detector" {
  function_name = "sentinel-iac-drift-detector"
  role          = aws_iam_role.drift_lambda.arn
  handler       = "handler.handler"
  runtime       = "python3.12"
  timeout       = 60
  memory_size   = 256

  filename         = local.lambda_package_path
  source_code_hash = filebase64sha256(local.lambda_package_path)

  environment {
    variables = {
      DRIFT_EVENTS_TABLE      = aws_dynamodb_table.drift_events.name
      DESIRED_STATE_S3_BUCKET = var.desired_state_bucket_name
      OPA_BUNDLE_PATH         = "/opt/policies"
    }
  }

  tags = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

# Fast path: fires on the CloudTrail-sourced EventBridge rule defined in
# modules/logging (specific security-relevant API calls only).
resource "aws_cloudwatch_event_target" "fast_path" {
  rule = var.security_mutations_event_rule_name
  arn  = aws_lambda_function.drift_detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge_fast_path" {
  statement_id  = "AllowEventBridgeFastPath"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = var.security_mutations_event_rule_arn
}

# Sweeper path: every 6 hours, catches anything the fast path missed.
resource "aws_cloudwatch_event_rule" "sweeper" {
  name                = "sentinel-iac-drift-sweep"
  schedule_expression = "rate(6 hours)"
  tags                = merge(var.tags, { ManagedBy = "sentinel-iac" })
}

resource "aws_cloudwatch_event_target" "sweeper" {
  rule = aws_cloudwatch_event_rule.sweeper.name
  arn  = aws_lambda_function.drift_detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge_sweeper" {
  statement_id  = "AllowEventBridgeSweeper"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sweeper.arn
}
