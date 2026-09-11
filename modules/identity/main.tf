# Identity module.
#
# Scope note: the original draft used AWS IAM Identity Center (SSO) for
# permission sets. Identity Center's SSO instance cannot be fully created
# via Terraform -- the instance itself is a manual, one-time console
# action per AWS Organization, which is pure setup friction with no
# governance payoff for a single-account demo. This module demonstrates
# the same invariants (least privilege, permission boundaries, MFA
# conditions on privileged role assumption) using plain cross-account-
# assumable IAM roles instead. See docs/decisions/0004-iam-roles-over-identity-center.md.

resource "aws_iam_policy" "workload_boundary" {
  name        = "SentinelWorkloadBoundary"
  description = "Permission boundary attached to every non-admin role. Caps effective permissions regardless of what the identity policy alone grants."
  policy      = data.aws_iam_policy_document.boundary.json
}

data "aws_iam_policy_document" "boundary" {
  statement {
    sid       = "DenyIAMEscalation"
    effect    = "Deny"
    actions   = ["iam:CreateUser", "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "organizations:*"]
    resources = ["*"]
  }

  statement {
    sid       = "DenyOutsideManagedByTag"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceTag/ManagedBy"
      values   = ["sentinel-iac"]
    }
  }

  statement {
    sid       = "AllowScopedWorkloadActions"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "secretsmanager:GetSecretValue", "rds:Describe*", "ec2:Describe*"]
    resources = ["*"]
  }
}

# --- Standard (non-admin) application role, e.g. attached to compute instance profile ---
resource "aws_iam_role" "app" {
  name                 = "${var.name_prefix}-app-role"
  assume_role_policy   = data.aws_iam_policy_document.app_trust.json
  permissions_boundary = aws_iam_policy.workload_boundary.arn

  tags = merge(var.tags, {
    ManagedBy = "sentinel-iac"
    privilege = "standard"
  })
}

data "aws_iam_policy_document" "app_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_instance_profile" "app" {
  # An IAM role alone can't be attached to an EC2 instance -- the launch
  # template needs an instance profile, which is a separate resource
  # that wraps the role. This was missing from an earlier version of
  # this module: environments/dev/main.tf was passing a raw
  # var.instance_profile_name string into modules/compute, implying an
  # instance profile existed somewhere, when nothing in this codebase
  # actually created one. Found while doing a full wiring recheck --
  # the compute module would have failed at apply time referencing a
  # profile that didn't exist unless someone created it by hand outside
  # Terraform first.
  name = "${var.name_prefix}-app-instance-profile"
  role = aws_iam_role.app.name
}

resource "aws_iam_role_policy" "app_scoped" {
  name   = "${var.name_prefix}-app-scoped-policy"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app_scoped.json
}

data "aws_iam_policy_document" "app_scoped" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${var.config_bucket_arn}/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.app_secret_arn]
  }
}

# --- Operator role: broader but explicitly denied IAM-role-creation, MFA required ---
resource "aws_iam_role" "operator" {
  name                 = "${var.name_prefix}-operator-role"
  assume_role_policy   = data.aws_iam_policy_document.operator_trust.json
  permissions_boundary = aws_iam_policy.workload_boundary.arn

  tags = merge(var.tags, {
    ManagedBy = "sentinel-iac"
    privilege = "standard"
  })
}

data "aws_iam_policy_document" "operator_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.trusted_account_arn]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role_policy" "operator_scoped" {
  name   = "${var.name_prefix}-operator-scoped-policy"
  role   = aws_iam_role.operator.id
  policy = data.aws_iam_policy_document.operator_scoped.json
}

data "aws_iam_policy_document" "operator_scoped" {
  statement {
    effect    = "Allow"
    actions   = ["ec2:*", "rds:Describe*", "rds:RebootDBInstance"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/environment"
      values   = [var.environment]
    }
  }
  statement {
    effect    = "Deny"
    actions   = ["iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy"]
    resources = ["*"]
  }
}

# --- Break-glass emergency role (privilege=admin, exempt from boundary requirement, MFA + short session) ---
resource "aws_iam_role" "break_glass" {
  name                 = "${var.name_prefix}-break-glass"
  assume_role_policy   = data.aws_iam_policy_document.break_glass_trust.json
  max_session_duration = 3600

  tags = merge(var.tags, {
    ManagedBy = "sentinel-iac"
    privilege = "admin" # exempt from IAM-BOUNDARY-001 by policy design, see runbooks/break-glass-access.md
  })
}

data "aws_iam_policy_document" "break_glass_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.trusted_account_arn]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "break_glass_admin" {
  role       = aws_iam_role.break_glass.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
