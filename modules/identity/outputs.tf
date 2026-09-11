output "app_role_arn" {
  value = aws_iam_role.app.arn
}

output "app_instance_profile_name" {
  value = aws_iam_instance_profile.app.name
}

output "operator_role_arn" {
  value = aws_iam_role.operator.arn
}

output "break_glass_role_arn" {
  value = aws_iam_role.break_glass.arn
}

output "boundary_policy_arn" {
  value = aws_iam_policy.workload_boundary.arn
}
