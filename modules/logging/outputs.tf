output "log_bucket_name" {
  value = aws_s3_bucket.logs.id
}

output "log_bucket_arn" {
  value = aws_s3_bucket.logs.arn
}

output "security_mutations_event_rule_name" {
  value = aws_cloudwatch_event_rule.security_mutations.name
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.org.arn
}

output "security_mutations_event_rule_arn" {
  value = aws_cloudwatch_event_rule.security_mutations.arn
}
