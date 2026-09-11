output "drift_events_table_name" {
  value = aws_dynamodb_table.drift_events.name
}

output "drift_lambda_arn" {
  value = aws_lambda_function.drift_detector.arn
}
