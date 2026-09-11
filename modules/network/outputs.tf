output "vpc_id" {
  value = aws_vpc.this.id
}

output "public_subnet_ids" {
  value = { for k, v in aws_subnet.public : k => v.id }
}

output "app_subnet_ids" {
  value = { for k, v in aws_subnet.app : k => v.id }
}

output "data_subnet_ids" {
  value = { for k, v in aws_subnet.data : k => v.id }
}

output "data_route_table_id" {
  value = aws_route_table.data.id
}

output "alb_security_group_id" {
  value = aws_security_group.alb.id
}

output "app_security_group_id" {
  value = aws_security_group.app.id
}

output "db_security_group_id" {
  value = aws_security_group.db.id
}
