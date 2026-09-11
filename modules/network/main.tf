# Network module: single VPC, 3-tier subnet layout, SG-based microsegmentation.
#
# Scope note: an earlier draft of this project included a Transit Gateway
# and a full stateless-NACL matrix on top of security groups. Both were
# cut (see docs/decisions/0002-no-transit-gateway.md and
# 0003-security-groups-over-nacls.md) because they added AWS cost and
# HCL surface area without adding a governance invariant that security
# groups + route-table isolation don't already provide. The interesting
# part of this project is the policy/drift engine, not the number of
# network primitives wired together.

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpc", ManagedBy = "sentinel-iac" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-igw", ManagedBy = "sentinel-iac" })
}

# --- Public tier (ALB only) ---
resource "aws_subnet" "public" {
  for_each                = var.public_subnet_cidrs
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = each.value
  map_public_ip_on_launch = true
  tags                    = merge(var.tags, { Name = "${var.name_prefix}-public-${each.key}", Tier = "public", ManagedBy = "sentinel-iac" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = merge(var.tags, { Name = "${var.name_prefix}-public-rt", Tier = "public", ManagedBy = "sentinel-iac" })
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# --- App tier (private, NAT egress) ---
resource "aws_subnet" "app" {
  for_each          = var.app_subnet_cidrs
  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = each.value
  tags              = merge(var.tags, { Name = "${var.name_prefix}-app-${each.key}", Tier = "app", ManagedBy = "sentinel-iac" })
}

resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? 1 : 0
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-nat-eip", ManagedBy = "sentinel-iac" })
}

resource "aws_nat_gateway" "this" {
  count         = var.enable_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = values(aws_subnet.public)[0].id
  tags          = merge(var.tags, { Name = "${var.name_prefix}-nat", ManagedBy = "sentinel-iac" })
}

resource "aws_route_table" "app" {
  vpc_id = aws_vpc.this.id
  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.this[0].id
    }
  }
  tags = merge(var.tags, { Name = "${var.name_prefix}-app-rt", Tier = "app", ManagedBy = "sentinel-iac" })
}

resource "aws_route_table_association" "app" {
  for_each       = aws_subnet.app
  subnet_id      = each.value.id
  route_table_id = aws_route_table.app.id
}

# --- Data tier (fully isolated: no route to IGW, no route to NAT) ---
resource "aws_subnet" "data" {
  for_each          = var.data_subnet_cidrs
  vpc_id            = aws_vpc.this.id
  availability_zone = each.key
  cidr_block        = each.value
  tags              = merge(var.tags, { Name = "${var.name_prefix}-data-${each.key}", Tier = "data", ManagedBy = "sentinel-iac" })
}

# Deliberately local-only route table: no 0.0.0.0/0 route of any kind.
# This is the resource NET-DB-002 inspects at runtime via AWS Config to
# verify the isolation invariant actually holds, independent of the
# db_instance's own publicly_accessible flag.
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-data-rt", Tier = "data", ManagedBy = "sentinel-iac" })
}

resource "aws_route_table_association" "data" {
  for_each       = aws_subnet.data
  subnet_id      = each.value.id
  route_table_id = aws_route_table.data.id
}

# --- Security groups: ALB -> App -> DB, reference-based, no CIDR shortcuts ---
resource "aws_security_group" "alb" {
  name_prefix = "${var.name_prefix}-alb-"
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name_prefix}-sg-alb", role = "alb", ManagedBy = "sentinel-iac" })
}

resource "aws_security_group_rule" "alb_ingress_https" {
  type              = "ingress"
  security_group_id = aws_security_group.alb.id
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Public HTTPS ingress - only SG tagged role=alb may have this rule (enforced by NET-INGRESS policy)"
}

resource "aws_security_group" "app" {
  name_prefix = "${var.name_prefix}-app-"
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name_prefix}-sg-app", ManagedBy = "sentinel-iac" })
}

resource "aws_security_group_rule" "app_ingress_from_alb" {
  type                     = "ingress"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.alb.id
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  description              = "App port reachable only from the ALB SG, never by CIDR"
}

resource "aws_security_group" "db" {
  name_prefix = "${var.name_prefix}-db-"
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name_prefix}-sg-db", ManagedBy = "sentinel-iac" })
}

resource "aws_security_group_rule" "db_ingress_from_app" {
  type                     = "ingress"
  security_group_id        = aws_security_group.db.id
  source_security_group_id = aws_security_group.app.id
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  description              = "Postgres reachable only from the app tier SG"
}
