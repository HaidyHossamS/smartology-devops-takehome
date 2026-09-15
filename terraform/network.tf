###############################################################################
# network.tf — security groups and VPC endpoints
#
# The design goal here is that the log processor fleet has NO route to the
# internet at all. No IGW, no NAT. Everything it talks to (Kinesis, Firehose,
# S3, KMS, CloudWatch, SSM) is reached over PrivateLink inside the VPC.
#
# Three things fall out of that:
#   - data exfiltration via a compromised log parser has nowhere to go
#   - we stop paying NAT gateway data-processing charges on high log volume,
#     which on a real pipeline is a five-figure annual line item
#   - "the instance can't reach the internet" stops being a security incident
#     and starts being the expected state
###############################################################################

# --- Processor security group ------------------------------------------------
# Note the name_prefix + create_before_destroy pair. With a fixed `name`, any
# change that forces replacement fails: AWS refuses the duplicate name, and the
# old group can't be deleted while ENIs still reference it. This is the single
# most common way a security group change deadlocks an apply.

resource "aws_security_group" "processor" {
  name_prefix = "${local.name_prefix}-processor-"
  description = "Log processor fleet. Egress to VPC endpoints only."
  vpc_id      = var.vpc_id

  tags = { Name = "${local.name_prefix}-processor" }

  lifecycle {
    create_before_destroy = true
  }
}

# Rules are separate resources (aws_vpc_security_group_*_rule), not inline
# blocks. Inline rules are authoritative for the whole group, so any rule added
# out-of-band during an incident gets silently reverted on the next apply, and
# a single rule change rewrites the entire group. Separate resources also give
# every rule its own description, which is what you want at 3am when you are
# reading a group with 40 rules in it.

resource "aws_vpc_security_group_egress_rule" "processor_to_endpoints" {
  security_group_id            = aws_security_group.processor.id
  description                  = "HTTPS to VPC interface endpoints (Kinesis, Firehose, KMS, SSM, CloudWatch)"
  referenced_security_group_id = aws_security_group.vpc_endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# S3 and DynamoDB are gateway endpoints, reached via a prefix list on the route
# table rather than an ENI, so egress is authorised against the prefix list ID.
resource "aws_vpc_security_group_egress_rule" "processor_to_s3" {
  security_group_id = aws_security_group.processor.id
  description       = "HTTPS to S3 via gateway endpoint"
  prefix_list_id    = data.aws_prefix_list.s3.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "processor_to_dynamodb" {
  security_group_id = aws_security_group.processor.id
  description       = "HTTPS to DynamoDB via gateway endpoint (KCL lease + metadata tables)"
  prefix_list_id    = data.aws_prefix_list.dynamodb.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# Optional legacy ingress. Only exists when enable_direct_ingest = true, and
# even then it is scoped to the VPC CIDR, never 0.0.0.0/0. There is no SSH
# rule anywhere in this file: access is via SSM Session Manager, which gives
# us IAM-controlled, CloudTrail-logged, keyless access with session recording.
resource "aws_vpc_security_group_ingress_rule" "syslog_from_vpc" {
  count = var.enable_direct_ingest ? 1 : 0

  security_group_id = aws_security_group.processor.id
  description       = "Syslog-over-TLS from in-VPC senders and the internal NLB"
  cidr_ipv4         = data.aws_vpc.selected.cidr_block
  ip_protocol       = "tcp"
  from_port         = var.syslog_port
  to_port           = var.syslog_port
}

# --- VPC endpoint security group ---------------------------------------------

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${local.name_prefix}-vpce-"
  description = "Interface endpoints for the log pipeline"
  vpc_id      = var.vpc_id

  tags = { Name = "${local.name_prefix}-vpce" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_processor" {
  security_group_id            = aws_security_group.vpc_endpoints.id
  description                  = "HTTPS from the log processor fleet"
  referenced_security_group_id = aws_security_group.processor.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# --- Endpoints ---------------------------------------------------------------

data "aws_vpc" "selected" {
  id = var.vpc_id
}

data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.region}.s3"
}

data "aws_prefix_list" "dynamodb" {
  name = "com.amazonaws.${data.aws_region.current.region}.dynamodb"
}

data "aws_route_tables" "private" {
  vpc_id = var.vpc_id

  filter {
    name   = "association.subnet-id"
    values = var.private_subnet_ids
  }
}

locals {
  interface_endpoints = {
    kinesis_streams  = "kinesis-streams"
    kinesis_firehose = "kinesis-firehose"
    kms              = "kms"
    logs             = "logs"
    monitoring       = "monitoring"
    ssm              = "ssm"
    ssmmessages      = "ssmmessages"
    ec2messages      = "ec2messages"
    sts              = "sts"
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = { Name = "${local.name_prefix}-vpce-${each.key}" }
}

resource "aws_vpc_endpoint" "gateway" {
  for_each = toset(["s3", "dynamodb"])

  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.${each.value}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_route_tables.private.ids

  tags = { Name = "${local.name_prefix}-vpce-${each.value}" }
}
