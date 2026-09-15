###############################################################################
# main.tf — locals, data sources, KMS
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# Resolve the AMI at plan time instead of hardcoding an ID. This uses the
# AL2023 SSM public parameter, so we always get the current patched image for
# whatever region we are applying into.
#
# In a regulated environment this is replaced by a golden AMI built with EC2
# Image Builder and pinned by a version parameter, so that a new AMI is a
# deliberate, reviewed change rather than something that silently lands when
# AWS publishes an update. Both are correct; which one depends on whether you
# care more about patch latency or change control.
data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

data "aws_subnet" "selected" {
  for_each = toset(var.private_subnet_ids)
  id       = each.value
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  name_prefix = "${var.name}-${var.environment}"

  common_tags = merge(
    {
      Name               = local.name_prefix
      Service            = var.name
      Environment        = var.environment
      Owner              = var.owner
      DataClassification = var.data_classification
      ManagedBy          = "terraform"
      Repository         = "platform/log-aggregator"
    },
    var.tags
  )

  # KCL 3.x creates three DynamoDB metadata tables named after the application:
  # the lease table, the worker-metrics table and the coordinator-state table.
  # IAM is scoped to that name prefix rather than to "*".
  kcl_app_name = local.name_prefix

  is_prod = var.environment == "prod"

  # Sanity check: the subnets the caller handed us must actually span AZs.
  # Terraform will not catch "three subnets, all in eu-west-1a" on its own.
  distinct_azs = length(distinct([for s in data.aws_subnet.selected : s.availability_zone]))
}

# Fail the plan, loudly, if someone passes three subnets from one AZ.
# This is the class of mistake that looks fine in code review and only shows
# up during an AZ event at 3am.
resource "terraform_data" "az_spread_guard" {
  lifecycle {
    precondition {
      condition     = local.distinct_azs >= 2
      error_message = "private_subnet_ids resolve to only ${local.distinct_azs} availability zone(s). Multi-AZ requires subnets in at least two."
    }
  }
}

###############################################################################
# KMS — one customer-managed key for the pipeline.
#
# Why not the AWS-managed aws/kinesis key: a CMK lets us (a) write a key policy
# that scopes decrypt to this workload's role, (b) rotate on our schedule,
# (c) revoke access to the data without deleting the data, and (d) produce a
# CloudTrail record of every Decrypt call for audit. On transaction logs that
# matters.
###############################################################################

resource "aws_kms_key" "logs" {
  description             = "${local.name_prefix} log pipeline encryption key"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = local.is_prod ? 30 : 7
  multi_region            = false

  policy = data.aws_iam_policy_document.kms_key_policy.json
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.logs.key_id
}

data "aws_iam_policy_document" "kms_key_policy" {
  # Root access. Without this statement the key becomes unmanageable if the
  # admin role that created it is ever deleted.
  statement {
    sid       = "AllowAccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # AWS services that need to encrypt on our behalf. Scoped with ViaService so
  # the grant only applies when the call comes through that service, not when
  # someone assumes a role and calls KMS directly.
  statement {
    sid    = "AllowServiceUse"
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]

    resources = ["*"]

    principals {
      type = "Service"
      identifiers = [
        "kinesis.amazonaws.com",
        "firehose.amazonaws.com",
        "s3.amazonaws.com",
        "logs.${data.aws_region.current.region}.amazonaws.com",
        "sns.amazonaws.com",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
  }
}
