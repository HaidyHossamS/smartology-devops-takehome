###############################################################################
# iam.tf
#
# The original snippet has no instance profile at all, which means the only way
# that box can talk to AWS is with static access keys baked into userdata or an
# env file. That is how long-lived credentials end up in an AMI, in a git repo,
# and eventually in someone else's hands.
#
# Every policy here is scoped to specific ARNs. No "Resource": "*" except where
# the API genuinely does not support resource-level permissions, and those are
# constrained with conditions instead.
###############################################################################

# --- Processor instance role --------------------------------------------------

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "processor" {
  name_prefix          = "${local.name_prefix}-ec2-"
  assume_role_policy   = data.aws_iam_policy_document.ec2_assume.json
  max_session_duration = 3600

  # Ceiling on what this role can ever do, even if someone attaches a wider
  # policy to it later. A permissions boundary is the difference between "we
  # trust the review process" and "the blast radius is bounded by design".
  # Left null here because the boundary policy is owned by the security team's
  # state file; wire it in via var in a real deployment.
  # permissions_boundary = var.permissions_boundary_arn

  tags = { Name = "${local.name_prefix}-ec2" }
}

resource "aws_iam_instance_profile" "processor" {
  name_prefix = "${local.name_prefix}-"
  role        = aws_iam_role.processor.name
}

# Session Manager instead of SSH. No port 22, no key pairs to rotate or lose,
# every session authenticated by IAM and recorded in CloudTrail.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.processor.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "processor" {
  # Read the stream. Note there is no kinesis:PutRecord here — the processors
  # consume, they never produce. If a parser bug ever tried to write back into
  # its own input stream, IAM stops the loop before it starts.
  statement {
    sid    = "ConsumeStream"
    effect = "Allow"

    actions = [
      "kinesis:DescribeStream",
      "kinesis:DescribeStreamSummary",
      "kinesis:DescribeStreamConsumer",
      "kinesis:GetShardIterator",
      "kinesis:GetRecords",
      "kinesis:ListShards",
      "kinesis:SubscribeToShard",
      "kinesis:RegisterStreamConsumer",
    ]

    resources = [
      aws_kinesis_stream.ingest.arn,
      "${aws_kinesis_stream.ingest.arn}/*",
    ]
  }

  # KCL 3.x keeps its state in three DynamoDB tables named after the
  # application: the lease table, the worker-metrics table and the
  # coordinator-state table. CreateTable is required even when the tables
  # already exist, because the library calls it on startup and tolerates the
  # ResourceInUseException. Scoped to the name prefix, not to "*".
  statement {
    sid    = "KclLeaseAndMetadataTables"
    effect = "Allow"

    actions = [
      "dynamodb:CreateTable",
      "dynamodb:DescribeTable",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:UpdateTimeToLive",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Scan",
      "dynamodb:Query",
      "dynamodb:GetRecords",
    ]

    resources = [
      "arn:${local.partition}:dynamodb:${data.aws_region.current.region}:${local.account_id}:table/${local.kcl_app_name}",
      "arn:${local.partition}:dynamodb:${data.aws_region.current.region}:${local.account_id}:table/${local.kcl_app_name}-*",
    ]
  }

  # Write the processed output. PutRecordBatch only — no delete, no update,
  # no ability to reconfigure the delivery stream.
  statement {
    sid    = "DeliverToFirehose"
    effect = "Allow"

    actions = [
      "firehose:PutRecord",
      "firehose:PutRecordBatch",
    ]

    resources = [aws_kinesis_firehose_delivery_stream.s3.arn]
  }

  # Decrypt the stream payloads. ViaService means this grant only works when
  # the call arrives through Kinesis or Firehose; it cannot be used to decrypt
  # arbitrary ciphertext by calling KMS directly.
  statement {
    sid    = "UseCmkViaPipelineServices"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]

    resources = [aws_kms_key.logs.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "kinesis.${data.aws_region.current.region}.amazonaws.com",
        "firehose.${data.aws_region.current.region}.amazonaws.com",
        "s3.${data.aws_region.current.region}.amazonaws.com",
      ]
    }
  }

  # PutMetricData has no resource-level permissions, so it is scoped by
  # namespace condition instead. Without this the role could write metrics into
  # any namespace, including overwriting the ones our alarms read.
  statement {
    sid       = "PublishOwnMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["Smartology/LogPipeline", "AWS/KinesisClientLibrary"]
    }
  }

  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]

    resources = ["${aws_cloudwatch_log_group.processor.arn}:*"]
  }

  # Read only this service's parameters, not the whole parameter store.
  statement {
    sid    = "ReadOwnConfig"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]

    resources = [
      "arn:${local.partition}:ssm:${data.aws_region.current.region}:${local.account_id}:parameter/${var.name}/${var.environment}/*",
    ]
  }

  # Needed by the lifecycle hook so a draining instance can say "I have
  # finished checkpointing, you may terminate me now".
  statement {
    sid     = "CompleteLifecycleAction"
    effect  = "Allow"
    actions = ["autoscaling:CompleteLifecycleAction"]
    # Wildcard suffix because the ASG uses name_prefix, so its final name
    # carries a Terraform-generated suffix.
    resources = ["arn:${local.partition}:autoscaling:${data.aws_region.current.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/${local.name_prefix}-*"]
  }
}

resource "aws_iam_role_policy" "processor" {
  name_prefix = "${local.name_prefix}-"
  role        = aws_iam_role.processor.id
  policy      = data.aws_iam_policy_document.processor.json
}

# --- Firehose delivery role ---------------------------------------------------

data "aws_iam_policy_document" "firehose_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }

    # Confused-deputy protection: without this, any other AWS account could in
    # principle induce Firehose to assume our role. sts:ExternalId on a service
    # principal is the standard mitigation.
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [local.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "firehose" {
  name_prefix        = "${local.name_prefix}-fh-"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json

  tags = { Name = "${local.name_prefix}-firehose" }
}

data "aws_iam_policy_document" "firehose" {
  statement {
    sid    = "WriteToLake"
    effect = "Allow"

    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
    ]

    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*",
    ]
  }

  statement {
    sid    = "UseCmk"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]

    resources = [aws_kms_key.logs.arn]
  }

  # Firehose reads the Glue table to know how to write Parquet.
  statement {
    sid    = "ReadSchema"
    effect = "Allow"

    actions = [
      "glue:GetTable",
      "glue:GetTableVersion",
      "glue:GetTableVersions",
      "glue:GetDatabase",
    ]

    resources = [
      "arn:${local.partition}:glue:${data.aws_region.current.region}:${local.account_id}:catalog",
      aws_glue_catalog_database.logs.arn,
      "arn:${local.partition}:glue:${data.aws_region.current.region}:${local.account_id}:table/${aws_glue_catalog_database.logs.name}/*",
    ]
  }

  statement {
    sid       = "WriteDeliveryLogs"
    effect    = "Allow"
    actions   = ["logs:PutLogEvents", "logs:CreateLogStream"]
    resources = ["${aws_cloudwatch_log_group.firehose.arn}:*"]
  }
}

resource "aws_iam_role_policy" "firehose" {
  name_prefix = "${local.name_prefix}-fh-"
  role        = aws_iam_role.firehose.id
  policy      = data.aws_iam_policy_document.firehose.json
}
