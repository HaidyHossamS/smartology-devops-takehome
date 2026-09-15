###############################################################################
# ingest.tf — the durability story
#
# The original snippet processes logs on an instance's local disk. When that
# instance dies, everything in flight dies with it and there is no way to know
# what was lost, let alone replay it. This file replaces that with a durable,
# replayable buffer in front and an immutable archive behind:
#
#   producers -> Kinesis (7d replay) -> processor fleet -> Firehose -> S3 (Parquet)
#
# The two properties that matter:
#   1. The processors are now stateless. Losing one costs nothing; its shard
#      lease is picked up by a peer and reprocessed from the last checkpoint.
#   2. A bad parser deploy is recoverable. Roll back, reset the KCL checkpoint,
#      and reprocess the last N hours out of Kinesis. Without the buffer, a bad
#      parser silently destroys data you can never get back.
###############################################################################

# --- Kinesis Data Stream ------------------------------------------------------

resource "aws_kinesis_stream" "ingest" {
  name             = "${local.name_prefix}-ingest"
  retention_period = var.stream_retention_hours

  # Omit shard_count entirely in ON_DEMAND mode; setting it is an error.
  shard_count = var.stream_mode == "PROVISIONED" ? var.shard_count : null

  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.logs.arn

  stream_mode_details {
    stream_mode = var.stream_mode
  }

  # Shard-level metrics are only meaningful (and only billed) in provisioned
  # mode. IteratorAgeMilliseconds is the single most important metric on this
  # whole pipeline: it is the answer to "are we keeping up?"
  shard_level_metrics = var.stream_mode == "PROVISIONED" ? [
    "IncomingBytes",
    "IncomingRecords",
    "IteratorAgeMilliseconds",
    "ReadProvisionedThroughputExceeded",
    "WriteProvisionedThroughputExceeded",
  ] : []

  tags = { Name = "${local.name_prefix}-ingest" }
}

# --- S3 log lake --------------------------------------------------------------

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "logs" {
  bucket = "${local.name_prefix}-lake-${random_id.bucket_suffix.hex}"

  # Object Lock can only be enabled at creation time. If compliance decides in
  # six months that they need it, that is a bucket migration, not a flag flip.
  object_lock_enabled = var.enable_object_lock

  force_destroy = !local.is_prod

  tags = { Name = "${local.name_prefix}-lake" }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
    # Bucket keys cut KMS request costs by ~99% on high object counts. On a log
    # lake writing millions of objects, leaving this off is a real bill.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  # Required by the provider once versioning is on, so that the rules have a
  # deterministic starting point.
  depends_on = [aws_s3_bucket_versioning.logs]

  rule {
    id     = "raw-log-tiering"
    status = "Enabled"

    filter {
      prefix = "raw/"
    }

    transition {
      days          = 30
      storage_class = "INTELLIGENT_TIERING"
    }

    transition {
      days          = var.archive_after_days
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.expire_after_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  # Delivery failures land here. They should be drained and fixed, not kept
  # forever, but 90 days gives plenty of room to notice and replay.
  rule {
    id     = "expire-delivery-errors"
    status = "Enabled"

    filter {
      prefix = "errors/"
    }

    expiration {
      days = 90
    }
  }
}

data "aws_iam_policy_document" "logs_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Belt and braces with the bucket-level default encryption: this rejects any
  # write that explicitly asks for something other than our CMK.
  statement {
    sid    = "DenyWrongKmsKey"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/*"]

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.logs.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  policy     = data.aws_iam_policy_document.logs_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# --- Glue catalog -------------------------------------------------------------
# Firehose converts JSON to Parquet on the way to S3, which needs a schema.
# The payoff is that the archive is directly queryable with Athena at roughly
# a tenth the scan cost of raw JSON, so "find every failed login for this user
# last March" is a 20-second query instead of a data engineering project.

resource "aws_glue_catalog_database" "logs" {
  name        = replace("${local.name_prefix}_lake", "-", "_")
  description = "Schema for the ${var.name} log lake"
}

resource "aws_glue_catalog_table" "logs" {
  name          = "app_logs"
  database_name = aws_glue_catalog_database.logs.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification        = "parquet"
    EXTERNAL              = "TRUE"
    "parquet.compression" = "SNAPPY"

    # Partition projection. Without this the table is defined, Firehose writes
    # objects into raw/dt=YYYY-MM-DD/ exactly as configured, and Athena returns
    # zero rows — because a Glue partition key is only queryable once the
    # partition has been *registered*, which Firehose does not do.
    #
    # The usual workarounds are a Glue crawler on a schedule (costs money, adds
    # minutes of lag, and silently falls behind) or MSCK REPAIR TABLE (scans
    # the whole prefix and gets slower every day). Projection computes the
    # partition list from the query predicate instead, so there is nothing to
    # register, nothing to fall behind, and no per-partition metadata call.
    #
    # This is the single easiest way to ship a log lake that looks perfect in
    # the console and returns nothing to the people who need it.
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "2026-01-01,NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${aws_s3_bucket.logs.bucket}/raw/dt=$${dt}/"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.logs.bucket}/raw/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    columns {
      name = "timestamp"
      type = "timestamp"
    }
    columns {
      name = "level"
      type = "string"
    }
    columns {
      name = "service"
      type = "string"
    }
    columns {
      name = "host"
      type = "string"
    }
    columns {
      name = "trace_id"
      type = "string"
    }
    columns {
      name = "event"
      type = "string"
    }
    columns {
      name = "username"
      type = "string"
    }
    columns {
      name = "source_ip"
      type = "string"
    }
    columns {
      name = "message"
      type = "string"
    }
  }
}

# --- Firehose delivery --------------------------------------------------------

resource "aws_kinesis_firehose_delivery_stream" "s3" {
  name        = "${local.name_prefix}-to-s3"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.logs.arn
  }

  extended_s3_configuration {
    role_arn    = aws_iam_role.firehose.arn
    bucket_arn  = aws_s3_bucket.logs.arn
    kms_key_arn = aws_kms_key.logs.arn

    # Hive-style partitioning so Athena can prune whole days without scanning.
    prefix              = "raw/dt=!{timestamp:yyyy-MM-dd}/"
    error_output_prefix = "errors/!{firehose:error-output-type}/dt=!{timestamp:yyyy-MM-dd}/"

    buffering_size     = var.firehose_buffer_mb
    buffering_interval = var.firehose_buffer_seconds

    # Compression is handled by the Parquet writer; setting both is an error.
    compression_format = "UNCOMPRESSED"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = "S3Delivery"
    }

    data_format_conversion_configuration {
      enabled = true

      input_format_configuration {
        deserializer {
          open_x_json_ser_de {}
        }
      }

      output_format_configuration {
        serializer {
          parquet_ser_de {
            compression = "SNAPPY"
          }
        }
      }

      schema_configuration {
        database_name = aws_glue_catalog_database.logs.name
        table_name    = aws_glue_catalog_table.logs.name
        role_arn      = aws_iam_role.firehose.arn
        region        = data.aws_region.current.region
      }
    }
  }

  tags = { Name = "${local.name_prefix}-to-s3" }
}

resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${local.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_cloudwatch_log_group" "processor" {
  name              = "/aws/ec2/${local.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}
