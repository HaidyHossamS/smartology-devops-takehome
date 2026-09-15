###############################################################################
# observability.tf
#
# The original snippet has no alarms at all, which means the first person to
# notice the log pipeline is down is a compliance auditor, six weeks later,
# asking why there is a gap.
#
# The alarm that earns its keep here is the last one: NoRecordsProcessed.
# Everything else tells you something broke. That one tells you something
# stopped, quietly, which on a log pipeline is the failure mode that actually
# costs you — you cannot retroactively collect logs you never ingested.
###############################################################################

resource "aws_sns_topic" "alarms" {
  name              = "${local.name_prefix}-alarms"
  kms_master_key_id = aws_kms_key.logs.arn

  tags = { Name = "${local.name_prefix}-alarms" }
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alarm_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

locals {
  alarm_actions = [aws_sns_topic.alarms.arn]
}

# --- Are we keeping up? -------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "iterator_age" {
  alarm_name        = "${local.name_prefix}-consumer-falling-behind"
  alarm_description = <<-EOT
    Consumers are more than 5 minutes behind the stream.

    Runbook: check per-shard IteratorAge to distinguish a hot shard (bad
    partition key, one tenant dominating) from a fleet-wide slowdown. If it is
    fleet-wide, check the Firehose delivery metrics first — the usual cause is
    back-pressure from downstream, not the consumers themselves.
  EOT

  namespace   = "AWS/Kinesis"
  metric_name = "GetRecords.IteratorAgeMilliseconds"
  statistic   = "Maximum"
  period      = 60

  dimensions = {
    StreamName = aws_kinesis_stream.ingest.name
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = 300000 # 5 minutes
  evaluation_periods  = 3
  datapoints_to_alarm = 2

  treat_missing_data = "breaching"
  alarm_actions      = concat(local.alarm_actions, [aws_autoscaling_policy.backlog.arn])
  ok_actions         = local.alarm_actions
}

# --- Is the buffer about to overflow? -----------------------------------------
# Only meaningful in provisioned mode; on-demand scales itself.

resource "aws_cloudwatch_metric_alarm" "write_throttles" {
  count = var.stream_mode == "PROVISIONED" ? 1 : 0

  alarm_name        = "${local.name_prefix}-producers-throttled"
  alarm_description = "Producers are being throttled writing to Kinesis. Records are being rejected: this is active data loss unless producers retry. Add shards."

  namespace   = "AWS/Kinesis"
  metric_name = "WriteProvisionedThroughputExceeded"
  statistic   = "Sum"
  period      = 60

  dimensions = {
    StreamName = aws_kinesis_stream.ingest.name
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 2

  treat_missing_data = "notBreaching"
  alarm_actions      = local.alarm_actions
}

# --- Is the archive actually being written? -----------------------------------

resource "aws_cloudwatch_metric_alarm" "firehose_freshness" {
  alarm_name        = "${local.name_prefix}-archive-stale"
  alarm_description = "Firehose has not landed data in S3 within twice the configured buffer interval. Check the delivery stream's CloudWatch log group for permission or schema-conversion errors."

  namespace   = "AWS/Firehose"
  metric_name = "DeliveryToS3.DataFreshness"
  statistic   = "Maximum"
  period      = 300

  dimensions = {
    DeliveryStreamName = aws_kinesis_firehose_delivery_stream.s3.name
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = var.firehose_buffer_seconds * 2
  evaluation_periods  = 2

  treat_missing_data = "breaching"
  alarm_actions      = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "firehose_conversion_failures" {
  alarm_name        = "${local.name_prefix}-parquet-conversion-failing"
  alarm_description = <<-EOT
    Firehose is failing to convert records to Parquet. Records are landing in
    the errors/ prefix as raw JSON rather than in the queryable table.

    Almost always means an upstream service changed its log shape and the Glue
    schema no longer matches. Data is not lost — it is in errors/ — but it is
    invisible to Athena until the schema is updated and the objects replayed.
  EOT

  namespace   = "AWS/Firehose"
  metric_name = "FailedConversion.Records"
  statistic   = "Sum"
  period      = 300

  dimensions = {
    DeliveryStreamName = aws_kinesis_firehose_delivery_stream.s3.name
  }

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1

  treat_missing_data = "notBreaching"
  alarm_actions      = local.alarm_actions
}

# --- Is the fleet there at all? -----------------------------------------------

resource "aws_cloudwatch_metric_alarm" "fleet_capacity" {
  alarm_name        = "${local.name_prefix}-fleet-below-minimum"
  alarm_description = "In-service instance count has dropped below the configured minimum. Check for a launch failure (AMI, IAM, capacity) or an instance refresh that stalled."

  namespace   = "AWS/AutoScaling"
  metric_name = "GroupInServiceInstances"
  statistic   = "Minimum"
  period      = 60

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.processor.name
  }

  comparison_operator = "LessThanThreshold"
  threshold           = var.min_size
  evaluation_periods  = 5
  datapoints_to_alarm = 3

  treat_missing_data = "breaching"
  alarm_actions      = local.alarm_actions
}

# --- Has everything gone quiet? -----------------------------------------------
#
# treat_missing_data = "breaching" is the whole point. If the fleet dies, or
# the parser starts throwing on every record, or an upstream service stops
# emitting, this metric stops being published — and an alarm that treats
# missing data as OK will sit there green while the pipeline is stone dead.
#
# This is the alarm I would keep if I were only allowed one.

resource "aws_cloudwatch_metric_alarm" "no_records_processed" {
  alarm_name        = "${local.name_prefix}-no-records-processed"
  alarm_description = <<-EOT
    The pipeline has processed no records for 15 minutes.

    This fires on silence, not on errors. Check, in order:
      1. ASG in-service count      (did the fleet go away?)
      2. Kinesis IncomingRecords   (are producers still sending?)
      3. Processor log group       (is the parser throwing on every record?)

    If IncomingRecords is healthy and this is firing, the loss is happening
    inside our code and the data is still replayable from the stream. Fix
    forward, then reset the KCL checkpoint to reprocess.
  EOT

  namespace   = "Smartology/LogPipeline"
  metric_name = "RecordsProcessed"
  statistic   = "Sum"
  period      = 300

  dimensions = {
    Environment = var.environment
    Service     = var.name
  }

  comparison_operator = "LessThanThreshold"
  threshold           = var.no_data_alarm_threshold
  evaluation_periods  = 3

  treat_missing_data = "breaching"
  alarm_actions      = local.alarm_actions
  ok_actions         = local.alarm_actions
}

# --- Composite alarm ----------------------------------------------------------
# One page, not seven. During a real incident the failure modes above tend to
# fire together, and six simultaneous pages is how an on-call engineer loses
# twenty minutes to acknowledging alerts instead of reading graphs.

resource "aws_cloudwatch_composite_alarm" "pipeline_degraded" {
  alarm_name        = "${local.name_prefix}-PIPELINE-DEGRADED"
  alarm_description = "Composite: the log pipeline is not healthy. See the child alarms for which dimension failed."

  alarm_rule = join(" OR ", [
    "ALARM(${aws_cloudwatch_metric_alarm.no_records_processed.alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.iterator_age.alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.firehose_freshness.alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.fleet_capacity.alarm_name})",
  ])

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}
