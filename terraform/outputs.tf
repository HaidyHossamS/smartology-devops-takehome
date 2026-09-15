###############################################################################
# outputs.tf — the contract this module exposes to producers and to operators
###############################################################################

output "ingest_stream_name" {
  description = "Kinesis stream producers write to. This is the only ingest contract; nothing writes to the processors directly."
  value       = aws_kinesis_stream.ingest.name
}

output "ingest_stream_arn" {
  description = "Stream ARN, for granting producer roles kinesis:PutRecord(s)."
  value       = aws_kinesis_stream.ingest.arn
}

output "delivery_stream_name" {
  description = "Firehose delivery stream the processors write to."
  value       = aws_kinesis_firehose_delivery_stream.s3.name
}

output "log_bucket" {
  description = "S3 bucket holding the Parquet log lake."
  value       = aws_s3_bucket.logs.bucket
}

output "athena_table" {
  description = "Fully qualified Glue table for querying the archive."
  value       = "${aws_glue_catalog_database.logs.name}.${aws_glue_catalog_table.logs.name}"
}

output "kms_key_arn" {
  description = "CMK protecting the stream, the archive and the EBS volumes."
  value       = aws_kms_key.logs.arn
}

output "processor_role_arn" {
  description = "Instance role. Grant this read access to anything the parser needs."
  value       = aws_iam_role.processor.arn
}

output "processor_security_group_id" {
  description = "Security group for the fleet. Producers reference this when writing their own egress rules."
  value       = aws_security_group.processor.id
}

output "autoscaling_group_name" {
  description = "ASG name, for instance refresh and for CLI operations during an incident."
  value       = aws_autoscaling_group.processor.name
}

output "alarm_topic_arn" {
  description = "SNS topic every alarm publishes to. Wire this to PagerDuty."
  value       = aws_sns_topic.alarms.arn
}

output "syslog_endpoint" {
  description = "Internal NLB DNS name for legacy syslog senders. Null unless enable_direct_ingest is true."
  value       = var.enable_direct_ingest ? "${aws_lb.syslog[0].dns_name}:${var.syslog_port}" : null
}

output "session_manager_hint" {
  description = "How to get a shell on a worker. There is no SSH key and no port 22 by design."
  value       = "aws ssm start-session --target <instance-id> --region ${data.aws_region.current.region}"
}
