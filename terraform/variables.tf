###############################################################################
# variables.tf
#
# Every variable is typed and validated. Validation blocks are cheap and they
# turn a 40-minute failed apply into a 2-second plan error.
###############################################################################

variable "region" {
  description = "AWS region for all resources in this module."
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Short service name. Used as the prefix for every resource name."
  type        = string
  default     = "log-processor"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.name))
    error_message = "name must be 3-25 chars, lowercase alphanumeric and hyphens, starting with a letter."
  }
}

variable "environment" {
  description = "Deployment environment. Drives retention, sizing and deletion protection."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "owner" {
  description = "Owning team. Goes on every resource and into the alarm routing."
  type        = string
  default     = "platform-engineering"
}

variable "data_classification" {
  description = "Data sensitivity of the logs flowing through this pipeline."
  type        = string
  default     = "confidential"

  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "data_classification must be one of: public, internal, confidential, restricted."
  }
}

# --- Networking -------------------------------------------------------------
# We consume the VPC rather than create it. Network topology in a real org is
# owned by a separate team/state file with its own change cadence; coupling a
# workload module to VPC creation means every app deploy can touch routing.

variable "vpc_id" {
  description = "ID of the existing VPC to deploy into."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "vpc_id must look like vpc-xxxxxxxx."
  }
}

variable "private_subnet_ids" {
  description = "Private subnet IDs, one per AZ. Minimum of two AZs is enforced."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Provide at least two private subnets in different AZs. A single-AZ log pipeline is not an availability story."
  }
}

# --- Ingest -----------------------------------------------------------------

variable "stream_mode" {
  description = "Kinesis capacity mode. ON_DEMAND absorbs unpredictable transaction spikes; PROVISIONED is ~30-40% cheaper at steady, well-understood volume."
  type        = string
  default     = "ON_DEMAND"

  validation {
    condition     = contains(["ON_DEMAND", "PROVISIONED"], var.stream_mode)
    error_message = "stream_mode must be ON_DEMAND or PROVISIONED."
  }
}

variable "shard_count" {
  description = "Shard count. Only used when stream_mode = PROVISIONED."
  type        = number
  default     = 4

  validation {
    condition     = var.shard_count >= 1 && var.shard_count <= 500
    error_message = "shard_count must be between 1 and 500."
  }
}

variable "stream_retention_hours" {
  description = "Kinesis retention. This is the replay window: how far back we can reprocess after a bad deploy or a downstream outage. 24h is the default; we want a week."
  type        = number
  default     = 168

  validation {
    condition     = var.stream_retention_hours >= 24 && var.stream_retention_hours <= 8760
    error_message = "stream_retention_hours must be between 24 and 8760."
  }
}

variable "enable_direct_ingest" {
  description = "Stand up an internal NLB in front of the fleet for legacy senders that can only push syslog/TCP and cannot call the Kinesis API. Off by default: the pull-based path needs no open ports at all."
  type        = bool
  default     = false
}

variable "syslog_port" {
  description = "TCP port for the optional legacy syslog listener."
  type        = number
  default     = 6514
}

# --- Compute ----------------------------------------------------------------

variable "instance_types" {
  description = "Candidate instance types for the mixed-instances policy, best first. Graviton by default: ~20% better price/performance on this kind of parse-and-forward workload."
  type        = list(string)
  default     = ["m7g.large", "m6g.large", "m7gd.large"]

  validation {
    condition     = length(var.instance_types) >= 2
    error_message = "Give the ASG at least two instance types, or a capacity shortfall in one type takes the fleet down."
  }
}

variable "min_size" {
  description = "Minimum instances. Must be >= 2 so a single instance failure is never a full outage."
  type        = number
  default     = 3

  validation {
    condition     = var.min_size >= 2
    error_message = "min_size must be at least 2."
  }
}

variable "max_size" {
  description = "Maximum instances. Sized for peak-hour burst plus backlog catch-up."
  type        = number
  default     = 12
}

variable "on_demand_base_capacity" {
  description = "Instances always served by On-Demand. Everything above this is Spot. Safe here because Kinesis checkpointing makes consumers interruption-tolerant: a reclaimed host just drops its lease and a peer picks up the shard."
  type        = number
  default     = 2
}

variable "root_volume_size" {
  description = "Root EBS volume size in GiB. Sized for the local disk buffer, not just the OS."
  type        = number
  default     = 50
}

# --- Durability -------------------------------------------------------------

variable "firehose_buffer_mb" {
  description = "Firehose buffer size in MiB. Bigger buffers make bigger, cheaper Parquet files but raise end-to-end latency."
  type        = number
  default     = 128

  validation {
    condition     = var.firehose_buffer_mb >= 64 && var.firehose_buffer_mb <= 128
    error_message = "With Parquet conversion enabled, Firehose requires a buffer between 64 and 128 MiB."
  }
}

variable "firehose_buffer_seconds" {
  description = "Maximum seconds Firehose holds records before flushing. This is the floor on how stale the log lake can be."
  type        = number
  default     = 300
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the agent's own logs."
  type        = number
  default     = 30
}

variable "archive_after_days" {
  description = "Days before raw log objects move to Glacier Instant Retrieval."
  type        = number
  default     = 90
}

variable "expire_after_days" {
  description = "Days before raw log objects are deleted. Set from the legal/compliance retention policy, not from a gut feeling about storage cost."
  type        = number
  default     = 2555 # 7 years
}

variable "enable_object_lock" {
  description = "Enable S3 Object Lock (governance mode) on the log bucket. Makes the archive tamper-evident for audit. Must be set at bucket creation and cannot be turned on later."
  type        = bool
  default     = false
}

# --- Alerting ---------------------------------------------------------------

variable "alarm_email" {
  description = "Optional email for the alarm topic. Real deployments wire the topic to PagerDuty instead."
  type        = string
  default     = ""
}

variable "no_data_alarm_threshold" {
  description = "Records-processed-per-minute below which we page. A log pipeline that silently stops is worse than one that loudly breaks."
  type        = number
  default     = 1
}

variable "tags" {
  description = "Extra tags merged into the default tag set."
  type        = map(string)
  default     = {}
}
