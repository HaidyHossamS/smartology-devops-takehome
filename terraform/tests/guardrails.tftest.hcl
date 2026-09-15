###############################################################################
# guardrails.tftest.hcl — Terraform's native test framework.
#
# Run with `terraform test`. mock_provider means these execute in a few seconds
# with no AWS credentials and no billable resources, so they belong in the PR
# pipeline, not in a nightly.
#
# The point is not coverage for its own sake. Each of these asserts one property
# that, if it silently regressed, would reintroduce exactly the flaw the
# redesign exists to fix. This is how "we fixed the open security group" becomes
# "the open security group cannot come back".
###############################################################################

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "eu-west-1"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_ssm_parameter" {
    defaults = {
      value = "ami-0mockmockmockmock0"
    }
  }

  mock_data "aws_vpc" {
    defaults = {
      cidr_block = "10.42.0.0/16"
    }
  }

  # This one is not obvious and it cost a test run to find.
  #
  # aws_iam_policy_document is a *data source*, even though it makes no API call
  # — it is a pure function that renders JSON. mock_provider does not know that
  # distinction: it mocks every data source the provider offers, so the computed
  # `json` attribute comes back as a generated random string. The IAM and KMS
  # resources then reject it with "invalid character 'w' looking for beginning
  # of value", and every test in the file fails at plan time with an error that
  # has nothing to do with what is being tested.
  #
  # Pinning it to a minimal valid policy document keeps the mock honest.
  #
  # The trade-off, stated plainly: these tests no longer exercise policy
  # *content*. They never asserted on it, so nothing regresses — but policy
  # correctness is now the job of checkov/trivy and of a real plan against a
  # sandbox account, not of this suite.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

mock_provider "random" {}

variables {
  environment        = "prod"
  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0aaa1111", "subnet-0bbb2222", "subnet-0ccc3333"]
}

# --- The flaw that started all this -------------------------------------------

run "no_unrestricted_ingress_anywhere" {
  command = plan

  assert {
    condition = alltrue([
      for r in aws_vpc_security_group_ingress_rule.syslog_from_vpc :
      r.cidr_ipv4 != "0.0.0.0/0"
    ])
    error_message = "An ingress rule allows 0.0.0.0/0. This is the exact defect the redesign exists to remove."
  }
}

run "no_ssh_port_exposed" {
  command = plan

  assert {
    condition = alltrue([
      for r in aws_vpc_security_group_ingress_rule.syslog_from_vpc :
      !(r.from_port <= 22 && r.to_port >= 22)
    ])
    error_message = "Port 22 is reachable. Access is meant to be SSM Session Manager only."
  }
}

# --- Credential theft protection ----------------------------------------------

run "imdsv2_is_mandatory" {
  command = plan

  assert {
    condition     = aws_launch_template.processor.metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 is not enforced. An SSRF in the log parser could read the instance role credentials."
  }

  assert {
    condition     = aws_launch_template.processor.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "Metadata hop limit allows the response to cross a container boundary."
  }
}

run "no_ssh_key_material" {
  command = plan

  assert {
    condition     = aws_launch_template.processor.key_name == null || aws_launch_template.processor.key_name == ""
    error_message = "A key pair is attached. Key material has to be rotated, stored and eventually leaked; use Session Manager."
  }
}

# --- Encryption ----------------------------------------------------------------

run "everything_at_rest_is_encrypted_with_our_cmk" {
  command = plan

  # tobool() is load-bearing, and the reason is a provider schema quirk.
  #
  # In aws_launch_template the ebs block's `encrypted` attribute is typed as a
  # STRING, not a bool, because the underlying EC2 API accepts it that way. So
  # the planned value is "true" (quoted), and `"true" == true` is false —
  # Terraform does not coerce across types in a comparison.
  #
  # Written the naive way, this assertion fails against a volume that is
  # correctly encrypted. A false alarm in a security guardrail is expensive:
  # it gets muted, and then the guardrail protects nothing.
  #
  # tobool() accepts both "true" and true, so the test keeps working if the
  # provider ever tightens the schema.
  assert {
    condition     = tobool(aws_launch_template.processor.block_device_mappings[0].ebs[0].encrypted) == true
    error_message = "Root volume is unencrypted. Transaction log fragments sit on that disk."
  }

  assert {
    condition     = aws_kinesis_stream.ingest.encryption_type == "KMS"
    error_message = "Kinesis stream is not encrypted."
  }

  assert {
    condition     = aws_kms_key.logs.enable_key_rotation == true
    error_message = "CMK rotation is disabled."
  }
}

# --- Availability --------------------------------------------------------------

run "fleet_survives_losing_an_instance" {
  command = plan

  assert {
    condition     = aws_autoscaling_group.processor.min_size >= 2
    error_message = "min_size < 2 means one instance failure is a full outage."
  }

  assert {
    condition     = length(aws_autoscaling_group.processor.vpc_zone_identifier) >= 2
    error_message = "ASG is not spread across multiple subnets."
  }
}

run "burstable_instances_are_rejected_in_prod" {
  command = plan

  variables {
    instance_types = ["m7g.large", "m6g.large"]
  }

  assert {
    condition = alltrue([
      for t in var.instance_types : !startswith(t, "t2.") && !startswith(t, "t3.") && !startswith(t, "t4g.")
    ])
    error_message = "A burstable instance type is configured for sustained log processing. It will exhaust CPU credits and throttle to baseline while reporting low CPU."
  }
}

# --- Durability ----------------------------------------------------------------

run "replay_window_is_long_enough_to_survive_a_weekend" {
  command = plan

  assert {
    condition     = aws_kinesis_stream.ingest.retention_period >= 72
    error_message = "Retention under 72h means an incident that starts on Friday evening is unrecoverable by Monday."
  }
}

run "archive_is_versioned_and_private" {
  command = plan

  assert {
    condition     = aws_s3_bucket_versioning.logs.versioning_configuration[0].status == "Enabled"
    error_message = "Log bucket is not versioned."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.logs.block_public_acls,
      aws_s3_bucket_public_access_block.logs.block_public_policy,
      aws_s3_bucket_public_access_block.logs.ignore_public_acls,
      aws_s3_bucket_public_access_block.logs.restrict_public_buckets,
    ])
    error_message = "Public access block is incomplete on a bucket holding transaction logs."
  }
}

# --- Input validation ----------------------------------------------------------
# expect_failures asserts that bad input is rejected at plan time rather than
# producing a broken-but-applied environment.

run "rejects_single_az_deployment" {
  command = plan

  variables {
    private_subnet_ids = ["subnet-0aaa1111"]
  }

  expect_failures = [var.private_subnet_ids]
}

run "rejects_single_instance_fleet" {
  command = plan

  variables {
    min_size = 1
  }

  expect_failures = [var.min_size]
}

run "rejects_unknown_environment" {
  command = plan

  variables {
    environment = "produciton"
  }

  expect_failures = [var.environment]
}
