###############################################################################
# compute.tf — the availability story
#
# One t2.micro becomes an Auto Scaling Group across every AZ we were given,
# with health checks, automated replacement, rolling deploys and scale-out
# driven by the only metric that actually matters here: how far behind the
# stream we are.
#
# On t2.micro specifically: T-family instances run on CPU credits. A burstable
# instance handling sustained high-volume log parsing exhausts its credit
# balance within the hour and is then throttled to its 10% baseline — 10% of
# one vCPU. The pipeline does not fall over, it just gets slower and slower
# while every dashboard shows "CPU 10%, healthy". That is a much worse failure
# than a crash, because nothing pages.
###############################################################################

resource "aws_launch_template" "processor" {
  name_prefix            = "${local.name_prefix}-"
  image_id               = data.aws_ssm_parameter.al2023_arm64.value
  instance_type          = var.instance_types[0]
  update_default_version = true

  iam_instance_profile {
    arn = aws_iam_instance_profile.processor.arn
  }

  vpc_security_group_ids = [aws_security_group.processor.id]

  # No key_name. Access is SSM Session Manager only.

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size = var.root_volume_size
      volume_type = "gp3"
      iops        = 3000
      throughput  = 250

      encrypted  = true
      kms_key_id = aws_kms_key.logs.arn

      delete_on_termination = true
    }
  }

  # IMDSv2 required. This is the Capital One mitigation: with http_tokens set
  # to "required", a server-side request forgery in the log parser cannot read
  # the instance role's credentials, because the attacker cannot make the
  # victim send a PUT with the right header.
  #
  # hop_limit 1 means the metadata response cannot cross a container network
  # boundary. Raise to 2 only if the workload runs in Docker with bridge
  # networking, and know that you are widening the blast radius when you do.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  monitoring {
    enabled = true # 1-minute metrics; 5-minute resolution is useless in an incident
  }

  # Note what is deliberately NOT here: disable_api_termination.
  #
  # It looks like prudent production hygiene, and on a pet instance it is. On an
  # instance owned by an Auto Scaling group it is fighting the component whose
  # entire job is terminating instances — scale-in, unhealthy-host replacement
  # and instance refresh all work by terminating. AWS models this properly with
  # *instance scale-in protection*, which is an ASG-level concept and which the
  # ASG itself knows how to override when it must.
  #
  # The protection actually wanted here is against a human running `terraform
  # destroy` against prod, and that belongs at the Terraform and CI layer —
  # plan review, a protected workspace, and a pipeline that refuses destroy
  # plans on the prod branch — not at the EC2 API.

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tftpl", {
    stream_name     = aws_kinesis_stream.ingest.name
    delivery_stream = aws_kinesis_firehose_delivery_stream.s3.name
    kcl_app_name    = local.kcl_app_name
    region          = data.aws_region.current.region
    log_group       = aws_cloudwatch_log_group.processor.name
    asg_name        = local.name_prefix
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.common_tags, { Name = "${local.name_prefix}-worker" })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.common_tags, { Name = "${local.name_prefix}-worker-root" })
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "processor" {
  # name_prefix, not name — for exactly the reason given for the security
  # group above. With create_before_destroy and a fixed name, any change that
  # forces replacement tries to create a second ASG with a name AWS already
  # holds, and the apply deadlocks. Getting this right on the security group
  # and wrong on the ASG would be an easy and very annoying mistake.
  name_prefix         = "${local.name_prefix}-"
  vpc_zone_identifier = var.private_subnet_ids

  min_size         = var.min_size
  max_size         = var.max_size
  desired_capacity = var.min_size

  # EC2 health checks only notice that the hypervisor is alive. With the
  # optional NLB attached we use ELB checks, which notice that the *process*
  # is alive. The grace period must exceed worst-case boot + lease acquisition,
  # or the ASG kills instances that were about to become healthy and you get a
  # replacement loop that looks exactly like a crash loop.
  health_check_type         = var.enable_direct_ingest ? "ELB" : "EC2"
  health_check_grace_period = 300

  # Spread instances evenly across AZs and rebalance proactively when Spot
  # capacity in one AZ starts to look shaky.
  capacity_rebalance = true

  default_cooldown          = 120
  wait_for_capacity_timeout = "10m"
  # Do not report success until instances are actually in service. Without this
  # a CI pipeline goes green on a fleet that never came up.
  min_elb_capacity = var.enable_direct_ingest ? var.min_size : null

  target_group_arns = var.enable_direct_ingest ? [aws_lb_target_group.syslog[0].arn] : []

  mixed_instances_policy {
    instances_distribution {
      # Keep a floor of On-Demand for the steady state; burst on Spot.
      on_demand_base_capacity                  = var.on_demand_base_capacity
      on_demand_percentage_above_base_capacity = 0
      spot_allocation_strategy                 = "price-capacity-optimized"
      on_demand_allocation_strategy            = "lowest-price"
    }

    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.processor.id
        version            = aws_launch_template.processor.latest_version
      }

      # Multiple types means a capacity shortfall in one does not stall the
      # scale-out. Spot works here because the consumer is checkpointed and
      # idempotent: losing a worker costs one lease handover, not data.
      dynamic "override" {
        for_each = var.instance_types
        content {
          instance_type = override.value
        }
      }
    }
  }

  # Rolling deploys, natively. A new launch template version triggers a
  # controlled replacement that keeps 90% of capacity in service and pauses at
  # 50% so a bad build is caught before it has rolled the whole fleet.
  instance_refresh {
    strategy = "Rolling"

    preferences {
      min_healthy_percentage = 90
      instance_warmup        = 300
      checkpoint_percentages = [25, 50, 100]
      checkpoint_delay       = 600
      auto_rollback          = true
    }

    # No `triggers` block at all.
    #
    # I originally listed ["launch_template"], having already removed
    # "desired_capacity" (which is in ignore_changes below, so it could never
    # fire). `terraform validate` then pointed out that the remaining entry is
    # redundant too: a launch template change ALWAYS triggers an instance
    # refresh, so naming it explicitly adds nothing.
    #
    # Two rounds of the same lesson — config that looks like intent but has no
    # effect is worse than no config, because the next person assumes it does
    # something.
  }

  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    # desired_capacity is owned by the scaling policies at runtime. Without
    # this, every `terraform apply` snaps a scaled-out fleet back to min_size,
    # which is how you cause an outage by running a no-op plan.
    ignore_changes = [desired_capacity]
  }

  depends_on = [terraform_data.az_spread_guard]
}

# Give a terminating worker 120 seconds to finish its batch and checkpoint
# before the instance is torn out. This is what turns "at-least-once with a
# large duplicate window" into "at-least-once with a negligible one".
resource "aws_autoscaling_lifecycle_hook" "drain" {
  name                   = "${local.name_prefix}-drain"
  autoscaling_group_name = aws_autoscaling_group.processor.name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  default_result         = "CONTINUE"
  heartbeat_timeout      = 120
}

###############################################################################
# Scaling
#
# Two policies, because they answer different questions.
#
#   CPU target tracking answers "is the fleet working hard?" and handles the
#   normal daily curve smoothly.
#
#   Iterator age step scaling answers "are we falling behind?" — and that is
#   the one that actually matters. A fleet can sit at 40% CPU and still be
#   30 minutes behind the stream if it is blocked on a slow downstream call.
#   CPU alone would never scale out for that.
###############################################################################

resource "aws_autoscaling_policy" "cpu" {
  name                   = "${local.name_prefix}-cpu-target"
  autoscaling_group_name = aws_autoscaling_group.processor.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 55

    # disable_scale_in = true is load-bearing, and it took a second look to see
    # why.
    #
    # Target tracking creates its own pair of alarms and will remove capacity
    # whenever CPU sits below target. A Kinesis consumer blocked on a slow
    # downstream — the exact situation the backlog policy exists for — has LOW
    # CPU and a GROWING backlog. Leave scale-in enabled and the two policies
    # fight: the step policy adds instances because we are 20 minutes behind,
    # the CPU policy removes them because the new instances are idle waiting on
    # the same slow downstream, and the group oscillates while the backlog
    # grows. ASG conflict resolution favours the larger capacity in the moment,
    # but the cooldowns interleave and the result is thrash, not stability.
    #
    # So: CPU may only scale OUT. Scale-in belongs to the backlog policy, which
    # is the one that actually understands whether we are done.
    disable_scale_in = true
  }
}

resource "aws_autoscaling_policy" "backlog" {
  name                      = "${local.name_prefix}-backlog-step"
  autoscaling_group_name    = aws_autoscaling_group.processor.name
  policy_type               = "StepScaling"
  adjustment_type           = "PercentChangeInCapacity"
  metric_aggregation_type   = "Maximum"
  estimated_instance_warmup = 300

  # Aggressive on the way up. Backlog compounds: while you are debating whether
  # to add capacity, the stream keeps filling, and at some point the oldest
  # records age out of the retention window and are gone for good.
  #
  # Bounds are OFFSETS FROM THE ALARM THRESHOLD, not absolute values. The alarm
  # fires at 300s of lag, so:
  #   lower 0 / upper 300000  -> 5 to 10 minutes behind  -> +50% capacity
  #   lower 300000            -> more than 10 min behind -> +100% capacity
  # Reading these as absolute milliseconds is the classic way to build a step
  # policy that never fires its upper steps.
  step_adjustment {
    metric_interval_lower_bound = 0
    metric_interval_upper_bound = 300000
    scaling_adjustment          = 50
  }

  step_adjustment {
    metric_interval_lower_bound = 300000
    scaling_adjustment          = 100
  }
}

###############################################################################
# Optional legacy ingress
#
# The primary design is pull-based: producers write to Kinesis with the SDK or
# a local agent, and the fleet needs no inbound ports at all. That is the right
# answer and it is why the processor security group has no ingress rule by
# default.
#
# Reality intrudes in the form of appliances and legacy JVM services that can
# only emit syslog over TCP. For those, an internal NLB, in private subnets,
# reachable only from inside the VPC. TLS is terminated by the agent on the
# host rather than at the NLB, so the logs are encrypted right up to the
# process that parses them.
###############################################################################

resource "aws_lb" "syslog" {
  count = var.enable_direct_ingest ? 1 : 0

  name               = "${local.name_prefix}-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.private_subnet_ids

  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = { Name = "${local.name_prefix}-nlb" }
}

resource "aws_lb_target_group" "syslog" {
  count = var.enable_direct_ingest ? 1 : 0

  name_prefix = substr(var.name, 0, 6)
  port        = var.syslog_port
  protocol    = "TCP"
  vpc_id      = var.vpc_id

  deregistration_delay = 90 # must exceed the lifecycle hook drain window

  health_check {
    protocol            = "HTTP"
    path                = "/health"
    port                = 8080
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "syslog" {
  count = var.enable_direct_ingest ? 1 : 0

  load_balancer_arn = aws_lb.syslog[0].arn
  port              = var.syslog_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.syslog[0].arn
  }
}
