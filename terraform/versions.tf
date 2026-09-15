###############################################################################
# versions.tf — pin everything. An unpinned provider is an unreviewed change
# that lands on a Friday. Provider 6.x is current (6.62.0 as of Aug 2026);
# 6.57.0 was withdrawn mid-2026, which is exactly why we pin and test upgrades.
###############################################################################

terraform {
  required_version = "~> 1.13"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0, >= 6.20.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state with native S3 locking (Terraform >= 1.11 — `use_lockfile`
  # replaces the old DynamoDB lock table, one less resource to own).
  # Left commented so this module can be `plan`ed standalone in review.
  #
  # backend "s3" {
  #   bucket       = "smartology-tfstate-prod"
  #   key          = "platform/log-aggregator/terraform.tfstate"
  #   region       = "eu-west-1"
  #   encrypt      = true
  #   kms_key_id   = "alias/tfstate"
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.region

  # Tags applied to every taggable resource, without repeating them 40 times.
  # Cost allocation, incident routing and data-classification queries all
  # depend on these being present and consistent.
  default_tags {
    tags = local.common_tags
  }
}
