terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # Partial configuration; values come from backend.hcl (see backend.hcl.example).
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project    = "security-guardrails"
      ManagedBy  = "terraform"
      Repository = "github.com/Monkmode-tech/aws-security-guardrails-detection"
      Owner      = var.owner
    }
  }
}
