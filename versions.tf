# -----------------------------------------------------------------------------
# Terraform and AWS Provider Version Requirements
# -----------------------------------------------------------------------------
# Terraform >= 1.5.0: Required for improved type constraints, optional object 
# type attributes, and better handling of complex validation rules
# AWS Provider >= 5.0.0: Required for latest EC2 dedicated host features,
# security improvements, and bug fixes
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }
  }
}
