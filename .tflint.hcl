plugin "aws" {
  enabled = true
  version = "0.21.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

config {
  module = true
  force = false
  disabled_by_default = false
  
  # Enable module inspection
  module_inspection = true
  
  # Specify working directory
  working_directory = "."
}

# General Terraform rules
rule "terraform_deprecated_index" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = true
}

rule "terraform_comment_syntax" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}

rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_typed_variables" {
  enabled = true
}

rule "terraform_naming_convention" {
  enabled = true
  format = "snake_case"
}

rule "terraform_required_version" {
  enabled = true
}

rule "terraform_required_providers" {
  enabled = true
}

rule "terraform_standard_module_structure" {
  enabled = true
}

# AWS specific rules
rule "aws_resource_missing_tags" {
  enabled = true
  tags = [
    "Environment", 
    "Project", 
    "Owner", 
    "ManagedBy"
  ]
}

rule "aws_instance_invalid_type" {
  enabled = true
}

# EC2 specific rules
rule "aws_instance_invalid_ami" {
  enabled = true
}

rule "aws_instance_previous_type" {
  enabled = true
}

# Security rules
rule "aws_resource_vpcs_provisioned_only" {
  enabled = true
}

rule "aws_db_instance_backup_enabled" {
  enabled = true
}

# Availability rules
rule "aws_availability_zones_multi" {
  enabled = true
}

# Provider configuration rules
rule "aws_provider_authentication" {
  enabled = true
}

# Documentation requirements
rule "terraform_module_documentation" {
  enabled = true
}

# Variable validation
rule "terraform_variable_validation" {
  enabled = true
}

# Dedicated host specific rules
rule "aws_ec2_host_validation" {
  enabled = true
}

# Tag enforcement for all AWS resources
rule "aws_ec2_host_tags" {
  enabled = true
  enforcement_level = "mandatory"
  tags = [
    "Environment",
    "Project",
    "ManagedBy",
    "CostCenter"
  ]
}

# Cost optimization rules
rule "aws_ec2_cost_optimization" {
  enabled = true
}

# Best practices for EC2 resources
rule "aws_ec2_best_practices" {
  enabled = true
  check_instance_profile = true
  check_ebs_optimization = true
  check_monitoring = true
}

