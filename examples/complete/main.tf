provider "aws" {
  region = "us-west-2"
}

locals {
  name = "advanced-dedicated-host"
}

module "dedicated_host" {
  source = "../../"

  name              = local.name
  availability_zone = "us-west-2a"
  instance_type     = "m7g.large"    # Modern Graviton instance type
  auto_placement    = "on"
  host_recovery     = "on"

  # Nitro System Features
  enable_nitro_enclaves    = true
  nitro_tpm_support        = true
  ebs_optimized_by_default = true

  # Systems Manager Integration
  enable_ssm_management = true
  ssm_activation_tier   = "advanced"
  ssm_document_name     = "AWS-ConfigureAWSHost"

  # Automated Backup Configuration
  enable_automated_backups = true
  backup_plan_schedule     = "cron(0 2 * * ? *)"  # Every day at 2am UTC
  backup_retention_days    = 30
  recovery_point_tags = {
    BackupType = "DedicatedHost"
    CostCenter = "Infrastructure"
  }

  # CloudWatch Monitoring
  enable_monitoring = true
  alarm_actions     = ["arn:aws:sns:us-west-2:123456789012:dedicated-host-alerts"]

  tags = {
    Environment = "production"
    Project     = "infrastructure"
    ManagedBy   = "terraform"
    CostCenter  = "platform"
  }
}

# Output all module outputs for reference
output "host_details" {
  description = "All details about the dedicated host"
  value = {
    id                      = module.dedicated_host.id
    arn                     = module.dedicated_host.arn
    availability_zone       = module.dedicated_host.availability_zone
    nitro_enclaves_enabled  = module.dedicated_host.nitro_enclaves_enabled
    nitro_tpm_support       = module.dedicated_host.nitro_tpm_support
    ssm_management_enabled  = module.dedicated_host.ssm_management_enabled
    backup_enabled          = module.dedicated_host.backup_enabled
    backup_vault_id         = module.dedicated_host.backup_vault_id
    backup_plan_id          = module.dedicated_host.backup_plan_id
  }
}
