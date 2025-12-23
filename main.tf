# Main AWS EC2 Dedicated Host resource
resource "aws_ec2_host" "this" {
  auto_placement    = var.auto_placement
  availability_zone = var.availability_zone
  host_recovery     = var.host_recovery
  instance_type     = var.instance_type
  instance_family   = var.instance_family
  outpost_arn       = var.outpost_arn

  tags = merge(
    {
      "Name" = var.name
    },
    var.tags,
    var.enable_nitro_enclaves ? { "NitroEnclaves" = "enabled" } : {},
    var.nitro_tpm_support ? { "NitroTPM" = "enabled" } : {},
    var.enable_ssm_management ? { "SSMManaged" = "true" } : {},
    var.enable_automated_backups ? { "AutomatedBackup" = "enabled" } : {}
  )

  lifecycle {
    # Force creation of a new host if instance type or AZ changes
    prevent_destroy = var.prevent_instance_deletion
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Monitoring
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "host_status" {
  count               = var.enable_monitoring ? 1 : 0
  alarm_name          = "${var.name}-host-status"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Maximum"
  threshold           = "1"
  alarm_description   = "Monitor the status of dedicated host ${var.name}"
  alarm_actions       = var.alarm_actions
  dimensions = {
    HostId = aws_ec2_host.this.id
  }
}

# -----------------------------------------------------------------------------
# AWS Systems Manager Integration
# -----------------------------------------------------------------------------

resource "aws_iam_role" "ssm_role" {
  count = var.enable_ssm_management ? 1 : 0
  name  = "${var.name}-ssm-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    var.ssm_activation_tier == "advanced" ? "arn:aws:iam::aws:policy/AmazonSSMFullAccess" : null
  ]
}

resource "aws_ssm_activation" "host_activation" {
  count         = var.enable_ssm_management ? 1 : 0
  name          = "${var.name}-activation"
  description   = "SSM activation for dedicated host ${var.name}"
  iam_role      = aws_iam_role.ssm_role[0].id
  registration_limit = 5
  depends_on    = [aws_ec2_host.this]
}

resource "aws_ssm_association" "host_management" {
  count      = var.enable_ssm_management ? 1 : 0
  name       = var.ssm_document_name
  
  targets {
    key    = "tag:SSMManaged"
    values = ["true"]
  }
  
  depends_on = [aws_ssm_activation.host_activation]
}

# -----------------------------------------------------------------------------
# AWS Backup Integration
# -----------------------------------------------------------------------------

resource "aws_backup_vault" "host_backup_vault" {
  count = var.enable_automated_backups ? 1 : 0
  name  = "${var.name}-backup-vault"
  tags  = merge(var.tags, var.recovery_point_tags)
}

resource "aws_backup_plan" "host_backup_plan" {
  count = var.enable_automated_backups ? 1 : 0
  name  = "${var.name}-backup-plan"

  rule {
    rule_name         = "${var.name}-backup-rule"
    target_vault_name = aws_backup_vault.host_backup_vault[0].name
    schedule          = var.backup_plan_schedule
    
    lifecycle {
      delete_after = var.backup_retention_days
    }
    
    recovery_point_tags = merge(var.tags, var.recovery_point_tags)
  }

  tags = var.tags
}

resource "aws_backup_selection" "host_backup_selection" {
  count        = var.enable_automated_backups ? 1 : 0
  name         = "${var.name}-backup-selection"
  iam_role_arn = aws_iam_role.backup_role[0].arn
  plan_id      = aws_backup_plan.host_backup_plan[0].id

  resources = [
    aws_ec2_host.this.arn
  ]

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "AutomatedBackup"
    value = "enabled"
  }
}

resource "aws_iam_role" "backup_role" {
  count = var.enable_automated_backups ? 1 : 0
  name  = "${var.name}-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
  ]
}
