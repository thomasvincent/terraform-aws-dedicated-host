# AWS EC2 Dedicated Host Terraform Module

This Terraform module creates an AWS EC2 Dedicated Host resource with support for core configuration options. Note: features like SSM activations/associations, AWS Backup plans/selections, and instance-level CloudWatch alarms are not applicable to the host resource and have been removed to align with AWS provider documentation. Nitro-related tagging options remain as inputs for consumers.

## Features

### Core Features
- Creates an EC2 Dedicated Host with support for latest generation instance types
- Supports host recovery configuration
- Configurable auto placement options
- Support for tagging and resource labeling
- Complete example configurations
- Comprehensive test coverage

### Advanced Features

#### Latest Instance Families Support
- Support for all modern instance families including:
  - Graviton-based instances (m7g, c7g, r7g)
  - Latest generation x86 instances (m7i, c7i, r7i)
  - High performance instances with flexible sizing (c7i-flex, m7i-flex)
  - GPU-accelerated instances (g5, g6)
  - Memory-optimized instances (x2gd, x2idn, x2iedn)
  - AI/ML optimized instances (inf2, dl1, p5)

#### Nitro System Features
- AWS Nitro Enclaves support for enhanced security isolation
- Trusted Platform Module (TPM) support for hardware-level security
- Optimized EBS performance by default

### Systems Manager Integration
- Not applicable at the host level; manage instances placed on the host with SSM instead.

### Automated Backup and Recovery
- Not applicable at the host level; use AWS Backup for instances/EBS volumes.

### Enhanced Monitoring
- Use instance-level or account-level CloudWatch metrics/alarms as appropriate; host-level alarm example removed.

## Usage

### Basic Dedicated Host

```hcl
module "dedicated_host" {
  source = "github.com/thomasvincent/terraform-aws-dedicated-host"

  name              = "my-dedicated-host"
  availability_zone = "us-west-2a"
  instance_type     = "m7g.large"  # Modern Graviton instance
  auto_placement    = "on"
  host_recovery     = "on"

  tags = {
    Environment = "production"
    Project     = "my-project"
  }
}
```

### With Nitro System Features

```hcl
module "dedicated_host_nitro" {
  source = "github.com/thomasvincent/terraform-aws-dedicated-host"

  name              = "nitro-dedicated-host"
  availability_zone = "us-west-2a"
  instance_type     = "c7g.large"
  auto_placement    = "on"
  host_recovery     = "on"

  # Nitro System Features
  enable_nitro_enclaves    = true
  nitro_tpm_support        = true
  ebs_optimized_by_default = true

  tags = {
    Environment = "production"
    Security    = "enhanced"
  }
}
```

### With Systems Manager Integration

```hcl
module "dedicated_host_ssm" {
  source = "github.com/thomasvincent/terraform-aws-dedicated-host"

  name              = "ssm-managed-host"
  availability_zone = "us-west-2a"
  instance_type     = "r6g.large"
  auto_placement    = "on"
  host_recovery     = "on"

  # Systems Manager Integration
  enable_ssm_management = true
  ssm_activation_tier   = "advanced"
  ssm_document_name     = "AWS-ConfigureAWSHost"

  tags = {
    Environment = "production"
    Management  = "ssm"
  }
}
```

### With Automated Backup

```hcl
module "dedicated_host_backup" {
  source = "github.com/thomasvincent/terraform-aws-dedicated-host"

  name              = "backup-enabled-host"
  availability_zone = "us-west-2a"
  instance_type     = "m7i.large"
  auto_placement    = "on"
  host_recovery     = "on"

  # Automated Backup Configuration
  enable_automated_backups = true
  backup_plan_schedule     = "cron(0 2 * * ? *)"  # Every day at 2am UTC
  backup_retention_days    = 30
  recovery_point_tags = {
    BackupType = "DedicatedHost"
    CostCenter = "Infrastructure"
  }

  tags = {
    Environment = "production"
    Backup      = "enabled"
  }
}
```

### Complete Example with All Features

See the [complete example](examples/complete) for a comprehensive implementation using all features.

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.0.0 |

## Providers

| Name | Version |
|------|---------|
| aws | >= 5.0.0 |

## Resources

| Name | Type |
|------|------|
| [aws_ec2_host.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_host) | resource |
| [aws_cloudwatch_metric_alarm.host_status](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_iam_role.ssm_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_ssm_activation.host_activation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_activation) | resource |
| [aws_ssm_association.host_management](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_association) | resource |
| [aws_backup_vault.host_backup_vault](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/backup_vault) | resource |
| [aws_backup_plan.host_backup_plan](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/backup_plan) | resource |
| [aws_backup_selection.host_backup_selection](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/backup_selection) | resource |
| [aws_iam_role.backup_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |

## Inputs

### Core Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| name | Name for the dedicated host | `string` | n/a | yes |
| availability_zone | The availability zone of the Dedicated Host | `string` | n/a | yes |
| instance_type | The instance type to support on this host | `string` | n/a | yes |
| auto_placement | Indicates whether the host accepts any untargeted instance launches that match its instance type configuration (on \| off) | `string` | `"on"` | no |
| host_recovery | Indicates whether to enable or disable host recovery for the Dedicated Host (on \| off) | `string` | `"off"` | no |
| instance_family | The instance family supported by this dedicated host | `string` | `null` | no |
| outpost_arn | The ARN of the AWS Outpost on which to allocate the Dedicated Host | `string` | `null` | no |
| tags | A map of tags to add to all resources | `map(string)` | `{}` | no |
| prevent_instance_deletion | If true, prevents the deletion of the Dedicated Host while instances are allocated to it | `bool` | `true` | no |

### Nitro System Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| enable_nitro_enclaves | Whether to enable AWS Nitro Enclaves on the dedicated host | `bool` | `false` | no |
| nitro_tpm_support | Whether to enable Trusted Platform Module (TPM) support for Nitro instances | `bool` | `false` | no |
| ebs_optimized_by_default | Whether instances launched on this dedicated host should be EBS-optimized by default | `bool` | `true` | no |

### Systems Manager Integration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| enable_ssm_management | Whether to enable AWS Systems Manager management for the dedicated host | `bool` | `false` | no |
| ssm_activation_tier | The tier of the Systems Manager activation (if ssm management is enabled) | `string` | `"standard"` | no |
| ssm_document_name | The name of the SSM document to use for host management (if ssm management is enabled) | `string` | `"AWS-ConfigureAWSHost"` | no |

### Automated Backup Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| enable_automated_backups | Whether to enable automated backups of instances on the dedicated host | `bool` | `false` | no |
| backup_plan_schedule | The schedule expression for the backup plan (if automated backups are enabled) | `string` | `"cron(0 1 * * ? *)"` | no |
| backup_retention_days | Number of days to retain backups (if automated backups are enabled) | `number` | `30` | no |
| recovery_point_tags | Tags to assign to recovery points (if automated backups are enabled) | `map(string)` | `{}` | no |

### Monitoring Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| enable_monitoring | Whether to enable CloudWatch monitoring for the Dedicated Host | `bool` | `false` | no |
| alarm_actions | List of ARNs to notify when host status changes (if monitoring is enabled) | `list(string)` | `[]` | no |

### Maintenance Window Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| enable_maintenance_window | Whether to enable a maintenance window for the Dedicated Host | `bool` | `false` | no |
| maintenance_window_start_time | Start time for the maintenance window in RFC3339 format (if maintenance window is enabled) | `string` | `null` | no |
| maintenance_window_end_time | End time for the maintenance window in RFC3339 format (if maintenance window is enabled) | `string` | `null` | no |
| maintenance_auto_placement | Auto placement setting during maintenance (if maintenance window is enabled) | `string` | `"on"` | no |

## Outputs

### Core Outputs

| Name | Description |
|------|-------------|
| id | The ID of the Dedicated Host |
| arn | The ARN of the Dedicated Host |
| availability_zone | The availability zone of the Dedicated Host |
| owner_id | The ID of the AWS account that owns the Dedicated Host |
| tags_all | A map of tags assigned to the resource, including those inherited from the provider |
| host_recovery_status | The current host recovery status of the Dedicated Host |
| instance_family_supported | The instance family supported by this Dedicated Host |
| auto_placement_status | The auto placement status of the Dedicated Host |

### Nitro System Outputs

| Name | Description |
|------|-------------|
| nitro_enclaves_enabled | Whether Nitro Enclaves are enabled for this Dedicated Host |
| nitro_tpm_support_enabled | Whether Trusted Platform Module (TPM) support is enabled for Nitro instances |
| ebs_optimized_by_default | Whether instances on this dedicated host are EBS-optimized by default |

### Systems Manager Outputs (removed)

| Name | Description |
|------|-------------|
| ssm_management_enabled | Whether AWS Systems Manager management is enabled for the Dedicated Host |
| ssm_activation_id | The ID of the SSM activation used for registering the Dedicated Host |
| ssm_activation_code | The activation code generated by SSM (sensitive value) |

### Backup Outputs (removed)

| Name | Description |
|------|-------------|
| backup_enabled | Whether automated backups are enabled for the Dedicated Host |
| backup_vault_id | The ID of the backup vault |
| backup_vault_arn | The ARN of the backup vault |
| backup_plan_id | The ID of the backup plan |
| backup_plan_arn | The ARN of the backup plan |

## Migration Guide

### Upgrading from v1.x to v2.x

If you're upgrading from version 1.x to 2.x of this module, be aware of these changes:

1. **AWS Provider Requirement**: The minimum AWS provider version has been increased from 4.0 to 5.0
2. **Terraform Requirement**: The minimum Terraform version has been increased from 1.0 to 1.5
3. **Instance Family Support**: The module now defaults to newer instance families; check your configuration
4. **New Features**: New features (Nitro, SSM, Backup) are disabled by default for backward compatibility

#### Migration Steps

1. Update your AWS provider and Terraform versions
2. Review your instance types to ensure they're still supported
3. Consider enabling new features like Nitro Enclaves, SSM integration, or automated backups

```hcl
# Before (v1.x)
module "dedicated_host" {
  source = "github.com/thomasvincent/terraform-aws-dedicated-host"
  version = "1.0.0"

  name              = "my-dedicated-host"
  availability_zone = "us-west-2a"
  instance_type     = "c5.large"
  auto_placement    = "on"
  host_recovery     = "on"

  tags = {
    Environment = "production"
  }
}

# After (v2.x)
module "dedicated_host" {
  source = "github.com/thomasvincent/terraform-aws-dedicated-host"
  version = "2.0.0"

  name              = "my-dedicated-host"
  availability_zone = "us-west-2a"
  instance_type     = "c7g.large"  # Upgraded to newer instance type
  auto_placement    = "on"
  host_recovery     = "on"

  # Optional: Enable new features
  enable_nitro_enclaves    = true
  enable_ssm_management    = true
  enable_automated_backups = true

  tags = {
    Environment = "production"
  }
}
```

## Troubleshooting

### Common Issues

#### Dedicated Host Allocation Failures

If you encounter failures when allocating a dedicated host:

1. Verify that the instance type is available in the specified availability zone
2. Check if you have sufficient dedicated host limits in your AWS account
3. For Nitro features, ensure the instance family supports Nitro capabilities

#### Systems Manager Connection Issues

If instances on your dedicated host aren't properly connecting to Systems Manager:

1. Verify that your instances have proper internet access or VPC endpoints for SSM
2. Check that the SSM agent is installed on your instances
3. Verify IAM permissions are correctly configured

#### Backup Failures

For backup issues:

1. Ensure the AWS Backup service has the necessary permissions to access your resources
2. Verify your backup vault settings and retention policies
3. Check CloudTrail logs for specific AWS Backup error messages

## Best Practices for Production Deployments

### Performance Optimization

1. **Choose the Right Instance Family**: Match the instance family to your workload requirements
2. **Enable EBS Optimization**: Keep `ebs_optimized_by_default = true` for best storage performance
3. **Use Host Recovery**: Set `host_recovery = "on"` to automatically recover from hardware failures

### Security Hardening

1. **Enable Nitro Enclaves**: For workloads requiring enhanced isolation
2. **Implement TPM Support**: For hardware-based security capabilities
3. **Use Systems Manager**: For secure, audit-friendly host management

### Cost Management

1. **Auto-Placement Configuration**: Use `auto_placement = "on"` to maximize host utilization
2. **Right-Size Dedicated Hosts**: Select instance types that maximize density for your workload
3. **Implement Backups**: Configure automated backups with appropriate retention periods

### Monitoring and Maintenance

1. **Enable CloudWatch Monitoring**: Set `enable_monitoring = true` and configure alarm actions
2. **Configure Maintenance Windows**: Use the maintenance window variables to control when AWS performs host maintenance
3. **Implement Appropriate Tagging**: Use comprehensive tagging for cost allocation and resource management

## Testing

The module includes a comprehensive test suite using Terratest and Docker for reproducible testing.

```bash
# Run tests using Docker
make docker-test

# Run linting and validation
make

# Format code
make fmt
```

## License

This module is licensed under the MIT License - see the LICENSE file for details.
