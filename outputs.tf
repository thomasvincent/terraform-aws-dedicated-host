output "id" {
  description = "The ID of the Dedicated Host"
  value       = aws_ec2_host.this.id
}

output "arn" {
  description = "The ARN of the Dedicated Host"
  value       = aws_ec2_host.this.arn
}

output "availability_zone" {
  description = "The availability zone of the Dedicated Host"
  value       = aws_ec2_host.this.availability_zone
}

output "owner_id" {
  description = "The ID of the AWS account that owns the Dedicated Host"
  value       = aws_ec2_host.this.owner_id
}

output "tags_all" {
  description = "A map of tags assigned to the resource, including those inherited from the provider"
  value       = aws_ec2_host.this.tags_all
}

# -----------------------------------------------------------------------------
# Nitro System Configuration Outputs
# -----------------------------------------------------------------------------

output "nitro_enclaves_enabled" {
  description = "Whether Nitro Enclaves are enabled for this Dedicated Host"
  value       = var.enable_nitro_enclaves
}

output "nitro_tpm_support_enabled" {
  description = "Whether Trusted Platform Module (TPM) support is enabled for Nitro instances"
  value       = var.nitro_tpm_support
}

output "ebs_optimized_by_default" {
  description = "Whether instances on this dedicated host are EBS-optimized by default"
  value       = var.ebs_optimized_by_default
}


# -----------------------------------------------------------------------------
# Additional Host Attributes
# -----------------------------------------------------------------------------

output "host_recovery_status" {
  description = "The current host recovery status of the Dedicated Host"
  value       = var.host_recovery
}

output "instance_family_supported" {
  description = "The instance family supported by this Dedicated Host"
  value       = var.instance_family
}

output "auto_placement_status" {
  description = "The auto placement status of the Dedicated Host"
  value       = var.auto_placement
}
