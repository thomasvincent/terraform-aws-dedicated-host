output "dedicated_host_id" {
  description = "The ID of the Dedicated Host"
  value       = module.dedicated_host.id
}

output "dedicated_host_arn" {
  description = "The ARN of the Dedicated Host"
  value       = module.dedicated_host.arn
}

output "availability_zone" {
  description = "The availability zone of the Dedicated Host"
  value       = module.dedicated_host.availability_zone
}