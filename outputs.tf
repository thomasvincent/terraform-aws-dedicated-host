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