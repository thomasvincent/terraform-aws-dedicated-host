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
    var.tags
  )

  lifecycle {
    # Force creation of a new host if instance type or AZ changes
    prevent_destroy = true
  }
}