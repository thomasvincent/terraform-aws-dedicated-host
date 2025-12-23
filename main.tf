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
    var.nitro_tpm_support ? { "NitroTPM" = "enabled" } : {}
  )

}

