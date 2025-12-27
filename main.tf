# This creates an AWS EC2 Dedicated Host - basically your own private physical server
# in AWS's datacenter. It's like having a reserved parking spot, but for compute.
resource "aws_ec2_host" "this" {
  # Let AWS decide where to place instances, or don't. We're flexible like that.
  auto_placement    = var.auto_placement

  # Pick your favorite datacenter location (or let your boss pick it)
  availability_zone = var.availability_zone

  # If the host dies, should AWS try to bring it back to life? Zombie host mode, basically.
  host_recovery     = var.host_recovery

  # What kind of instances can live here? This is the host's "type"
  instance_type     = var.instance_type
  instance_family   = var.instance_family

  # For those fancy folks using AWS Outposts (hardware at your own datacenter)
  outpost_arn       = var.outpost_arn

  # Tag everything because finding resources without tags is like finding
  # a needle in a haystack, except the haystack is on fire and also in the cloud
  tags = merge(
    {
      "Name" = var.name
    },
    var.tags
  )

  lifecycle {
    # This prevents us from accidentally destroying the host and causing a very bad day
    # Trust me, I learned this the hard way. Don't be like past me.
    prevent_destroy = true
  }
}