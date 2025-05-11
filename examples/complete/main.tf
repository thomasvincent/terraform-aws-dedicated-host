provider "aws" {
  region = "us-west-2"
}

locals {
  name = "example-dedicated-host"
}

module "dedicated_host" {
  source = "../../"

  name              = local.name
  availability_zone = "us-west-2a"
  instance_type     = "c5.large"
  auto_placement    = "on"
  host_recovery     = "on"

  tags = {
    Environment = "test"
    Project     = "dedicated-host-module"
  }
}