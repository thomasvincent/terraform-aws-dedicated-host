# -----------------------------------------------------------------------------
# Locals for Validation and Computed Values
# -----------------------------------------------------------------------------

locals {
  # Valid AWS instance types pattern
  valid_instance_types_pattern = "^[a-z][1-9][.][a-z0-9]+$"

  # Valid AWS availability zone pattern
  valid_az_pattern = "^[a-z]{2}-[a-z]+-[1-9][a-z]$"

  # Common AWS instance families
  valid_instance_families = [
    "a1", "c5", "c6g", "d2", "f1", "g4", "i3", "i4i", "inf1", "m5", "m6g",
    "p3", "r5", "r6g", "t3", "t4g", "x1", "x2", "z1d"
  ]

  # Error messages
  errors = {
    invalid_instance_type = "Invalid instance type format. Must match pattern: ${local.valid_instance_types_pattern}"
    invalid_az           = "Invalid availability zone format. Must match pattern: ${local.valid_az_pattern}"
    invalid_family       = "Invalid instance family. Must be one of: ${join(", ", local.valid_instance_families)}"
    family_mismatch     = "Instance type does not match specified instance family"
  }

  # Extract instance family from instance type for validation
  instance_type_family = var.instance_type != null ? regex("^[a-z][1-9]", var.instance_type)[0] : null

  # Validate instance family match if both are specified
  validate_family_match = (
    var.instance_family != null && 
    var.instance_type != null && 
    local.instance_type_family != var.instance_family
  )
}

