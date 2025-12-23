# -----------------------------------------------------------------------------
# Input Variables
# -----------------------------------------------------------------------------

variable "name" {
  description = "Name for the dedicated host. Must be unique within your AWS account."
  type        = string
  validation {
    condition     = length(var.name) >= 3 && length(var.name) <= 128
    error_message = "Name must be between 3 and 128 characters in length."
  }
}

variable "auto_placement" {
  description = "Indicates whether the host accepts any untargeted instance launches that match its instance type configuration."
  type        = string
  default     = "on"
  validation {
    condition     = contains(["on", "off"], var.auto_placement)
    error_message = "Valid values are 'on' or 'off'."
  }
}

variable "availability_zone" {
  description = "The Availability Zone where the Dedicated Host will be allocated."
  type        = string
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[1-9][a-z]$", var.availability_zone))
    error_message = "Invalid availability zone format. Must match pattern: 'region-az-identifier' (e.g., 'us-west-2a')."
  }
}

variable "host_recovery" {
  description = "Indicates whether to enable or disable host recovery for the Dedicated Host."
  type        = string
  default     = "off"
  validation {
    condition     = contains(["on", "off"], var.host_recovery)
    error_message = "Valid values are 'on' or 'off'."
  }
}

variable "instance_type" {
  description = "The instance type to be supported by the Dedicated Host. If specified, instance_family must be omitted or match the family of this instance type."
  type        = string
  validation {
    condition     = can(regex("^[a-z][1-9][.][a-z0-9]+$", var.instance_type))
    error_message = "Invalid instance type format. Must match AWS instance type pattern (e.g., 't3.micro', 'm5.large')."
  }
}

variable "instance_family" {
  description = "The instance family supported by this Dedicated Host. If specified with instance_type, must match the family of the instance type."
  type        = string
  default     = null
  validation {
    condition     = var.instance_family == null ? true : contains([
      "a1", "c5", "c6g", "c6gn", "c6i", "c6in", "c7g", "c7gn", "c7i", "c7i-flex",
      "d2", "d3", "dl1", "f1", "g4", "g5", "g5g", "g6", "i3", "i4i", "i4g", "inf1", "inf2",
      "m5", "m5a", "m5n", "m6g", "m6gd", "m6i", "m6in", "m7g", "m7gd", "m7i", "m7i-flex",
      "p3", "p4d", "p5", "r5", "r5a", "r5b", "r5n", "r6g", "r6gd", "r6i", "r6in", "r7g", "r7gd", "r7i", "r7iz",
      "t3", "t4g", "x1", "x2", "x2gd", "x2idn", "x2iedn", "z1d"
    ], var.instance_family)
    error_message = "Invalid instance family specified."
  }
}

variable "outpost_arn" {
  description = "The ARN of the AWS Outpost on which to allocate the Dedicated Host."
  type        = string
  default     = null
  validation {
    condition     = var.outpost_arn == null ? true : can(regex("^arn:aws:outposts:[a-z0-9-]+:[0-9]{12}:outpost/[a-z0-9-]+$", var.outpost_arn))
    error_message = "Invalid Outpost ARN format."
  }
}

variable "tags" {
  description = "A map of tags to assign to the Dedicated Host."
  type        = map(string)
  default     = {}
  validation {
    condition     = length(var.tags) <= 50
    error_message = "AWS allows a maximum of 50 tags per resource."
  }
}

variable "prevent_instance_deletion" {
  description = "If true, prevents the deletion of the Dedicated Host while instances are allocated to it."
  type        = bool
  default     = true
}

variable "enable_monitoring" {
  description = "Whether to enable CloudWatch monitoring for the Dedicated Host."
  type        = bool
  default     = false
}

variable "alarm_actions" {
  description = "List of ARNs to notify when host status changes (if monitoring is enabled)."
  type        = list(string)
  default     = []
}

variable "enable_capacity_reservation" {
  description = "Whether to enable capacity reservation for the Dedicated Host."
  type        = bool
  default     = false
}

variable "capacity_reservation_count" {
  description = "Number of instances to reserve capacity for (if capacity reservation is enabled)."
  type        = number
  default     = 1
  validation {
    condition     = var.capacity_reservation_count > 0
    error_message = "Capacity reservation count must be greater than 0."
  }
}

variable "capacity_reservation_end_date" {
  description = "End date for the capacity reservation in RFC3339 format (if capacity reservation is enabled)."
  type        = string
  default     = null
}

variable "enable_maintenance_window" {
  description = "Whether to enable a maintenance window for the Dedicated Host."
  type        = bool
  default     = false
}

variable "maintenance_window_start_time" {
  description = "Start time for the maintenance window in RFC3339 format (if maintenance window is enabled)."
  type        = string
  default     = null
}

variable "maintenance_window_end_time" {
  description = "End time for the maintenance window in RFC3339 format (if maintenance window is enabled)."
  type        = string
  default     = null
}

variable "maintenance_auto_placement" {
  description = "Auto placement setting during maintenance (if maintenance window is enabled)."
  type        = string
  default     = "on"
  validation {
    condition     = contains(["on", "off"], var.maintenance_auto_placement)
    error_message = "Valid values are 'on' or 'off'."
  }
}

# -----------------------------------------------------------------------------
# Nitro System Support
# -----------------------------------------------------------------------------

variable "enable_nitro_enclaves" {
  description = "Whether to enable AWS Nitro Enclaves on the dedicated host."
  type        = bool
  default     = false
}

variable "nitro_tpm_support" {
  description = "Whether to enable Trusted Platform Module (TPM) support for Nitro instances."
  type        = bool
  default     = false
}

variable "ebs_optimized_by_default" {
  description = "Whether instances launched on this dedicated host should be EBS-optimized by default."
  type        = bool
  default     = true
}

