variable "name" {
  description = "Name for the dedicated host"
  type        = string
}

variable "auto_placement" {
  description = "Indicates whether the host accepts any untargeted instance launches that match its instance type configuration (on | off)"
  type        = string
  default     = "on"
  validation {
    condition     = contains(["on", "off"], var.auto_placement)
    error_message = "Valid values are on or off."
  }
}

variable "availability_zone" {
  description = "The availability zone of the Dedicated Host"
  type        = string
}

variable "host_recovery" {
  description = "Indicates whether to enable or disable host recovery for the Dedicated Host (on | off)"
  type        = string
  default     = "off"
  validation {
    condition     = contains(["on", "off"], var.host_recovery)
    error_message = "Valid values are on or off."
  }
}

variable "instance_type" {
  description = "The instance type to support on this host"
  type        = string
}

variable "instance_family" {
  description = "The instance family supported by this dedicated host"
  type        = string
  default     = null
}

variable "outpost_arn" {
  description = "The ARN of the AWS Outpost on which to allocate the Dedicated Host"
  type        = string
  default     = null
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}