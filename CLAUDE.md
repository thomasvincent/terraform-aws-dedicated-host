# CLAUDE.md

Terraform module for provisioning AWS EC2 Dedicated Hosts with configurable recovery and placement options.

## Stack
- Terraform >= 1.0.0
- AWS Provider >= 5.0.0

## Development Workflow

```bash
# Format and validate
terraform fmt -recursive
terraform validate

# Run linting
make

# Docker-based testing
make docker-test
```

## Key Features
- Supports both instance type and instance family allocation
- Host recovery and auto-placement configuration
- Built-in Terratest validation suite
- Complete example in module documentation
