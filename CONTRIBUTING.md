# Contributing

Thank you for considering contributing to this Terraform module! Here are some guidelines to help you get started.

## Development Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `make test`
5. Run linting: `make lint`
6. Commit your changes: `git commit -am 'Add my feature'`
7. Push to the branch: `git push origin feature/my-feature`
8. Submit a pull request

## Local Development Setup

This module uses Docker for testing and development to ensure a consistent environment.

### Prerequisites

- Docker
- Git
- Make
- Terraform CLI (for local validation)

### Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/terraform-aws-dedicated-host-.git
   cd terraform-aws-dedicated-host-
   ```

2. Install pre-commit hooks:
   ```bash
   pip install pre-commit
   pre-commit install
   ```

3. Run linting and validation:
   ```bash
   make
   ```

4. Run tests in Docker:
   ```bash
   make docker-test
   ```

## Code Style and Guidelines

- Follow the HashiCorp Terraform style conventions
- Use meaningful variable and output names
- Document all variables and outputs
- All new features should include tests
- Changes should be backward compatible when possible

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update the examples if necessary
3. Run `make docs` to update generated documentation
4. Your PR will be reviewed by maintainers who may request changes
5. Once approved, a maintainer will merge your PR

## Releasing

Maintainers will handle version bumping and tagging:

```bash
make bump-version VERSION=1.0.0
git push --tags
```

This will automatically trigger a GitHub release workflow.

## Questions?

If you have any questions, feel free to open an issue for discussion.