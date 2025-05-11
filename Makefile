.PHONY: test fmt validate lint clean docs pre-commit bump-version generate-changelog

TERRAFORM_VERSION = 1.6.6
TF_DOCS_VERSION = 0.16.0

default: lint validate

lint:
	@echo "==> Linting Terraform code..."
	@terraform fmt -check -recursive

fmt:
	@echo "==> Formatting Terraform code..."
	@terraform fmt -recursive

validate:
	@echo "==> Validating Terraform code..."
	@for dir in examples/complete .; do \
		echo "==> Validating in $${dir}..."; \
		cd "$${dir}" && terraform init -backend=false && terraform validate || exit 1; \
		cd - > /dev/null; \
	done

test:
	@echo "==> Running tests..."
	cd test && go test -v -timeout 30m

clean:
	@echo "==> Cleaning up..."
	@rm -rf .terraform terraform.tfstate terraform.tfstate.backup .terraform.lock.hcl

docker-test:
	@echo "==> Testing in Docker container..."
	docker build -t terraform-aws-dedicated-host-test .
	docker run --rm -v $(PWD):/terraform terraform-aws-dedicated-host-test make test

docs:
	@echo "==> Generating docs with terraform-docs..."
	@docker run --rm -v $$(pwd):/data -w /data quay.io/terraform-docs/terraform-docs:latest markdown . > README.md

pre-commit:
	@echo "==> Running pre-commit hooks..."
	@pre-commit run -a

bump-version:
	@echo "==> Bumping version..."
	@if [ -z "$(VERSION)" ]; then echo "VERSION is required (e.g., make bump-version VERSION=1.0.0)"; exit 1; fi
	@git tag -a v$(VERSION) -m "Release v$(VERSION)"
	@echo "Tagged v$(VERSION). Run 'git push --tags' to push the new tag."

generate-changelog:
	@echo "==> Generating changelog..."
	@if [ -z "$(VERSION)" ]; then echo "VERSION is required (e.g., make generate-changelog VERSION=1.0.0)"; exit 1; fi
	@git log --pretty=format:"* %s" $$(git describe --tags --abbrev=0 2>/dev/null || echo HEAD~10)..HEAD > CHANGELOG.md