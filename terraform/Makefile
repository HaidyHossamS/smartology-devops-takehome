.PHONY: help fmt validate lint security plan test all
.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

fmt: ## Rewrite files to canonical format
	terraform fmt -recursive

validate: ## Syntax and internal consistency (no credentials needed)
	terraform init -backend=false -input=false
	terraform validate

lint: ## Provider-aware linting: deprecated args, invalid instance types, naming
	tflint --init
	tflint --recursive

security: ## Static security analysis. Both, because they catch different things.
	checkov -d . --framework terraform --compact
	trivy config . --severity HIGH,CRITICAL

plan: ## Plan against the current workspace
	terraform plan -input=false -lock-timeout=5m -out=tfplan

test: ## Terraform's native test framework (tests/*.tftest.hcl)
	terraform test

all: fmt validate lint security ## Everything CI runs before a plan is allowed
