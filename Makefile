.PHONY: help install install-dev lint format inspector

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package
	uv sync

install-dev:  ## Install the package with development dependencies
	uv sync --dev

lint:  ## Run linting
	uv run pylint src/
	uv run black --check src/

format:  ## Format code
	uv run black src/

inspector:  ## Run MCP Inspector for testing tools
	npx @modelcontextprotocol/inspector