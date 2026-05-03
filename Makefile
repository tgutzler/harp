.PHONY: all build test run dev clean

PYTHON := uv run python
UV     := uv

all: build

# Install dependencies and run tests
build:
	$(UV) sync --all-groups
	$(UV) run pytest

# Run tests only
test:
	$(UV) run pytest

# Run tests with verbose output
test-v:
	$(UV) run pytest -v

# Run the server (production-like, reads .env)
run:
	$(PYTHON) main.py

# Run the server in debug mode (auto-reload, debug log level)
dev:
	LOG_LEVEL=debug RELOAD=true $(PYTHON) main.py

# Remove generated files
clean:
	rm -f test_harp.db
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -name "*.pyc" -delete
