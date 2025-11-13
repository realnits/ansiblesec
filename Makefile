.PHONY: all build test clean install run format lint help docker-build docker-run release

# Default target
all: build

# Build the project
build:
	@echo "🔨 Building ansiblesec..."
	cargo build

# Build release version
release:
	@echo "🚀 Building release version..."
	cargo build --release

# Run tests
test:
	@echo "🧪 Running tests..."
	cargo test

# Run tests with output
test-verbose:
	@echo "🧪 Running tests (verbose)..."
	cargo test -- --nocapture

# Run integration tests
test-integration:
	@echo "🔗 Running integration tests..."
	cargo test --test '*'

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
	rm -rf .ansiblesec_cache/

# Install locally
install:
	@echo "📦 Installing ansiblesec..."
	cargo install --path .

# Format code
format:
	@echo "🎨 Formatting code..."
	cargo fmt

# Check formatting
format-check:
	@echo "🎨 Checking code formatting..."
	cargo fmt -- --check

# Run clippy
lint:
	@echo "🔍 Running clippy..."
	cargo clippy -- -D warnings

# Run all checks (format, lint, test)
check: format-check lint test
	@echo "✅ All checks passed!"

# Run the tool
run:
	cargo run -- $(ARGS)

# Run scan example
run-scan:
	cargo run -- scan examples/bad_playbook.yml

# Run scan with output
run-scan-json:
	cargo run -- scan examples/bad_playbook.yml --format json --output report.json

# Run lint example
run-lint:
	cargo run -- lint examples/bad_playbook.yml

# Generate SBOM
run-sbom:
	cargo run -- sbom examples/ --format cyclonedx --output sbom.json

# Validate rules
run-rules:
	cargo run -- rules validate examples/custom_rules.yml

# Build Docker image
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t ansiblesec:latest .

# Run Docker container
docker-run:
	@echo "🐳 Running Docker container..."
	docker run --rm -v $(PWD)/examples:/workspace ansiblesec:latest scan /workspace/bad_playbook.yml

# Development setup
setup:
	@echo "🚀 Setting up development environment..."
	rustup component add rustfmt clippy
	cargo build

# Watch and rebuild on changes (requires cargo-watch)
watch:
	cargo watch -x build

# Generate documentation
docs:
	@echo "📚 Generating documentation..."
	cargo doc --no-deps --open

# Run coverage (requires cargo-tarpaulin)
coverage:
	@echo "📊 Generating coverage report..."
	cargo tarpaulin --out Html --output-dir coverage

# Benchmark (requires criterion)
bench:
	@echo "⚡ Running benchmarks..."
	cargo bench

# Check for security vulnerabilities in dependencies
audit:
	@echo "🔒 Auditing dependencies..."
	cargo audit

# Update dependencies
update:
	@echo "⬆️  Updating dependencies..."
	cargo update

# Help
help:
	@echo "ansiblesec Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build          - Build the project"
	@echo "  release        - Build release version"
	@echo "  test           - Run tests"
	@echo "  test-verbose   - Run tests with output"
	@echo "  clean          - Clean build artifacts"
	@echo "  install        - Install locally"
	@echo "  format         - Format code"
	@echo "  format-check   - Check code formatting"
	@echo "  lint           - Run clippy"
	@echo "  check          - Run all checks"
	@echo "  run            - Run the tool (use ARGS='...' for arguments)"
	@echo "  run-scan       - Run scan example"
	@echo "  run-scan-json  - Run scan with JSON output"
	@echo "  run-lint       - Run lint example"
	@echo "  run-sbom       - Generate SBOM"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  setup          - Setup development environment"
	@echo "  docs           - Generate documentation"
	@echo "  coverage       - Generate coverage report"
	@echo "  audit          - Check for security vulnerabilities"
	@echo "  update         - Update dependencies"
	@echo "  help           - Show this help"
