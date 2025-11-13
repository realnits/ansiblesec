#!/bin/bash

# Quick setup script for ansiblesec development environment

set -e

echo "🚀 Setting up ansiblesec development environment..."

# Check for Rust
if ! command -v rustc &> /dev/null; then
    echo "❌ Rust is not installed. Please install Rust from https://rustup.rs/"
    exit 1
fi

echo "✅ Rust found: $(rustc --version)"

# Check for Cargo
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo is not installed."
    exit 1
fi

echo "✅ Cargo found: $(cargo --version)"

# Install development tools
echo "📦 Installing development tools..."
rustup component add rustfmt clippy

# Build the project
echo "🔨 Building ansiblesec..."
cargo build

# Run tests
echo "🧪 Running tests..."
cargo test

# Format check
echo "🎨 Checking code formatting..."
cargo fmt -- --check || {
    echo "⚠️  Code needs formatting. Run 'cargo fmt' to fix."
}

# Clippy check
echo "🔍 Running clippy..."
cargo clippy -- -D warnings || {
    echo "⚠️  Clippy found issues. Please fix them."
}

echo ""
echo "✅ Development environment setup complete!"
echo ""
echo "📚 Next steps:"
echo "  - Run 'cargo run -- --help' to see CLI options"
echo "  - Run 'cargo run -- scan examples/bad_playbook.yml' to test scanning"
echo "  - Run 'cargo test' to run tests"
echo "  - Read CONTRIBUTING.md for contribution guidelines"
echo ""
echo "Happy coding! 🎉"
