#!/usr/bin/env bash

# Pre-commit hook for ansiblesec

set -e

echo "🔍 Running pre-commit checks..."

# Check formatting
echo "📝 Checking code formatting..."
if ! cargo fmt -- --check; then
    echo "❌ Code is not formatted. Run 'cargo fmt' to fix."
    exit 1
fi

# Run clippy
echo "🔍 Running clippy..."
if ! cargo clippy -- -D warnings; then
    echo "❌ Clippy found issues. Please fix them."
    exit 1
fi

# Run tests
echo "🧪 Running tests..."
if ! cargo test; then
    echo "❌ Tests failed. Please fix them."
    exit 1
fi

echo "✅ All pre-commit checks passed!"
