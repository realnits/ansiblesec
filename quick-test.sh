#!/usr/bin/env bash

# Quick test script for ansiblesec

set -e

echo "🔍 ansiblesec - Quick Test Script"
echo "=================================="
echo ""

# Check if Rust is available
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust/Cargo not found in PATH"
    echo ""
    echo "Please run:"
    echo '  source "$HOME/.cargo/env"'
    echo ""
    exit 1
fi

echo "✅ Rust found: $(rustc --version)"
echo "✅ Cargo found: $(cargo --version)"
echo ""

# Build the project
echo "🔨 Building ansiblesec (this may take a few minutes)..."
cargo build --release

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Build successful!"
    echo ""
    echo "Binary location: ./target/release/ansiblesec"
    echo ""
    echo "🧪 Running quick test..."
    ./target/release/ansiblesec scan examples/bad_playbook.yml
    echo ""
    echo "🎉 Success! ansiblesec is working!"
else
    echo "❌ Build failed. Please check the errors above."
    exit 1
fi
