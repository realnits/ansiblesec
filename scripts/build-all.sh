#!/usr/bin/env bash

# Build script for cross-platform binaries

set -e

VERSION=${1:-"0.1.0"}
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-gnu"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
    "x86_64-pc-windows-msvc"
)

echo "🚀 Building ansiblesec v${VERSION} for multiple platforms..."

# Create dist directory
mkdir -p dist

# Build for each target
for target in "${TARGETS[@]}"; do
    echo ""
    echo "📦 Building for $target..."
    
    # Install target if not already installed
    rustup target add $target 2>/dev/null || true
    
    # Build
    cargo build --release --target $target
    
    # Copy binary to dist
    if [[ $target == *"windows"* ]]; then
        cp "target/$target/release/ansiblesec.exe" "dist/ansiblesec-${VERSION}-${target}.exe"
    else
        cp "target/$target/release/ansiblesec" "dist/ansiblesec-${VERSION}-${target}"
    fi
    
    echo "✅ Built for $target"
done

echo ""
echo "🎉 All builds completed!"
echo ""
echo "📂 Binaries are in the dist/ directory:"
ls -lh dist/

# Create checksums
cd dist
echo ""
echo "🔐 Generating checksums..."
sha256sum ansiblesec-* > checksums.txt
cat checksums.txt

echo ""
echo "✅ Build complete!"
