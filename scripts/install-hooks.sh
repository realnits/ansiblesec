#!/usr/bin/env bash

# Install pre-commit hook

HOOK_DIR=".git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

if [ ! -d "$HOOK_DIR" ]; then
    echo "❌ Not in a git repository"
    exit 1
fi

echo "📦 Installing pre-commit hook..."

# Copy pre-commit script
cp scripts/pre-commit.sh "$HOOK_FILE"
chmod +x "$HOOK_FILE"

echo "✅ Pre-commit hook installed!"
echo ""
echo "The hook will run automatically before each commit."
echo "To skip the hook, use: git commit --no-verify"
