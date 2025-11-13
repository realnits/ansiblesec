#!/usr/bin/env bash

# Release script

set -e

if [ -z "$1" ]; then
    echo "Usage: ./scripts/release.sh <version>"
    echo "Example: ./scripts/release.sh 0.1.0"
    exit 1
fi

VERSION=$1
TAG="v${VERSION}"

echo "🚀 Preparing release ${TAG}..."

# Check if working directory is clean
if [[ -n $(git status -s) ]]; then
    echo "❌ Working directory is not clean. Please commit or stash changes."
    exit 1
fi

# Check if on main branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$BRANCH" != "main" ]]; then
    echo "⚠️  Warning: Not on main branch (current: $BRANCH)"
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update version in Cargo.toml
echo "📝 Updating version in Cargo.toml..."
sed -i.bak "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml
rm Cargo.toml.bak

# Update Cargo.lock
cargo build --release

# Update CHANGELOG.md
echo "📝 Updating CHANGELOG.md..."
DATE=$(date +%Y-%m-%d)
sed -i.bak "s/## \[Unreleased\]/## [Unreleased]\n\n## [${VERSION}] - ${DATE}/" CHANGELOG.md
rm CHANGELOG.md.bak

# Commit changes
echo "💾 Committing changes..."
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore: release ${TAG}"

# Create tag
echo "🏷️  Creating tag ${TAG}..."
git tag -a "${TAG}" -m "Release ${TAG}"

# Show summary
echo ""
echo "✅ Release prepared successfully!"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git show"
echo "  2. Push to remote: git push origin main --tags"
echo "  3. GitHub Actions will build and publish the release"
echo ""
echo "To abort:"
echo "  git tag -d ${TAG}"
echo "  git reset --hard HEAD~1"
