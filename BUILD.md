# Build Instructions

## Prerequisites

### Required
- **Rust**: 1.70 or higher
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source $HOME/.cargo/env
  ```

### Optional
- **Docker**: For containerized builds
- **Make**: For using Makefile targets
- **Git**: For version control

## Quick Build

### Using the setup script
```bash
./setup.sh
```

This will:
1. Check Rust installation
2. Install development tools (rustfmt, clippy)
3. Build the project
4. Run tests
5. Check formatting and linting

### Using Cargo directly
```bash
# Debug build (fast, for development)
cargo build

# Release build (optimized, for production)
cargo build --release

# The binary will be at:
# - Debug: target/debug/ansiblesec
# - Release: target/release/ansiblesec
```

### Using Make
```bash
# Build
make build

# Build release
make release

# Build and run tests
make check
```

## Running the Tool

### After building
```bash
# Debug build
./target/debug/ansiblesec --help

# Release build
./target/release/ansiblesec --help

# Or install to system
cargo install --path .
ansiblesec --help
```

### Without building (using cargo run)
```bash
cargo run -- scan examples/bad_playbook.yml
cargo run -- lint examples/good_playbook.yml
cargo run -- sbom examples/ --format cyclonedx
```

## Testing

### Run all tests
```bash
cargo test
```

### Run tests with output
```bash
cargo test -- --nocapture
```

### Run specific test
```bash
cargo test test_aws_key_detection
```

### Run integration tests only
```bash
cargo test --test '*'
```

## Development Workflow

### 1. Make changes to source code
```bash
vim src/secrets.rs
```

### 2. Format code
```bash
cargo fmt
```

### 3. Check with clippy
```bash
cargo clippy
```

### 4. Run tests
```bash
cargo test
```

### 5. Build and test
```bash
cargo build
./target/debug/ansiblesec scan examples/bad_playbook.yml
```

## Cross-Platform Builds

### Build for specific target
```bash
# Linux
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu

# macOS
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin

# Windows (from Linux/macOS requires cross-compilation tools)
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

### Build all targets
```bash
./scripts/build-all.sh 0.1.0
```

This creates binaries in `dist/` directory for:
- Linux (x86_64, aarch64)
- macOS (x86_64, arm64)
- Windows (x86_64)

## Docker Builds

### Build Docker image
```bash
docker build -t ansiblesec:latest .
```

### Build Alpine variant (smaller)
```bash
docker build -f Dockerfile.alpine -t ansiblesec:alpine .
```

### Run from Docker
```bash
docker run --rm -v $(pwd)/examples:/workspace ansiblesec:latest scan /workspace/bad_playbook.yml
```

## Common Issues

### Issue: Cargo not found
**Solution**: Install Rust or add to PATH
```bash
source $HOME/.cargo/env
```

### Issue: Compilation errors
**Solution**: Update Rust
```bash
rustup update
```

### Issue: OpenSSL errors (Linux)
**Solution**: Install OpenSSL development packages
```bash
# Ubuntu/Debian
sudo apt-get install pkg-config libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# macOS
brew install openssl
```

### Issue: Slow builds
**Solution**: Use incremental compilation and caching
```bash
export CARGO_INCREMENTAL=1
```

Or use sccache:
```bash
cargo install sccache
export RUSTC_WRAPPER=sccache
```

## IDE Setup

### VS Code
Install extensions:
- rust-analyzer
- CodeLLDB (for debugging)
- Better TOML

### CLion / IntelliJ IDEA
- Install Rust plugin

### Vim/Neovim
- Install rust.vim
- Configure LSP with rust-analyzer

## Debugging

### Using cargo
```bash
RUST_LOG=debug cargo run -- scan examples/bad_playbook.yml
```

### Using LLDB/GDB
```bash
cargo build
lldb target/debug/ansiblesec
# or
gdb target/debug/ansiblesec
```

### Using VS Code
Add to `.vscode/launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug ansiblesec",
      "cargo": {
        "args": ["build", "--bin=ansiblesec"]
      },
      "args": ["scan", "examples/bad_playbook.yml"],
      "cwd": "${workspaceFolder}"
    }
  ]
}
```

## Performance Optimization

### Release builds with optimizations
Edit `Cargo.toml`:
```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

### Profile-guided optimization
```bash
# Step 1: Build with instrumentation
RUSTFLAGS="-Cprofile-generate=/tmp/pgo-data" cargo build --release

# Step 2: Run to generate profile
./target/release/ansiblesec scan examples/

# Step 3: Build with profile
RUSTFLAGS="-Cprofile-use=/tmp/pgo-data/merged.profdata" cargo build --release
```

## Benchmarking

```bash
# Install criterion
cargo install cargo-criterion

# Run benchmarks
cargo bench
```

## Code Coverage

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage
cargo tarpaulin --out Html

# Open coverage/index.html
```

## Documentation

### Generate API docs
```bash
cargo doc --no-deps --open
```

### Build README examples
Ensure examples in README work:
```bash
cargo test --doc
```

## Pre-commit Hooks

Install Git hooks:
```bash
./scripts/install-hooks.sh
```

This runs formatting, linting, and tests before each commit.

## Clean Build

Remove all build artifacts:
```bash
cargo clean
# or
make clean
```

## Environment Variables

Useful environment variables:
```bash
# Logging level
export RUST_LOG=debug

# Backtrace on panic
export RUST_BACKTRACE=1

# Full backtrace
export RUST_BACKTRACE=full

# Cargo home (for dependencies)
export CARGO_HOME=$HOME/.cargo

# Number of parallel jobs
export CARGO_BUILD_JOBS=4
```

## Troubleshooting Build Times

```bash
# Show build times
cargo build --release --timings

# Use cargo-bloat to analyze binary size
cargo install cargo-bloat
cargo bloat --release

# Use cargo-udeps to find unused dependencies
cargo install cargo-udeps
cargo +nightly udeps
```

## Next Steps

After successful build:
1. Run the examples: `make run-scan`
2. Read the documentation: See README.md
3. Try CI/CD integration: See .github/workflows/ci.yml
4. Contribute: See CONTRIBUTING.md

For support:
- GitHub Issues: Report bugs or request features
- Documentation: All .md files in the repository
- Code examples: See examples/ directory
