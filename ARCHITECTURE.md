# ansiblesec - Project Structure

This document provides an overview of the ansiblesec project structure.

## Directory Structure

```
ansiblesec/
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions CI/CD workflow
├── src/
│   ├── main.rs                    # Entry point
│   ├── cli.rs                     # CLI argument parsing with clap
│   ├── config.rs                  # Configuration management
│   ├── scanner.rs                 # Main scanning engine (multi-threaded)
│   ├── secrets.rs                 # Secrets detection (regex + entropy)
│   ├── policy.rs                  # Policy enforcement engine
│   ├── linter.rs                  # Linting engine
│   ├── rules.rs                   # Rules management
│   ├── reporting.rs               # Report generation (text, JSON, SARIF)
│   ├── sbom.rs                    # SBOM generation (CycloneDX, SPDX)
│   ├── cache.rs                   # Caching system with BLAKE3
│   └── errors.rs                  # Error handling
├── tests/
│   └── integration_test.rs        # Integration tests
├── examples/
│   ├── bad_playbook.yml           # Example with security issues
│   ├── good_playbook.yml          # Example secure playbook
│   ├── .ansiblesec.yml            # Example configuration
│   ├── custom_rules.yml           # Example custom rules
│   └── requirements.yml           # Example dependencies
├── Cargo.toml                     # Rust dependencies and metadata
├── Cargo.lock                     # Locked dependencies
├── Dockerfile                     # Docker image (Debian-based)
├── Dockerfile.alpine              # Docker image (Alpine-based)
├── Makefile                       # Build automation
├── rustfmt.toml                   # Rust formatting configuration
├── .gitignore                     # Git ignore patterns
├── .gitlab-ci.yml                 # GitLab CI configuration
├── Jenkinsfile                    # Jenkins pipeline
├── action.yml                     # GitHub Action definition
├── setup.sh                       # Development setup script
├── README.md                      # Main documentation
├── QUICKSTART.md                  # Quick reference guide
├── CONTRIBUTING.md                # Contribution guidelines
├── CHANGELOG.md                   # Version history
├── SECURITY.md                    # Security policy
└── LICENSE                        # MIT License

```

## Core Modules

### main.rs
Entry point that initializes logging and delegates to CLI.

### cli.rs
Implements the command-line interface using clap:
- `scan` - Security scanning
- `lint` - Code quality checks
- `sbom` - SBOM generation
- `rules` - Rule management

### scanner.rs
Core scanning engine:
- Multi-threaded file scanning with rayon
- File collection and filtering
- Findings aggregation
- Cache integration

### secrets.rs
Secrets detection:
- Default patterns (AWS, GitHub, SSH keys, etc.)
- Custom patterns support
- Shannon entropy calculation
- Secret redaction for safe reporting

### policy.rs
Policy enforcement:
- Rule-based checking
- YAML path validation
- Module restrictions
- Vault requirement checks
- Permission validation

### linter.rs
Ansible-specific linting:
- YAML structure validation
- Best practices enforcement
- Naming conventions
- Code quality checks

### rules.rs
Rules management:
- Rule definition and validation
- Rule loading from YAML
- Default rules set
- Rule listing and filtering

### reporting.rs
Report generation:
- Text output with colors
- JSON output for automation
- SARIF output for code scanning
- Severity-based formatting

### sbom.rs
Software Bill of Materials:
- CycloneDX format support
- SPDX format support
- Role and collection parsing
- Optional CVE lookups

### cache.rs
Intelligent caching:
- BLAKE3 file hashing
- JSON-based cache storage
- Automatic invalidation
- Configurable cache directory

### config.rs
Configuration management:
- YAML configuration loading
- Default settings
- Environment overrides
- Validation

### errors.rs
Error handling:
- Custom error types
- Error conversion
- User-friendly messages

## Key Features

### 1. Secrets Detection
- **Regex-based**: Detects known patterns (AWS keys, tokens, etc.)
- **Entropy-based**: Finds high-entropy strings that may be secrets
- **Configurable**: Custom patterns via configuration
- **Safe**: Automatic redaction in reports

### 2. Policy Enforcement
- **Built-in rules**: Common security policies
- **Custom rules**: YAML-based rule definitions
- **Flexible**: Multiple rule types supported
- **Severity levels**: Critical, High, Medium, Low, Info

### 3. Performance
- **Multi-threaded**: Parallel file scanning with rayon
- **Caching**: Avoid rescanning unchanged files
- **Streaming**: Memory-efficient processing
- **Optimized**: Built with Rust for speed

### 4. CI/CD Integration
- **Exit codes**: Fail pipelines on findings
- **Multiple formats**: JSON, SARIF for tool integration
- **Templates**: GitHub Actions, GitLab CI, Jenkins
- **Docker**: Containerized execution

### 5. Extensibility
- **Plugin system**: Custom rules via YAML
- **Multiple formats**: Various input/output formats
- **Configurable**: Fine-tune behavior
- **Modular**: Clean separation of concerns

## Development Workflow

1. **Setup**: Run `./setup.sh` or `make setup`
2. **Build**: Run `make build`
3. **Test**: Run `make test`
4. **Format**: Run `make format`
5. **Lint**: Run `make lint`
6. **Check**: Run `make check` (format + lint + test)

## Testing Strategy

### Unit Tests
- Located in each module file
- Test individual functions
- Mock external dependencies

### Integration Tests
- Located in `tests/` directory
- Test complete workflows
- Use real file system with tempfiles

### Example Tests
- Use `examples/` directory
- Validate against known good/bad playbooks
- Ensure backward compatibility

## Release Process

1. Update `CHANGELOG.md`
2. Bump version in `Cargo.toml`
3. Create git tag
4. GitHub Actions builds binaries
5. Docker images published
6. GitHub Release created

## Security Considerations

- **Input validation**: All file paths validated
- **File size limits**: Prevent DoS
- **No eval**: No dynamic code execution
- **Dependency auditing**: Regular cargo audit
- **Minimal privileges**: Docker runs as non-root

## Performance Characteristics

- **Memory**: O(n) where n = number of files
- **Disk**: Optional cache (configurable)
- **CPU**: Scales with thread count
- **Network**: Only when CVE lookup enabled

## Future Enhancements

- [ ] OPA/Rego support for policies
- [ ] Terraform/Kubernetes integration
- [ ] Web UI for reports
- [ ] Plugin marketplace
- [ ] Real-time CVE database
- [ ] Machine learning for secret detection
- [ ] VS Code extension
- [ ] Pre-commit hooks
