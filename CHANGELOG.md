# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of ansiblesec
- Secrets detection with regex and entropy analysis
- Policy enforcement engine with custom rules
- Linting capabilities for Ansible playbooks
- SBOM generation (CycloneDX and SPDX formats)
- Multi-threaded scanning support
- Intelligent caching system
- CI/CD integration examples (GitHub Actions, GitLab CI, Jenkins)
- Comprehensive CLI with scan, lint, sbom, and rules subcommands
- Docker support
- Cross-platform binaries (Linux, macOS, Windows)
- SARIF output format for code scanning tools
- Default security rules:
  - POLICY_001: Disallow risky modules
  - POLICY_002: Require Ansible Vault
  - POLICY_003: Disallow hardcoded credentials
  - POLICY_004: Require no_log for sensitive tasks
  - POLICY_005: Check file permissions
- Default secret patterns:
  - AWS keys
  - GitHub tokens
  - Private keys
  - API keys
  - Generic secrets
  - High entropy strings
- Linting rules:
  - YAML structure validation
  - Best practices enforcement
  - Naming conventions
  - Line length and formatting

### Security
- Safe handling of sensitive data with redaction
- No external network calls by default
- Secure caching with file hashing

## [0.1.0] - 2025-11-13

### Added
- Initial project structure
- Core scanning engine
- Basic documentation
- Example playbooks and configurations
- Test suite
- CI/CD workflows

[Unreleased]: https://github.com/yourusername/ansiblesec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/ansiblesec/releases/tag/v0.1.0
