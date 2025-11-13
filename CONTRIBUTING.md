# Contributing to ansiblesec

Thank you for your interest in contributing to ansiblesec! We welcome contributions from the community.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/ansiblesec.git`
3. Create a feature branch: `git checkout -b feature/my-new-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Commit your changes: `git commit -am 'Add new feature'`
7. Push to the branch: `git push origin feature/my-new-feature`
8. Submit a pull request

## Development Setup

### Prerequisites

- Rust 1.70 or higher
- Cargo

### Building

```bash
cargo build
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_aws_key_detection
```

### Code Style

We follow standard Rust formatting conventions:

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Run clippy
cargo clippy -- -D warnings
```

## Adding New Rules

To add a new security rule:

1. Define the rule in `src/rules.rs`
2. Implement the check logic in `src/policy.rs`
3. Add tests in `tests/integration_test.rs`
4. Update documentation

Example:

```rust
Rule {
    id: "POLICY_006".to_string(),
    name: "My New Rule".to_string(),
    description: "Description of what it checks".to_string(),
    severity: "HIGH".to_string(),
    enabled: true,
    rule_type: RuleType::CustomYamlPath {
        path: "some.yaml.path",
        expected_value: Some("expected".to_string()),
    },
}
```

## Adding Secret Patterns

To add new secret detection patterns:

1. Add the pattern to `src/secrets.rs` in the `DEFAULT_PATTERNS` vector
2. Test with various examples
3. Document the pattern

Example:

```rust
SecretPattern {
    name: "New Service Token".to_string(),
    pattern: r"new-service-[A-Za-z0-9]{32}".to_string(),
    severity: Severity::Critical,
    description: "New service token detected".to_string(),
}
```

## Testing Guidelines

- Write unit tests for new functions
- Add integration tests for new features
- Include test cases for edge cases
- Test with real-world Ansible playbooks

## Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Write clear commit messages
- Update documentation as needed
- Add tests for new functionality
- Ensure all tests pass
- Update CHANGELOG.md

## Code Review Process

1. All PRs require at least one review
2. Address review comments
3. Ensure CI passes
4. Squash commits if requested
5. Maintainer will merge when ready

## Reporting Bugs

Use GitHub Issues to report bugs. Include:

- Description of the bug
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (OS, Rust version, etc.)
- Sample playbook if applicable

## Feature Requests

We welcome feature requests! Please:

- Check if the feature already exists or is planned
- Describe the use case clearly
- Explain why it would be beneficial
- Provide examples if possible

## Security Issues

For security vulnerabilities, please use GitHub Security Advisories instead of using the issue tracker.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
