# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in ansiblesec, please report it responsibly.

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via GitHub's Security Advisories or create an issue with the label "security":

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** of the vulnerability
4. **Suggested fix** (if you have one)

You can also use GitHub's private vulnerability reporting feature.

### What to Expect

- We will acknowledge receipt of your report within 48 hours
- We will provide a detailed response within 7 days
- We will keep you informed of our progress
- We will credit you in the security advisory (unless you prefer to remain anonymous)

### Security Best Practices for Users

When using ansiblesec:

1. **Keep it updated**: Always use the latest version
2. **Validate rules files**: Only use trusted rules files
3. **Review findings**: Manually verify critical findings
4. **Secure output**: Protect scan reports as they may contain sensitive information
5. **Cache security**: The cache directory may contain file hashes and findings
6. **Network calls**: Be cautious when enabling CVE lookups (network calls)

### Known Security Considerations

1. **Regex DoS**: Complex regex patterns in custom rules could cause performance issues
2. **File size limits**: Large files are skipped by default (configurable)
3. **Path traversal**: File paths are validated to prevent directory traversal
4. **Sensitive data in logs**: Use appropriate log levels in production

## Security Features

ansiblesec includes several security features:

- **Secret redaction**: Detected secrets are automatically redacted in reports
- **No network by default**: Network calls only when explicitly enabled
- **Safe file handling**: Input validation and size limits
- **Secure caching**: File integrity verification with BLAKE3 hashing
- **Minimal dependencies**: Reduced attack surface

## Security Scanning of ansiblesec Itself

We regularly scan our own codebase:

- **Dependency auditing**: `cargo audit` in CI/CD
- **SAST**: CodeQL analysis on every PR
- **Dependency updates**: Automated with Dependabot
- **Fuzzing**: Planned for critical components

## Disclosure Policy

When we receive a security report:

1. We will confirm the vulnerability
2. We will develop and test a fix
3. We will prepare a security advisory
4. We will release a patched version
5. We will publish the security advisory

We aim to complete this process within 90 days of the initial report.

## Bug Bounty

We currently do not have a bug bounty program. However, we greatly appreciate security researchers who help us keep ansiblesec secure.

## Contact

For security concerns: GitHub Security Advisories

For general questions: GitHub Issues
