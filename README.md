# 🔒 AnsibleSec

**Production-ready security scanner and policy enforcement tool for Ansible playbooks**

[![Build Status](https://github.com/yourusername/ansiblesec/workflows/CI/badge.svg)](https://github.com/yourusername/ansiblesec/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/yourusername/ansiblesec)](https://github.com/yourusername/ansiblesec/releases)

AnsibleSec is a blazing-fast, production-grade security scanner for Ansible playbooks written in Rust. It detects secrets, enforces security policies, performs linting, and generates SBOMs to ensure your infrastructure-as-code follows security best practices.

## ✨ Features

- 🔍 **Secrets Detection** - Detect 50+ types of hardcoded credentials (AWS keys, API tokens, passwords, private keys, etc.)
- 📋 **Policy Enforcement** - Enforce 50+ security policies for Ansible best practices
- 🧹 **Linting** - Quality checks for playbook structure and best practices
- 📦 **SBOM Generation** - Generate CycloneDX and SPDX Software Bill of Materials
- ⚡ **Multi-threaded** - Parallel scanning for blazing-fast performance
- 💾 **Caching** - Smart file hashing to skip unchanged files
- 🎨 **Multiple Outputs** - Text, JSON, and SARIF formats
- 🔧 **Customizable Rules** - Define your own secrets patterns and policies via YAML
- 🚀 **CI/CD Ready** - Exit codes and formats designed for automation
- 🐳 **Docker Support** - Run in containers with minimal footprint

## 🚀 Quick Start

### Installation

#### From Release Binary

```bash
# Download the latest release
wget https://github.com/yourusername/ansiblesec/releases/latest/download/ansiblesec-linux-x86_64.tar.gz

# Extract and install
tar -xzf ansiblesec-linux-x86_64.tar.gz
sudo mv ansiblesec /usr/local/bin/
```

#### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/ansiblesec.git
cd ansiblesec

# Build with Cargo
cargo build --release

# Install
sudo cp target/release/ansiblesec /usr/local/bin/
```

#### Using Docker

```bash
docker pull yourusername/ansiblesec:latest
docker run --rm -v $(pwd):/workspace ansiblesec scan /workspace/playbook.yml
```

### Basic Usage

```bash
# Scan a single playbook
ansiblesec scan playbook.yml

# Scan an entire directory
ansiblesec scan ansible/

# Lint playbooks
ansiblesec lint playbook.yml

# Generate SBOM
ansiblesec sbom playbook.yml --format cyclonedx

# Output as JSON
ansiblesec scan playbook.yml --format json

# Use custom rules
ansiblesec scan playbook.yml --secrets-rules custom-secrets.yml --policy-rules custom-policies.yml

# CI/CD mode (fail on findings)
ansiblesec scan playbook.yml --ci-mode --fail-on-findings
```

## 📖 Documentation

### Commands

#### `scan` - Security Scanning

Scan Ansible playbooks for secrets and policy violations.

```bash
ansiblesec scan [OPTIONS] <PATH>

Options:
  -c, --config <FILE>              Configuration file path [default: .ansiblesec.yml]
  -f, --format <FORMAT>            Output format [default: text] [possible: text, json, sarif]
  -o, --output <FILE>              Write output to file
  --secrets-rules <FILE>           Custom secrets detection rules [default: rules/secrets.yml]
  --policy-rules <FILE>            Custom policy rules [default: rules/policies.yml]
  --no-cache                       Disable caching
  --ci-mode                        CI/CD mode with exit codes
  --fail-on-findings              Exit with error code if findings detected
  -v, --verbose                    Verbose output
```

**Exit Codes:**
- `0` - No issues found
- `1` - Error occurred
- `2` - Critical findings detected (with `--fail-on-findings`)
- `3` - High severity findings detected (with `--fail-on-findings`)

#### `lint` - Playbook Linting

Perform quality and security linting on playbooks.

```bash
ansiblesec lint [OPTIONS] <PATH>

Options:
  -c, --config <FILE>              Configuration file path
  -f, --format <FORMAT>            Output format [default: text]
  -o, --output <FILE>              Write output to file
  --ci-mode                        CI/CD mode
  --fail-on-findings              Exit with error code if findings detected
```

#### `sbom` - SBOM Generation

Generate Software Bill of Materials for Ansible dependencies.

```bash
ansiblesec sbom [OPTIONS] <PATH>

Options:
  -f, --format <FORMAT>            SBOM format [default: cyclonedx] [possible: cyclonedx, spdx]
  -o, --output <FILE>              Write SBOM to file
```

#### `rules` - Rules Management

Validate and manage custom rules.

```bash
ansiblesec rules validate <FILE>     # Validate rules file
ansiblesec rules list <FILE>         # List all rules
```

### Configuration

Create a `.ansiblesec.yml` configuration file:

```yaml
general:
  max_depth: 10
  max_file_size: 10485760  # 10MB
  parallel_jobs: 0         # 0 = auto (CPU cores)
  cache_enabled: true
  cache_dir: ".ansiblesec_cache"

secrets:
  enabled: true
  rules_file: "rules/secrets.yml"
  entropy_threshold: 4.5
  min_entropy_length: 20

policies:
  enabled: true
  rules_file: "rules/policies.yml"

linter:
  enabled: true
  max_line_length: 120
  require_name: true
  check_permissions: true
  
exclude:
  paths:
    - "vendor/"
    - "node_modules/"
    - ".git/"
  patterns:
    - "*.retry"
    - "*.swp"
```

### Custom Rules

#### Secrets Rules (`rules/secrets.yml`)

Define custom patterns for secrets detection:

```yaml
rules:
  - id: SECRET_CUSTOM_API_KEY
    name: "Custom API Key"
    pattern: 'custom_api_key:\s*["\']?([a-zA-Z0-9_-]{32,})["\']?'
    severity: CRITICAL
    description: "Custom API key pattern detected"
    enabled: true
    
  - id: SECRET_DATABASE_PASSWORD
    name: "Database Password"
    pattern: 'db_password:\s*["\']?([^"\'\s]{8,})["\']?'
    severity: HIGH
    description: "Database password detected"
    enabled: true
```

**Available Severity Levels:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

#### Policy Rules (`rules/policies.yml`)

Define security policies for Ansible playbooks:

```yaml
rules:
  - id: POLICY_CUSTOM_001
    name: "Require sudo password"
    severity: HIGH
    description: "Tasks with become should use become_password or ask for password"
    enabled: true
    check_type: "module_usage"
    conditions:
      - field: "become"
        operator: "equals"
        value: true
      - field: "become_password"
        operator: "not_exists"
        
  - id: POLICY_CUSTOM_002
    name: "Restrict dangerous modules"
    severity: CRITICAL
    description: "Dangerous modules should not be used"
    enabled: true
    check_type: "module_blacklist"
    conditions:
      - modules: ["raw", "script", "shell"]
        require_justification: true
```

## 🔍 Examples

### Example: Scanning Output

```bash
$ ansiblesec scan playbook.yml

================================================================
                  ANSIBLESEC SECURITY SCAN REPORT
================================================================

Files scanned: 1
Total findings: 8

Summary:
  4 CRITICAL Critical
  2 HIGH High
  2 MEDIUM Medium
  0 LOW Low
  0 INFO Info

Secrets Detected:
----------------------------------------------------------------
📄 playbook.yml
  12:7 [CRITICAL] AWS Access Key ID detected
    └─ AKIA***REDACTED***
  13:21 [CRITICAL] AWS Secret Access Key detected
    └─ wJal***REDACTED***
  25:10 [HIGH] GitHub Personal Access Token detected
    └─ ghp_***REDACTED***

Policy Violations:
----------------------------------------------------------------
📄 playbook.yml
  45:0 [CRITICAL] Use of dangerous 'shell' module (POLICY_001)
    └─ Consider using specific modules instead of shell
  67:0 [HIGH] File permissions too permissive (POLICY_005)
    └─ Mode 0777 detected, use more restrictive permissions

================================================================
❌ CRITICAL issues found - immediate action required!
================================================================
```

### Example: JSON Output

```bash
$ ansiblesec scan playbook.yml --format json

{
  "files_scanned": 1,
  "total_findings": 8,
  "summary": {
    "critical": 4,
    "high": 2,
    "medium": 2,
    "low": 0,
    "info": 0
  },
  "secrets": [
    {
      "file_path": "playbook.yml",
      "line": 12,
      "column": 7,
      "severity": "CRITICAL",
      "rule_id": "SECRET_AWS_ACCESS_KEY",
      "message": "AWS Access Key ID detected",
      "context": "AKIA***REDACTED***"
    }
  ],
  "policies": [
    {
      "file_path": "playbook.yml",
      "line": 45,
      "column": 0,
      "severity": "CRITICAL",
      "rule_id": "POLICY_001",
      "message": "Use of dangerous 'shell' module",
      "remediation": "Consider using specific modules instead of shell"
    }
  ]
}
```

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  ansiblesec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install AnsibleSec
        run: |
          wget https://github.com/yourusername/ansiblesec/releases/latest/download/ansiblesec-linux-x86_64.tar.gz
          tar -xzf ansiblesec-linux-x86_64.tar.gz
          sudo mv ansiblesec /usr/local/bin/
          
      - name: Scan playbooks
        run: ansiblesec scan ansible/ --format sarif --output results.sarif --ci-mode --fail-on-findings
        
      - name: Upload results
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
ansiblesec:
  stage: security
  image: yourusername/ansiblesec:latest
  script:
    - ansiblesec scan ansible/ --format json --output results.json --ci-mode --fail-on-findings
  artifacts:
    reports:
      sast: results.json
    when: always
```

### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'ansiblesec scan ansible/ --format json --output results.json --ci-mode'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'results.json', fingerprint: true
        }
    }
}
```

## 📊 Built-in Rules

### Secrets Detection (50+ patterns)

- **Cloud Providers:** AWS Keys, Azure Keys, GCP Keys, DigitalOcean Tokens
- **Version Control:** GitHub Tokens, GitLab Tokens, Bitbucket Keys
- **APIs:** Slack Tokens, Stripe Keys, Twilio Keys, SendGrid Keys
- **Databases:** MongoDB URIs, PostgreSQL passwords, MySQL passwords
- **Encryption:** Private Keys (RSA, SSH, PGP), Certificates, JWT tokens
- **Generic:** API keys, passwords, secrets, tokens with entropy analysis

### Policy Violations (50+ rules)

- **Dangerous Modules:** shell, raw, script usage
- **Security Configs:** File permissions, become usage, vault usage
- **Best Practices:** Task naming, variable naming, deprecations
- **Network Security:** Firewall rules, SSL/TLS validation
- **Data Protection:** Credential handling, sensitive data exposure

### Linting Rules

- Code quality and formatting
- Ansible best practices
- YAML syntax and structure
- Task and playbook organization

## 🏗️ Architecture

```
ansiblesec/
├── src/
│   ├── main.rs          # Entry point
│   ├── cli.rs           # Command-line interface
│   ├── scanner.rs       # File scanning engine
│   ├── secrets.rs       # Secrets detection (external rules)
│   ├── policy.rs        # Policy enforcement (external rules)
│   ├── linter.rs        # Linting engine
│   ├── reporting.rs     # Output formatting
│   ├── sbom.rs          # SBOM generation
│   ├── cache.rs         # File caching
│   ├── config.rs        # Configuration
│   ├── rules.rs         # Rules management
│   └── errors.rs        # Error handling
├── rules/
│   ├── secrets.yml      # 50+ secrets detection rules
│   └── policies.yml     # 50+ policy rules
├── examples/
│   ├── bad_playbook.yml # Example with issues
│   ├── good_playbook.yml # Example following best practices
│   └── custom_rules/    # Example custom rules
├── .github/
│   └── workflows/       # GitHub Actions CI/CD
└── Cargo.toml           # Rust dependencies
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Run linter (`cargo clippy`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) for performance and safety
- Uses [regex](https://github.com/rust-lang/regex) for pattern matching
- Inspired by tools like [ansible-lint](https://github.com/ansible/ansible-lint) and [detect-secrets](https://github.com/Yelp/detect-secrets)

## 📞 Support

- 🐛 [Report bugs](https://github.com/yourusername/ansiblesec/issues)
- 💡 [Request features](https://github.com/yourusername/ansiblesec/issues)
- 📖 [Documentation](https://github.com/yourusername/ansiblesec/wiki)
- 💬 [Discussions](https://github.com/yourusername/ansiblesec/discussions)

---

**Made with ❤️ for the DevSecOps community**
