# 📚 ansiblesec Documentation Index

Welcome to the ansiblesec documentation! This index will help you find the information you need.

## 🎯 Start Here

**New to ansiblesec?** Start with these files in order:

1. **[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)** - High-level overview (5 min read)
2. **[GETTING_STARTED.md](GETTING_STARTED.md)** - Quick setup guide (10 min)
3. **[QUICKSTART.md](QUICKSTART.md)** - Command reference (5 min)

## 📖 Main Documentation

### For Users

| Document | Purpose | When to Read |
|----------|---------|--------------|
| **[README.md](README.md)** | Complete user guide | When you need full documentation |
| **[GETTING_STARTED.md](GETTING_STARTED.md)** | Quick start guide | First time using the tool |
| **[QUICKSTART.md](QUICKSTART.md)** | Command reference | Looking up specific commands |
| **[BUILD.md](BUILD.md)** | Build instructions | Compiling from source |
| **[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)** | Project summary | Understanding the project |

### For Developers

| Document | Purpose | When to Read |
|----------|---------|--------------|
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Technical architecture | Understanding internals |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | Contribution guidelines | Before contributing |
| **[BUILD.md](BUILD.md)** | Build & development | Setting up dev environment |
| **[SECURITY.md](SECURITY.md)** | Security policy | Reporting vulnerabilities |

### For DevOps/CI/CD

| Document | Purpose | When to Read |
|----------|---------|--------------|
| **[README.md](README.md)** (CI/CD section) | Integration examples | Setting up pipelines |
| **[.github/workflows/ci.yml](.github/workflows/ci.yml)** | GitHub Actions | Using GitHub Actions |
| **[.gitlab-ci.yml](.gitlab-ci.yml)** | GitLab CI | Using GitLab CI |
| **[Jenkinsfile](Jenkinsfile)** | Jenkins | Using Jenkins |
| **[action.yml](action.yml)** | GitHub Action | Creating workflows |

### Project Information

| Document | Purpose | When to Read |
|----------|---------|--------------|
| **[CHANGELOG.md](CHANGELOG.md)** | Version history | Checking what's new |
| **[LICENSE](LICENSE)** | License terms | Legal information |
| **[SECURITY.md](SECURITY.md)** | Security policy | Security concerns |
| **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** | Implementation status | Project completion |
| **[COMPLETION_CHECKLIST.md](COMPLETION_CHECKLIST.md)** | Feature checklist | Verifying features |

## 🔍 Find Information By Topic

### Installation & Setup
- [GETTING_STARTED.md](GETTING_STARTED.md) - Quick setup
- [BUILD.md](BUILD.md) - Building from source
- [README.md](README.md) - Installation section

### Usage & Commands
- [QUICKSTART.md](QUICKSTART.md) - Command reference
- [README.md](README.md) - CLI Reference section
- [examples/](examples/) - Example configurations

### Configuration
- [examples/.ansiblesec.yml](examples/.ansiblesec.yml) - Config example
- [examples/custom_rules.yml](examples/custom_rules.yml) - Custom rules
- [README.md](README.md) - Configuration section

### CI/CD Integration
- [README.md](README.md) - CI/CD Integration section
- [.github/workflows/ci.yml](.github/workflows/ci.yml) - GitHub Actions
- [.gitlab-ci.yml](.gitlab-ci.yml) - GitLab CI
- [Jenkinsfile](Jenkinsfile) - Jenkins
- [action.yml](action.yml) - GitHub Action

### Security Features
- [README.md](README.md) - Built-in Security Checks
- [SECURITY.md](SECURITY.md) - Security policy
- [src/secrets.rs](src/secrets.rs) - Secrets detection code
- [src/policy.rs](src/policy.rs) - Policy enforcement code

### Development
- [ARCHITECTURE.md](ARCHITECTURE.md) - Code architecture
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute
- [BUILD.md](BUILD.md) - Build instructions
- [Makefile](Makefile) - Build automation

### Examples
- [examples/bad_playbook.yml](examples/bad_playbook.yml) - Security issues demo
- [examples/good_playbook.yml](examples/good_playbook.yml) - Secure practices
- [examples/.ansiblesec.yml](examples/.ansiblesec.yml) - Configuration
- [examples/custom_rules.yml](examples/custom_rules.yml) - Custom rules

## 📁 Source Code Navigation

### Core Modules
- **[src/main.rs](src/main.rs)** - Entry point
- **[src/cli.rs](src/cli.rs)** - Command-line interface
- **[src/scanner.rs](src/scanner.rs)** - Scanning engine
- **[src/secrets.rs](src/secrets.rs)** - Secrets detection
- **[src/policy.rs](src/policy.rs)** - Policy enforcement
- **[src/linter.rs](src/linter.rs)** - Linting
- **[src/rules.rs](src/rules.rs)** - Rules management
- **[src/reporting.rs](src/reporting.rs)** - Output formatting
- **[src/sbom.rs](src/sbom.rs)** - SBOM generation
- **[src/cache.rs](src/cache.rs)** - Caching
- **[src/config.rs](src/config.rs)** - Configuration
- **[src/errors.rs](src/errors.rs)** - Error handling

### Tests
- **[tests/integration_test.rs](tests/integration_test.rs)** - Integration tests

## 🎓 Learning Paths

### Path 1: Quick User (30 minutes)
1. [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) - 5 min
2. [GETTING_STARTED.md](GETTING_STARTED.md) - 10 min
3. [QUICKSTART.md](QUICKSTART.md) - 5 min
4. Try examples - 10 min

### Path 2: Power User (2 hours)
1. Quick User path (above)
2. [README.md](README.md) - 30 min
3. [examples/](examples/) - Explore examples - 30 min
4. Create custom config - 30 min

### Path 3: Developer (4 hours)
1. Power User path (above)
2. [ARCHITECTURE.md](ARCHITECTURE.md) - 30 min
3. [BUILD.md](BUILD.md) - 30 min
4. Read source code - 1 hour
5. [CONTRIBUTING.md](CONTRIBUTING.md) - 15 min
6. Run tests - 15 min

### Path 4: DevOps Engineer (1 hour)
1. [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) - 5 min
2. [README.md](README.md) - CI/CD section - 15 min
3. Review CI/CD configs - 20 min
4. Set up pipeline - 20 min

## 🔗 Quick Links

### Most Important Files
- 🚀 **Start here**: [GETTING_STARTED.md](GETTING_STARTED.md)
- 📖 **Full docs**: [README.md](README.md)
- ⚡ **Quick ref**: [QUICKSTART.md](QUICKSTART.md)
- 🏗️ **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- 🤝 **Contribute**: [CONTRIBUTING.md](CONTRIBUTING.md)

### Configuration Files
- 📝 **Cargo.toml** - Dependencies
- ⚙️ **rustfmt.toml** - Code style
- 🐳 **Dockerfile** - Container image
- 🔧 **Makefile** - Build commands

### CI/CD Templates
- 🐙 **GitHub**: [.github/workflows/ci.yml](.github/workflows/ci.yml)
- 🦊 **GitLab**: [.gitlab-ci.yml](.gitlab-ci.yml)
- 🏠 **Jenkins**: [Jenkinsfile](Jenkinsfile)
- 🎬 **Action**: [action.yml](action.yml)

## 💡 Tips for Reading

1. **Start with overviews** - Don't dive into code first
2. **Use the search** - All docs are searchable
3. **Try examples** - Hands-on learning works best
4. **Check multiple sources** - Some topics span files
5. **Keep QUICKSTART.md open** - Great reference while working

## 🆘 Common Questions

**Q: How do I install it?**  
A: See [GETTING_STARTED.md](GETTING_STARTED.md)

**Q: What commands are available?**  
A: See [QUICKSTART.md](QUICKSTART.md)

**Q: How do I configure it?**  
A: See [examples/.ansiblesec.yml](examples/.ansiblesec.yml) and [README.md](README.md)

**Q: How do I use it in CI/CD?**  
A: See [README.md](README.md) CI/CD section and config files

**Q: How do I contribute?**  
A: See [CONTRIBUTING.md](CONTRIBUTING.md)

**Q: How does it work internally?**  
A: See [ARCHITECTURE.md](ARCHITECTURE.md)

**Q: Is it secure?**  
A: See [SECURITY.md](SECURITY.md)

**Q: What's new?**  
A: See [CHANGELOG.md](CHANGELOG.md)

## 📊 Documentation Statistics

- **Total Documentation**: 11 markdown files
- **Total Words**: ~20,000+
- **Example Files**: 5
- **CI/CD Configs**: 4
- **Scripts**: 4
- **Source Modules**: 12

## 🎯 Next Steps

Based on your role:

**User**: Start with [GETTING_STARTED.md](GETTING_STARTED.md)  
**Developer**: Read [ARCHITECTURE.md](ARCHITECTURE.md)  
**DevOps**: Check CI/CD configs  
**Contributor**: See [CONTRIBUTING.md](CONTRIBUTING.md)

---

**Need help?** All documentation is interconnected - use this index to navigate!

Happy scanning! 🛡️
