#[cfg(test)]
mod tests {
    use ansiblesec::config::*;
    use ansiblesec::scanner::*;
    use ansiblesec::secrets::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_aws_key_detection() {
        let detector = SecretDetector::new(vec![], 4.5).unwrap();
        let content = r#"
aws_access_key_id: AKIAIOSFODNN7EXAMPLE
aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#;

        let findings = detector.scan_content(content);
        assert!(findings.len() >= 1, "Should detect AWS access key");

        let has_aws_key = findings.iter().any(|f| f.secret_type.contains("AWS"));
        assert!(has_aws_key, "Should contain AWS key finding");
    }

    #[test]
    fn test_github_token_detection() {
        let detector = SecretDetector::new(vec![], 4.5).unwrap();
        let content = "github_token: ghp_1234567890abcdefghijklmnopqrstuvwxyz12";

        let findings = detector.scan_content(content);
        assert!(!findings.is_empty(), "Should detect GitHub token");
    }

    #[test]
    fn test_private_key_detection() {
        let detector = SecretDetector::new(vec![], 4.5).unwrap();
        let content = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----
"#;

        let findings = detector.scan_content(content);
        assert!(!findings.is_empty(), "Should detect private key");
    }

    #[test]
    fn test_entropy_detection() {
        let detector = SecretDetector::new(vec![], 4.0).unwrap();

        // High entropy string
        let high_entropy = "aB3dEf9hIj2kLm5nOp8qRs1tUv4wXy7z";
        let content = format!("secret_key: \"{}\"", high_entropy);

        let findings = detector.scan_content(&content);
        assert!(!findings.is_empty(), "Should detect high entropy string");
    }

    #[test]
    fn test_custom_pattern() {
        let custom_pattern = SecretPattern {
            name: "Custom Token".to_string(),
            pattern: r"CUSTOM-[A-Z0-9]{32}".to_string(),
            severity: Severity::High,
            description: "Custom token pattern".to_string(),
        };

        let detector = SecretDetector::new(vec![custom_pattern], 4.5).unwrap();
        let content = "api_token: CUSTOM-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";

        let findings = detector.scan_content(content);
        assert!(!findings.is_empty(), "Should detect custom pattern");
    }

    #[test]
    fn test_scanner_scan_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.yml");

        let content = r#"
---
- name: Test playbook
  hosts: localhost
  vars:
    password: SuperSecret123!
    aws_key: AKIAIOSFODNN7EXAMPLE
  tasks:
    - name: Bad task
      shell: echo "test"
"#;

        fs::write(&file_path, content).unwrap();

        let config = Config::default();
        let scanner = Scanner::new(config, 0, false);
        let findings = scanner.scan(&file_path).unwrap();

        assert!(findings.files_scanned > 0);
        assert!(findings.total_findings() > 0);
    }

    #[test]
    fn test_scanner_exclude_paths() {
        let temp_dir = TempDir::new().unwrap();
        let git_dir = temp_dir.path().join(".git");
        fs::create_dir(&git_dir).unwrap();

        let git_file = git_dir.join("config.yml");
        fs::write(&git_file, "password: test123").unwrap();

        let config = Config::default();
        let scanner = Scanner::new(config, 0, false);
        let findings = scanner.scan(temp_dir.path()).unwrap();

        assert_eq!(findings.files_scanned, 0, "Should exclude .git directory");
    }

    #[test]
    fn test_scanner_multi_threaded() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple test files
        for i in 0..10 {
            let file_path = temp_dir.path().join(format!("playbook{}.yml", i));
            fs::write(&file_path, "password: test123").unwrap();
        }

        let config = Config::default();
        let scanner = Scanner::new(config, 4, false);
        let findings = scanner.scan(temp_dir.path()).unwrap();

        assert!(findings.files_scanned >= 10);
    }

    #[test]
    fn test_severity_levels() {
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Medium.as_str(), "MEDIUM");
        assert_eq!(Severity::Low.as_str(), "LOW");
        assert_eq!(Severity::Info.as_str(), "INFO");
    }

    #[test]
    fn test_scan_findings_helpers() {
        let findings = ScanFindings {
            files_scanned: 5,
            secrets: vec![],
            policy_violations: vec![],
            lint_issues: vec![],
            summary: Summary {
                critical: 2,
                high: 3,
                medium: 1,
                low: 0,
                info: 0,
            },
        };

        assert!(findings.has_critical());
        assert!(findings.has_high());
        assert!(findings.has_errors());
        assert_eq!(findings.total_findings(), 6);
    }
}
