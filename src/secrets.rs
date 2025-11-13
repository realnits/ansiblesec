use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPattern {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub description: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretsRulesFile {
    rules: Vec<SecretPattern>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            "INFO" => Severity::Info,
            _ => Severity::Medium,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretDetector {
    patterns: Vec<CompiledPattern>,
    entropy_threshold: f64,
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    id: String,
    #[allow(dead_code)]
    name: String,
    regex: Regex,
    severity: Severity,
    description: String,
}

impl SecretDetector {
    /// Create with custom patterns
    #[allow(dead_code)]
    pub fn new(patterns: Vec<SecretPattern>, entropy_threshold: f64) -> Result<Self> {
        let mut compiled_patterns = Vec::new();

        for pattern in patterns {
            match Regex::new(&pattern.pattern) {
                Ok(regex) => {
                    compiled_patterns.push(CompiledPattern {
                        id: pattern.id,
                        name: pattern.name,
                        regex,
                        severity: Severity::from_str(&pattern.severity),
                        description: pattern.description,
                    });
                }
                Err(e) => {
                    eprintln!("Warning: Invalid regex pattern for {}: {}", pattern.name, e);
                }
            }
        }

        Ok(Self {
            patterns: compiled_patterns,
            entropy_threshold,
        })
    }

    /// Create from external rules file
    pub fn from_file<P: AsRef<Path>>(path: P, entropy_threshold: f64) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())?;
        let rules_file: SecretsRulesFile = serde_yaml::from_str(&content)?;

        let mut patterns = Vec::new();
        for rule in rules_file.rules {
            if !rule.enabled {
                continue;
            }

            match Regex::new(&rule.pattern) {
                Ok(regex) => {
                    patterns.push(CompiledPattern {
                        id: rule.id,
                        name: rule.name,
                        regex,
                        severity: Severity::from_str(&rule.severity),
                        description: rule.description,
                    });
                }
                Err(e) => {
                    eprintln!("Warning: Invalid regex pattern for rule {}: {}", rule.id, e);
                }
            }
        }

        Ok(Self {
            patterns,
            entropy_threshold,
        })
    }

    /// Fallback with minimal defaults
    pub fn with_defaults(entropy_threshold: f64) -> Self {
        let mut patterns = Vec::new();
        let defaults = vec![
            (
                "SECRET_AWS_ACCESS_KEY",
                "AWS Access Key",
                r"AKIA[0-9A-Z]{16}",
                "CRITICAL",
            ),
            (
                "SECRET_GITHUB_TOKEN",
                "GitHub Token",
                r"ghp_[0-9a-zA-Z]{36}",
                "CRITICAL",
            ),
            (
                "SECRET_PRIVATE_KEY",
                "Private Key",
                r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                "CRITICAL",
            ),
        ];

        for (id, name, pattern, sev) in defaults {
            if let Ok(regex) = Regex::new(pattern) {
                patterns.push(CompiledPattern {
                    id: id.to_string(),
                    name: name.to_string(),
                    regex,
                    severity: Severity::from_str(sev),
                    description: format!("{} detected", name),
                });
            }
        }

        Self {
            patterns,
            entropy_threshold,
        }
    }

    pub fn scan_content(&self, content: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.patterns {
                for mat in pattern.regex.find_iter(line) {
                    findings.push(SecretFinding {
                        line: line_num + 1,
                        column: mat.start(),
                        severity: pattern.severity,
                        rule_id: pattern.id.clone(),
                        message: pattern.description.clone(),
                        context: Self::redact_secret(mat.as_str()),
                    });
                }
            }

            for (pos, potential) in self.extract_potential_secrets(line) {
                let entropy = self.calculate_entropy(potential);
                if entropy >= self.entropy_threshold && potential.len() >= 20 {
                    findings.push(SecretFinding {
                        line: line_num + 1,
                        column: pos,
                        severity: Severity::Medium,
                        rule_id: "SECRET_HIGH_ENTROPY".to_string(),
                        message: format!("High entropy string detected (entropy: {:.2})", entropy),
                        context: Self::redact_secret(potential),
                    });
                }
            }
        }

        findings
    }

    fn extract_potential_secrets<'a>(&self, line: &'a str) -> Vec<(usize, &'a str)> {
        let mut results = Vec::new();

        let quote_regex = Regex::new(r#"["']([^"']{20,})["']"#).unwrap();
        for captures in quote_regex.captures_iter(line) {
            if let Some(m) = captures.get(1) {
                results.push((m.start(), m.as_str()));
            }
        }

        let yaml_regex = Regex::new(r":\s*([a-zA-Z0-9+/=_-]{20,})").unwrap();
        for captures in yaml_regex.captures_iter(line) {
            if let Some(m) = captures.get(1) {
                results.push((m.start(), m.as_str()));
            }
        }

        results
    }

    fn redact_secret(secret: &str) -> String {
        if secret.len() <= 8 {
            return "***REDACTED***".to_string();
        }
        format!("{}***REDACTED***", &secret[..4])
    }

    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq: HashMap<char, usize> = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for &count in freq.values() {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }

        entropy
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SecretFinding {
    pub line: usize,
    pub column: usize,
    pub severity: Severity,
    pub rule_id: String,
    pub message: String,
    pub context: String,
}
