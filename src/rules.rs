use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::errors::{AnsibleSecError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub enabled: bool,
    pub rule_type: RuleType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleType {
    DisallowModule {
        modules: Vec<String>,
    },
    RequireVault {
        exceptions: Vec<String>,
    },
    DisallowHardcodedCredentials,
    RequireNoLogForSensitive,
    CheckPermissions {
        max_permissions: String,
    },
    CustomYamlPath {
        path: String,
        expected_value: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesFile {
    pub rules: Vec<Rule>,
}

pub struct RulesEngine {
    rules: Vec<Rule>,
}

impl Default for RulesEngine {
    fn default() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }
}

impl RulesEngine {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let rules_file: RulesFile = serde_yaml::from_str(&content)?;

        Ok(Self {
            rules: rules_file.rules,
        })
    }

    pub fn validate(&self) -> Result<()> {
        for rule in &self.rules {
            // Validate rule structure
            if rule.id.is_empty() {
                return Err(AnsibleSecError::RuleValidationError(
                    "Rule has empty ID".to_string(),
                ));
            }
            if rule.name.is_empty() {
                return Err(AnsibleSecError::RuleValidationError(format!(
                    "Rule {} has empty name",
                    rule.id
                )));
            }

            // Validate severity
            match rule.severity.to_uppercase().as_str() {
                "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" => {}
                _ => {
                    return Err(AnsibleSecError::RuleValidationError(format!(
                        "Rule {} has invalid severity: {}",
                        rule.id, rule.severity
                    )))
                }
            }
        }

        Ok(())
    }

    pub fn list_rules(&self) {
        println!("Available Rules:");
        println!("{:-<80}", "");

        for rule in &self.rules {
            let status = if rule.enabled { "✓" } else { "✗" };
            println!(
                "[{}] {} - {} ({})",
                status, rule.id, rule.name, rule.severity
            );
            println!("    {}", rule.description);
            println!();
        }
    }

    pub fn get_enabled_rules(&self) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.enabled).collect()
    }

    fn default_rules() -> Vec<Rule> {
        vec![
            Rule {
                id: "POLICY_001".to_string(),
                name: "Disallow Risky Modules".to_string(),
                description: "Prevents use of risky modules like shell, command, and raw"
                    .to_string(),
                severity: "HIGH".to_string(),
                enabled: true,
                rule_type: RuleType::DisallowModule {
                    modules: vec![
                        "shell".to_string(),
                        "command".to_string(),
                        "raw".to_string(),
                    ],
                },
            },
            Rule {
                id: "POLICY_002".to_string(),
                name: "Require Ansible Vault".to_string(),
                description: "Ensures sensitive variables are encrypted with Ansible Vault"
                    .to_string(),
                severity: "CRITICAL".to_string(),
                enabled: true,
                rule_type: RuleType::RequireVault {
                    exceptions: vec!["ansible_connection".to_string()],
                },
            },
            Rule {
                id: "POLICY_003".to_string(),
                name: "Disallow Hardcoded Credentials".to_string(),
                description: "Prevents hardcoded passwords and credentials in playbooks"
                    .to_string(),
                severity: "CRITICAL".to_string(),
                enabled: true,
                rule_type: RuleType::DisallowHardcodedCredentials,
            },
            Rule {
                id: "POLICY_004".to_string(),
                name: "Require no_log for Sensitive Tasks".to_string(),
                description: "Ensures sensitive tasks have no_log: true".to_string(),
                severity: "HIGH".to_string(),
                enabled: true,
                rule_type: RuleType::RequireNoLogForSensitive,
            },
            Rule {
                id: "POLICY_005".to_string(),
                name: "Check File Permissions".to_string(),
                description: "Validates file/directory permissions are not overly permissive"
                    .to_string(),
                severity: "MEDIUM".to_string(),
                enabled: true,
                rule_type: RuleType::CheckPermissions {
                    max_permissions: "0644".to_string(),
                },
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rules_valid() {
        let engine = RulesEngine::default();
        assert!(engine.validate().is_ok());
    }

    #[test]
    fn test_get_enabled_rules() {
        let engine = RulesEngine::default();
        let enabled = engine.get_enabled_rules();
        assert!(!enabled.is_empty());
    }
}
