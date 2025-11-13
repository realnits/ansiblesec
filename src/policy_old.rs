use std::path::Path;
use std::fs;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use crate::config::Config;
use crate::scanner::Finding;
use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub check_type: String,
    pub parameters: serde_yaml::Value,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRulesFile {
    pub version: String,
    pub rules: Vec<PolicyRule>,
}

pub struct PolicyEngine {
    config: Config,
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    pub fn from_file(config: Config, rules_path: &Path) -> Result<Self> {
        let content = fs::read_to_string(rules_path)?;
        let rules_file: PolicyRulesFile = serde_yaml::from_str(&content)?;
        
        Ok(Self {
            config,
            rules: rules_file.rules.into_iter().filter(|r| r.enabled).collect(),
        })
    }
    
    pub fn new(config: Config) -> Self {
    
    pub fn check_policies(&self, _file_path: &Path, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Parse YAML
        let yaml: Value = match serde_yaml::from_str(content) {
            Ok(v) => v,
            Err(_) => return Ok(findings), // Skip non-YAML files
        };
        
        let enabled_rules = self.rules_engine.get_enabled_rules();
        
        for rule in enabled_rules {
            findings.extend(self.check_rule(rule, &yaml, content)?);
        }
        
        Ok(findings)
    }
    
    fn check_rule(&self, rule: &Rule, yaml: &Value, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        match &rule.rule_type {
            RuleType::DisallowModule { modules } => {
                findings.extend(self.check_disallow_module(rule, yaml, modules, content));
            }
            RuleType::RequireVault { exceptions } => {
                findings.extend(self.check_require_vault(rule, yaml, exceptions, content));
            }
            RuleType::DisallowHardcodedCredentials => {
                findings.extend(self.check_hardcoded_credentials(rule, yaml, content));
            }
            RuleType::RequireNoLogForSensitive => {
                findings.extend(self.check_no_log(rule, yaml, content));
            }
            RuleType::CheckPermissions { max_permissions } => {
                findings.extend(self.check_permissions(rule, yaml, max_permissions, content));
            }
            RuleType::CustomYamlPath { path, expected_value } => {
                findings.extend(self.check_yaml_path(rule, yaml, path, expected_value, content));
            }
        }
        
        Ok(findings)
    }
    
    fn check_disallow_module(&self, rule: &Rule, yaml: &Value, modules: &[String], content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check if this is a playbook with tasks
        if let Some(tasks) = self.extract_tasks(yaml) {
            for (idx, task) in tasks.iter().enumerate() {
                if let Some(obj) = task.as_mapping() {
                    for (key, _value) in obj {
                        if let Some(module_name) = key.as_str() {
                            if modules.iter().any(|m| m == module_name) {
                                let line = self.find_line_number(content, module_name, idx);
                                findings.push(Finding {
                                    line,
                                    column: 0,
                                    severity: rule.severity.clone(),
                                    rule_id: rule.id.clone(),
                                    message: format!("Use of disallowed module: {}", module_name),
                                    context: Some(format!("Module '{}' is restricted for security reasons", module_name)),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        findings
    }
    
    fn check_require_vault(&self, rule: &Rule, yaml: &Value, exceptions: &[String], content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check for variables that look like they should be vaulted
        if let Some(vars) = yaml.get("vars").or_else(|| yaml.get("vars_files")) {
            if let Some(obj) = vars.as_mapping() {
                for (key, value) in obj {
                    if let Some(key_str) = key.as_str() {
                        // Check if this is a sensitive variable
                        if self.is_sensitive_var(key_str) && !exceptions.contains(&key_str.to_string()) {
                            // Check if value is vaulted
                            if let Some(val_str) = value.as_str() {
                                if !val_str.starts_with("$ANSIBLE_VAULT") {
                                    let line = self.find_line_number(content, key_str, 0);
                                    findings.push(Finding {
                                        line,
                                        column: 0,
                                        severity: rule.severity.clone(),
                                        rule_id: rule.id.clone(),
                                        message: format!("Sensitive variable '{}' should be encrypted with Ansible Vault", key_str),
                                        context: Some("Use ansible-vault to encrypt sensitive values".to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        findings
    }
    
    fn check_hardcoded_credentials(&self, rule: &Rule, _yaml: &Value, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Look for patterns like password: "plaintext"
        let sensitive_keywords = ["password", "passwd", "secret", "api_key", "token", "credential"];
        
        for (line_num, line) in content.lines().enumerate() {
            for keyword in &sensitive_keywords {
                if line.to_lowercase().contains(keyword) && 
                   !line.contains("$ANSIBLE_VAULT") &&
                   !line.contains("{{ ") && // Allow Jinja2 variables
                   !line.trim().starts_with('#') {
                    
                    // Check if it looks like a key-value pair with a non-variable value
                    if line.contains(':') {
                        let parts: Vec<&str> = line.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            let value = parts[1].trim();
                            if !value.is_empty() && 
                               !value.starts_with("{{") && 
                               !value.starts_with("\"{{") &&
                               value.len() > 3 {
                                findings.push(Finding {
                                    line: line_num + 1,
                                    column: 0,
                                    severity: rule.severity.clone(),
                                    rule_id: rule.id.clone(),
                                    message: format!("Potential hardcoded credential detected for '{}'", keyword),
                                    context: Some("Use Ansible Vault or variables for sensitive data".to_string()),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        findings
    }
    
    fn check_no_log(&self, rule: &Rule, yaml: &Value, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if let Some(tasks) = self.extract_tasks(yaml) {
            for (idx, task) in tasks.iter().enumerate() {
                if let Some(obj) = task.as_mapping() {
                    // Check if task involves sensitive modules
                    let has_sensitive_module = obj.keys().any(|k| {
                        if let Some(key_str) = k.as_str() {
                            self.is_sensitive_module(key_str)
                        } else {
                            false
                        }
                    });
                    
                    if has_sensitive_module {
                        // Check for no_log
                        let has_no_log = obj.get("no_log")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        
                        if !has_no_log {
                            let line = self.find_line_number(content, "name", idx);
                            findings.push(Finding {
                                line,
                                column: 0,
                                severity: rule.severity.clone(),
                                rule_id: rule.id.clone(),
                                message: "Sensitive task should have 'no_log: true'".to_string(),
                                context: Some("Prevents sensitive data from being logged".to_string()),
                            });
                        }
                    }
                }
            }
        }
        
        findings
    }
    
    fn check_permissions(&self, rule: &Rule, yaml: &Value, max_permissions: &str, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if let Some(tasks) = self.extract_tasks(yaml) {
            for (idx, task) in tasks.iter().enumerate() {
                if let Some(obj) = task.as_mapping() {
                    // Check file/copy/template modules
                    for module in &["file", "copy", "template"] {
                        if let Some(module_params) = obj.get(*module) {
                            if let Some(params_obj) = module_params.as_mapping() {
                                if let Some(mode) = params_obj.get("mode") {
                                    if let Some(mode_str) = mode.as_str() {
                                        if self.is_permission_too_open(mode_str, max_permissions) {
                                            let line = self.find_line_number(content, "mode", idx);
                                            findings.push(Finding {
                                                line,
                                                column: 0,
                                                severity: rule.severity.clone(),
                                                rule_id: rule.id.clone(),
                                                message: format!("File permissions '{}' are too permissive", mode_str),
                                                context: Some(format!("Consider using {} or more restrictive", max_permissions)),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        findings
    }
    
    fn check_yaml_path(&self, rule: &Rule, yaml: &Value, path: &str, expected_value: &Option<String>, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Simple YAML path traversal
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = yaml;
        
        for part in &parts {
            if let Some(next) = current.get(part) {
                current = next;
            } else {
                return findings; // Path doesn't exist
            }
        }
        
        // If we have an expected value, check it
        if let Some(expected) = expected_value {
            if let Some(actual) = current.as_str() {
                if actual != expected {
                    let line = self.find_line_number(content, parts.last().unwrap(), 0);
                    findings.push(Finding {
                        line,
                        column: 0,
                        severity: rule.severity.clone(),
                        rule_id: rule.id.clone(),
                        message: format!("Value at '{}' should be '{}'", path, expected),
                        context: Some(format!("Found: '{}'", actual)),
                    });
                }
            }
        }
        
        findings
    }
    
    fn extract_tasks<'a>(&self, yaml: &'a Value) -> Option<&'a Vec<Value>> {
        // Try different locations for tasks
        yaml.get("tasks")
            .or_else(|| yaml.get("handlers"))
            .or_else(|| yaml.get("pre_tasks"))
            .or_else(|| yaml.get("post_tasks"))
            .and_then(|v| v.as_sequence())
    }
    
    fn is_sensitive_var(&self, var_name: &str) -> bool {
        let lower = var_name.to_lowercase();
        lower.contains("password") || 
        lower.contains("secret") || 
        lower.contains("token") || 
        lower.contains("api_key") ||
        lower.contains("private_key")
    }
    
    fn is_sensitive_module(&self, module_name: &str) -> bool {
        matches!(module_name, "user" | "mysql_user" | "postgresql_user" | "uri" | "get_url")
    }
    
    fn is_permission_too_open(&self, mode: &str, max_mode: &str) -> bool {
        // Simple octal comparison
        let mode_clean = mode.trim_start_matches("0o").trim_start_matches('0');
        let max_clean = max_mode.trim_start_matches("0o").trim_start_matches('0');
        
        if let (Ok(mode_val), Ok(max_val)) = (
            u32::from_str_radix(mode_clean, 8),
            u32::from_str_radix(max_clean, 8)
        ) {
            mode_val > max_val
        } else {
            false
        }
    }
    
    fn find_line_number(&self, content: &str, search_term: &str, occurrence: usize) -> usize {
        let mut count = 0;
        for (line_num, line) in content.lines().enumerate() {
            if line.contains(search_term) {
                if count == occurrence {
                    return line_num + 1;
                }
                count += 1;
            }
        }
        1 // Default to line 1 if not found
    }
}
