use crate::config::Config;
use crate::scanner::Finding;
use crate::errors::Result;

pub struct Linter {
    config: Config,
}

impl Linter {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
    
    pub fn lint(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Parse YAML structure
        if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) {
            findings.extend(self.check_yaml_structure(&yaml, content)?);
            findings.extend(self.check_best_practices(&yaml, content)?);
            findings.extend(self.check_naming_conventions(&yaml, content)?);
        }
        
        // General linting checks
        findings.extend(self.check_line_length(content)?);
        findings.extend(self.check_trailing_whitespace(content)?);
        findings.extend(self.check_yaml_syntax(content)?);
        
        Ok(findings)
    }
    
    fn check_yaml_structure(&self, yaml: &serde_yaml::Value, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for proper playbook structure
        if yaml.is_sequence() {
            // This is a list of plays
            if let Some(plays) = yaml.as_sequence() {
                for (idx, play) in plays.iter().enumerate() {
                    if let Some(obj) = play.as_mapping() {
                        // Check for required fields
                        if !obj.contains_key("hosts") {
                            findings.push(Finding {
                                line: self.find_line_number(content, "name", idx),
                                column: 0,
                                severity: "MEDIUM".to_string(),
                                rule_id: "LINT_001".to_string(),
                                message: "Play should define 'hosts'".to_string(),
                                context: Some("Every play should specify which hosts to run on".to_string()),
                            });
                        }
                        
                        if !obj.contains_key("name") {
                            findings.push(Finding {
                                line: 1,
                                column: 0,
                                severity: "LOW".to_string(),
                                rule_id: "LINT_002".to_string(),
                                message: "Play should have a descriptive 'name'".to_string(),
                                context: Some("Named plays improve readability and debugging".to_string()),
                            });
                        }
                    }
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_best_practices(&self, yaml: &serde_yaml::Value, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for become usage
        if let Some(tasks) = yaml.get("tasks").and_then(|t| t.as_sequence()) {
            for (idx, task) in tasks.iter().enumerate() {
                if let Some(obj) = task.as_mapping() {
                    // Check for package managers without become
                    let package_modules = ["apt", "yum", "dnf", "package", "pip"];
                    let has_package_module = obj.keys().any(|k| {
                        if let Some(key_str) = k.as_str() {
                            package_modules.contains(&key_str)
                        } else {
                            false
                        }
                    });
                    
                    if has_package_module {
                        let has_become = obj.get("become")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        
                        if !has_become {
                            findings.push(Finding {
                                line: self.find_line_number(content, "name", idx),
                                column: 0,
                                severity: "MEDIUM".to_string(),
                                rule_id: "LINT_003".to_string(),
                                message: "Package management tasks should use 'become: true'".to_string(),
                                context: Some("Package installation typically requires elevated privileges".to_string()),
                            });
                        }
                    }
                    
                    // Check for changed_when/failed_when on command/shell
                    let command_modules = ["command", "shell"];
                    let has_command_module = obj.keys().any(|k| {
                        if let Some(key_str) = k.as_str() {
                            command_modules.contains(&key_str)
                        } else {
                            false
                        }
                    });
                    
                    if has_command_module {
                        let has_changed_when = obj.contains_key("changed_when");
                        
                        if !has_changed_when {
                            findings.push(Finding {
                                line: self.find_line_number(content, "name", idx),
                                column: 0,
                                severity: "LOW".to_string(),
                                rule_id: "LINT_004".to_string(),
                                message: "Command tasks should define 'changed_when'".to_string(),
                                context: Some("Improves idempotency tracking".to_string()),
                            });
                        }
                    }
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_naming_conventions(&self, yaml: &serde_yaml::Value, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        if let Some(tasks) = yaml.get("tasks").and_then(|t| t.as_sequence()) {
            for (idx, task) in tasks.iter().enumerate() {
                if let Some(obj) = task.as_mapping() {
                    if let Some(name) = obj.get("name").and_then(|n| n.as_str()) {
                        // Check naming conventions
                        if name.len() < 5 {
                            findings.push(Finding {
                                line: self.find_line_number(content, "name", idx),
                                column: 0,
                                severity: "LOW".to_string(),
                                rule_id: "LINT_005".to_string(),
                                message: "Task name is too short".to_string(),
                                context: Some("Use descriptive task names (at least 5 characters)".to_string()),
                            });
                        }
                        
                        // Check if name starts with uppercase
                        if !name.chars().next().unwrap_or(' ').is_uppercase() {
                            findings.push(Finding {
                                line: self.find_line_number(content, "name", idx),
                                column: 0,
                                severity: "INFO".to_string(),
                                rule_id: "LINT_006".to_string(),
                                message: "Task name should start with uppercase letter".to_string(),
                                context: Some("Follow consistent naming conventions".to_string()),
                            });
                        }
                    }
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_line_length(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        const MAX_LINE_LENGTH: usize = 160;
        
        for (line_num, line) in content.lines().enumerate() {
            if line.len() > MAX_LINE_LENGTH {
                findings.push(Finding {
                    line: line_num + 1,
                    column: MAX_LINE_LENGTH,
                    severity: "INFO".to_string(),
                    rule_id: "LINT_007".to_string(),
                    message: format!("Line too long ({} > {})", line.len(), MAX_LINE_LENGTH),
                    context: Some("Consider breaking long lines for readability".to_string()),
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_trailing_whitespace(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            if line.ends_with(' ') || line.ends_with('\t') {
                findings.push(Finding {
                    line: line_num + 1,
                    column: line.trim_end().len(),
                    severity: "INFO".to_string(),
                    rule_id: "LINT_008".to_string(),
                    message: "Trailing whitespace".to_string(),
                    context: Some("Remove trailing whitespace".to_string()),
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_yaml_syntax(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for common YAML issues
        for (line_num, line) in content.lines().enumerate() {
            // Check for tabs (YAML doesn't allow tabs for indentation)
            if line.contains('\t') {
                findings.push(Finding {
                    line: line_num + 1,
                    column: line.find('\t').unwrap_or(0),
                    severity: "HIGH".to_string(),
                    rule_id: "LINT_009".to_string(),
                    message: "YAML does not allow tabs for indentation".to_string(),
                    context: Some("Use spaces instead of tabs".to_string()),
                });
            }
        }
        
        Ok(findings)
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
        1
    }
}
