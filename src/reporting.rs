use std::path::Path;
use std::fs;
use colored::Colorize;

use crate::scanner::ScanFindings;
use crate::errors::Result;

pub struct Reporter {
    format: OutputFormat,
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "text" | "txt" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            _ => Err(crate::errors::AnsibleSecError::ConfigError(
                format!("Unknown output format: {}", s)
            )),
        }
    }
}

impl Reporter {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }
    
    pub fn report(&self, findings: &ScanFindings, output_file: Option<&Path>) -> Result<()> {
        let output = match self.format {
            OutputFormat::Text => self.format_text(findings),
            OutputFormat::Json => self.format_json(findings)?,
            OutputFormat::Sarif => self.format_sarif(findings)?,
        };
        
        if let Some(path) = output_file {
            fs::write(path, output)?;
        } else {
            println!("{}", output);
        }
        
        Ok(())
    }
    
    fn format_text(&self, findings: &ScanFindings) -> String {
        let mut output = String::new();
        
        use colored::*;
        
        // Header with box drawing
        output.push_str("\n");
        output.push_str(&format!("╔{}╗\n", "═".repeat(78)));
        output.push_str(&format!("║{:^78}║\n", "🔒 ANSIBLESEC SECURITY SCAN REPORT 🔒".bold().cyan()));
        output.push_str(&format!("╚{}╝\n\n", "═".repeat(78)));
        
        // Scan statistics
        output.push_str(&format!("📊 {}\n", "Scan Statistics:".bold().underline()));
        output.push_str(&format!("   ├─ Files scanned: {}\n", findings.files_scanned.to_string().bold().white()));
        output.push_str(&format!("   ├─ Total findings: {}\n", findings.total_findings().to_string().bold().white()));
        output.push_str(&format!("   └─ Scan date: {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string().dimmed()));
        
        // Severity Summary with visual indicators
        output.push_str(&format!("📈 {}\n", "Severity Distribution:".bold().underline()));
        let total = findings.total_findings() as f32;
        if total > 0.0 {
            output.push_str(&self.format_severity_bar("CRITICAL", findings.summary.critical, total));
            output.push_str(&self.format_severity_bar("HIGH", findings.summary.high, total));
            output.push_str(&self.format_severity_bar("MEDIUM", findings.summary.medium, total));
            output.push_str(&self.format_severity_bar("LOW", findings.summary.low, total));
            output.push_str(&self.format_severity_bar("INFO", findings.summary.info, total));
        } else {
            output.push_str(&format!("   {}\n", "No findings detected!".green()));
        }
        output.push_str("\n");
        
        // Secrets section with enhanced formatting
        if !findings.secrets.is_empty() {
            output.push_str(&format!("╭─{}─╮\n", "─".repeat(76)));
            output.push_str(&format!("│ 🔑 {:^73} │\n", "SECRETS DETECTED".bold().red()));
            output.push_str(&format!("╰─{}─╯\n", "─".repeat(76)));
            
            for (idx, file_finding) in findings.secrets.iter().enumerate() {
                output.push_str(&format!("\n📄 {} {}\n", 
                    format!("[{}]", idx + 1).dimmed(),
                    file_finding.file_path.display().to_string().bold().white()
                ));
                
                let secret_findings: Vec<_> = file_finding.findings.iter()
                    .filter(|f| f.rule_id.starts_with("SECRET"))
                    .collect();
                
                for (finding_idx, finding) in secret_findings.iter().enumerate() {
                    let is_last = finding_idx == secret_findings.len() - 1;
                    let prefix = if is_last { "└─" } else { "├─" };
                    
                    output.push_str(&format!(
                        "   {} Line {} Col {} │ {} │ {}\n",
                        prefix,
                        format!("{:>4}", finding.line).cyan(),
                        format!("{:>3}", finding.column).cyan(),
                        self.colorize_severity_box(&finding.severity),
                        finding.message.white()
                    ));
                    
                    if let Some(ref context) = finding.context {
                        let context_prefix = if is_last { "   " } else { "│  " };
                        output.push_str(&format!("   {}    ↳ Rule: {}\n", 
                            context_prefix,
                            finding.rule_id.dimmed()
                        ));
                        output.push_str(&format!("   {}    ↳ Match: {}\n", 
                            context_prefix,
                            context.yellow()
                        ));
                    }
                }
            }
            output.push_str("\n");
        }
        
        // Policy Violations with enhanced formatting
        if !findings.policy_violations.is_empty() {
            output.push_str(&format!("╭─{}─╮\n", "─".repeat(76)));
            output.push_str(&format!("│ ⚠️  {:^73} │\n", "POLICY VIOLATIONS".bold().yellow()));
            output.push_str(&format!("╰─{}─╯\n", "─".repeat(76)));
            
            for (idx, file_finding) in findings.policy_violations.iter().enumerate() {
                output.push_str(&format!("\n📄 {} {}\n", 
                    format!("[{}]", idx + 1).dimmed(),
                    file_finding.file_path.display().to_string().bold().white()
                ));
                
                let policy_findings: Vec<_> = file_finding.findings.iter()
                    .filter(|f| f.rule_id.starts_with("POLICY"))
                    .collect();
                
                for (finding_idx, finding) in policy_findings.iter().enumerate() {
                    let is_last = finding_idx == policy_findings.len() - 1;
                    let prefix = if is_last { "└─" } else { "├─" };
                    
                    output.push_str(&format!(
                        "   {} Line {} Col {} │ {} │ {}\n",
                        prefix,
                        format!("{:>4}", finding.line).cyan(),
                        format!("{:>3}", finding.column).cyan(),
                        self.colorize_severity_box(&finding.severity),
                        finding.message.white()
                    ));
                    
                    let context_prefix = if is_last { "   " } else { "│  " };
                    output.push_str(&format!("   {}    ↳ Rule: {}\n", 
                        context_prefix,
                        finding.rule_id.dimmed()
                    ));
                    
                    if let Some(ref context) = finding.context {
                        output.push_str(&format!("   {}    ↳ Fix: {}\n", 
                            context_prefix,
                            context.bright_blue()
                        ));
                    }
                }
            }
            output.push_str("\n");
        }
        
        // Lint Issues with enhanced formatting
        if !findings.lint_issues.is_empty() {
            output.push_str(&format!("╭─{}─╮\n", "─".repeat(76)));
            output.push_str(&format!("│ 🧹 {:^73} │\n", "LINTING ISSUES".bold().blue()));
            output.push_str(&format!("╰─{}─╯\n", "─".repeat(76)));
            
            for (idx, file_finding) in findings.lint_issues.iter().enumerate() {
                output.push_str(&format!("\n📄 {} {}\n", 
                    format!("[{}]", idx + 1).dimmed(),
                    file_finding.file_path.display().to_string().bold().white()
                ));
                
                let lint_findings: Vec<_> = file_finding.findings.iter()
                    .filter(|f| f.rule_id.starts_with("LINT"))
                    .collect();
                
                for (finding_idx, finding) in lint_findings.iter().enumerate() {
                    let is_last = finding_idx == lint_findings.len() - 1;
                    let prefix = if is_last { "└─" } else { "├─" };
                    
                    output.push_str(&format!(
                        "   {} Line {} │ {} │ {}\n",
                        prefix,
                        format!("{:>4}", finding.line).cyan(),
                        self.colorize_severity_box(&finding.severity),
                        finding.message.white()
                    ));
                }
            }
            output.push_str("\n");
        }
        
        // Final summary with recommendations
        output.push_str(&format!("╔{}╗\n", "═".repeat(78)));
        
        if findings.has_critical() {
            output.push_str(&format!("║ {} {:65} ║\n", 
                "❌".red(),
                "CRITICAL ISSUES FOUND - IMMEDIATE ACTION REQUIRED!".red().bold()
            ));
            output.push_str(&format!("║ {:78} ║\n", ""));
            output.push_str(&format!("║ {} {:<72} ║\n", 
                "💡",
                "Recommendation: Do not deploy until critical issues are resolved.".yellow()
            ));
        } else if findings.has_high() {
            output.push_str(&format!("║ {} {:67} ║\n", 
                "⚠️",
                "HIGH SEVERITY ISSUES FOUND - REVIEW REQUIRED".yellow().bold()
            ));
            output.push_str(&format!("║ {:78} ║\n", ""));
            output.push_str(&format!("║ {} {:<72} ║\n", 
                "💡",
                "Recommendation: Address high severity issues before deployment.".yellow()
            ));
        } else if findings.total_findings() > 0 {
            output.push_str(&format!("║ {} {:69} ║\n", 
                "✓",
                "NO CRITICAL ISSUES - SOME FINDINGS REQUIRE ATTENTION".green()
            ));
            output.push_str(&format!("║ {:78} ║\n", ""));
            output.push_str(&format!("║ {} {:<72} ║\n", 
                "💡",
                "Recommendation: Review and address remaining findings.".cyan()
            ));
        } else {
            output.push_str(&format!("║ {} {:66} ║\n", 
                "✨",
                "SCAN COMPLETE - NO SECURITY ISSUES DETECTED!".green().bold()
            ));
            output.push_str(&format!("║ {:78} ║\n", ""));
            output.push_str(&format!("║ {} {:<72} ║\n", 
                "🎉",
                "Great job! Your playbooks follow security best practices.".green()
            ));
        }
        
        output.push_str(&format!("╚{}╝\n\n", "═".repeat(78)));
        
        output
    }
    
    fn format_severity_bar(&self, severity: &str, count: usize, total: f32) -> String {
        let percentage = (count as f32 / total * 100.0) as usize;
        let bar_width = 40;
        let filled = (percentage as f32 / 100.0 * bar_width as f32) as usize;
        let empty = bar_width - filled;
        
        let bar = format!("{}{}",
            "█".repeat(filled),
            "░".repeat(empty)
        );
        
        let colored_bar = match severity {
            "CRITICAL" => bar.red(),
            "HIGH" => bar.bright_red(),
            "MEDIUM" => bar.yellow(),
            "LOW" => bar.blue(),
            _ => bar.white(),
        };
        
        format!("   ├─ {:8} {} │ {} │ {:>3}% ({} finding{})\n",
            self.colorize_severity(severity),
            colored_bar,
            format!("{:>3}", count).bold(),
            percentage,
            count,
            if count == 1 { "" } else { "s" }
        )
    }
    
    fn colorize_severity_box(&self, severity: &str) -> colored::ColoredString {
        match severity {
            "CRITICAL" => format!(" {} ", severity).on_red().white().bold(),
            "HIGH" => format!(" {} ", severity).on_bright_red().white().bold(),
            "MEDIUM" => format!(" {} ", severity).on_yellow().black().bold(),
            "LOW" => format!(" {} ", severity).on_blue().white().bold(),
            _ => format!(" {} ", severity).on_white().black().bold(),
        }
    }
    
    fn format_json(&self, findings: &ScanFindings) -> Result<String> {
        let json = serde_json::to_string_pretty(findings)?;
        Ok(json)
    }
    
    fn format_sarif(&self, findings: &ScanFindings) -> Result<String> {
        // SARIF format for integration with GitHub Code Scanning and other tools
        let mut runs = Vec::new();
        
        let mut results = Vec::new();
        
        // Convert findings to SARIF results
        for file_finding in findings.secrets.iter()
            .chain(findings.policy_violations.iter())
            .chain(findings.lint_issues.iter()) {
            
            for finding in &file_finding.findings {
                results.push(serde_json::json!({
                    "ruleId": finding.rule_id,
                    "level": self.severity_to_sarif_level(&finding.severity),
                    "message": {
                        "text": finding.message
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_finding.file_path.to_string_lossy()
                            },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column
                            }
                        }
                    }]
                }));
            }
        }
        
        runs.push(serde_json::json!({
            "tool": {
                "driver": {
                    "name": "ansiblesec",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/yourusername/ansiblesec"
                }
            },
            "results": results
        }));
        
        let sarif = serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": runs
        });
        
        Ok(serde_json::to_string_pretty(&sarif)?)
    }
    
    fn colorize_severity(&self, severity: &str) -> colored::ColoredString {
        use colored::*;
        match severity {
            "CRITICAL" => severity.red().bold(),
            "HIGH" => severity.red(),
            "MEDIUM" => severity.yellow(),
            "LOW" => severity.blue(),
            "INFO" => severity.cyan(),
            _ => severity.normal(),
        }
    }
    
    fn severity_text(&self, severity: &str, count: usize) -> colored::ColoredString {
        use colored::*;
        let text = format!("{} {}", count, severity);
        if count == 0 {
            text.dimmed()
        } else {
            match severity {
                "CRITICAL" => text.red().bold(),
                "HIGH" => text.red(),
                "MEDIUM" => text.yellow(),
                "LOW" => text.blue(),
                "INFO" => text.cyan(),
                _ => text.normal(),
            }
        }
    }
    
    fn severity_to_sarif_level(&self, severity: &str) -> &str {
        match severity {
            "CRITICAL" | "HIGH" => "error",
            "MEDIUM" => "warning",
            "LOW" | "INFO" => "note",
            _ => "none",
        }
    }
}
