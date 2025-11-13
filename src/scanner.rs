use log::{debug, info, warn};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::cache::Cache;
use crate::config::Config;
use crate::errors::Result;
use crate::linter::Linter;
use crate::policy::PolicyEngine;
use crate::secrets::SecretDetector;

pub struct Scanner {
    config: Config,
    secret_detector: SecretDetector,
    policy_engine: PolicyEngine,
    linter: Linter,
    cache: Option<Cache>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanFindings {
    pub files_scanned: usize,
    pub secrets: Vec<FileFinding>,
    pub policy_violations: Vec<FileFinding>,
    pub lint_issues: Vec<FileFinding>,
    pub summary: Summary,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileFinding {
    pub file_path: PathBuf,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub line: usize,
    pub column: usize,
    pub severity: String,
    pub rule_id: String,
    pub message: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl Scanner {
    pub fn new(config: Config, threads: usize, enable_cache: bool) -> Self {
        // Load secrets detector from file or use defaults
        let secret_detector = if let Some(ref rules_file) = config.secrets.rules_file {
            SecretDetector::from_file(rules_file, config.secrets.entropy_threshold).unwrap_or_else(
                |e| {
                    eprintln!(
                        "Warning: Failed to load secrets rules from {}: {}",
                        rules_file, e
                    );
                    eprintln!("Falling back to default rules");
                    SecretDetector::with_defaults(config.secrets.entropy_threshold)
                },
            )
        } else {
            SecretDetector::with_defaults(config.secrets.entropy_threshold)
        };

        let policy_engine = PolicyEngine::new(config.clone());
        let linter = Linter::new(config.clone());

        let cache = if enable_cache {
            Some(Cache::new(config.general.cache_dir.clone()))
        } else {
            None
        };

        if threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build_global()
                .ok();
        }

        Self {
            config,
            secret_detector,
            policy_engine,
            linter,
            cache,
        }
    }

    pub fn scan(&self, path: &Path) -> Result<ScanFindings> {
        let files = self.collect_files(path)?;

        // Print scan start message
        eprintln!("🔍 Starting security scan...");
        eprintln!(
            "📂 Found {} Ansible file{} to scan",
            files.len(),
            if files.len() == 1 { "" } else { "s" }
        );

        info!("Scanning {} files", files.len());

        let results: Vec<_> = files
            .par_iter()
            .enumerate()
            .filter_map(|(idx, file)| {
                // Progress indicator
                if files.len() > 1 {
                    let progress = (idx + 1) as f32 / files.len() as f32 * 100.0;
                    eprint!(
                        "\r⏳ Progress: [{:3.0}%] Scanning file {}/{}...",
                        progress,
                        idx + 1,
                        files.len()
                    );
                }

                if let Some(ref cache) = self.cache {
                    if let Ok(cached) = cache.get(file) {
                        debug!("Using cached results for {:?}", file);
                        return Some(cached);
                    }
                }

                match self.scan_file(file) {
                    Ok(finding) => {
                        if let Some(ref cache) = self.cache {
                            cache.set(file, &finding).ok();
                        }
                        Some(finding)
                    }
                    Err(e) => {
                        warn!("Error scanning {:?}: {}", file, e);
                        None
                    }
                }
            })
            .collect();

        if files.len() > 1 {
            eprintln!(
                "\r✅ Scan complete! Analyzed {} files.                    ",
                files.len()
            );
        } else {
            eprintln!("✅ Scan complete!");
        }
        eprintln!();

        Ok(self.aggregate_findings(results, files.len()))
    }

    pub fn lint(&self, path: &Path) -> Result<ScanFindings> {
        let files = self.collect_files(path)?;
        info!("Linting {} files", files.len());

        let results: Vec<_> = files
            .par_iter()
            .filter_map(|file| match self.lint_file(file) {
                Ok(finding) => Some(finding),
                Err(e) => {
                    warn!("Error linting {:?}: {}", file, e);
                    None
                }
            })
            .collect();

        Ok(self.aggregate_findings(results, files.len()))
    }

    fn scan_file(&self, file_path: &Path) -> Result<FileFinding> {
        let content = fs::read_to_string(file_path)?;
        let mut findings = Vec::new();

        // Secrets detection
        if self.config.secrets.enabled {
            let secret_findings = self.secret_detector.scan_content(&content);
            for sf in secret_findings {
                findings.push(Finding {
                    line: sf.line,
                    column: sf.column,
                    severity: sf.severity.as_str().to_string(),
                    rule_id: sf.rule_id,
                    message: sf.message,
                    context: Some(sf.context),
                });
            }
        }

        // Policy enforcement
        if self.config.policies.enabled {
            let policy_findings = self.policy_engine.check_policies(file_path, &content)?;
            findings.extend(policy_findings);
        }

        Ok(FileFinding {
            file_path: file_path.to_path_buf(),
            findings,
        })
    }

    fn lint_file(&self, file_path: &Path) -> Result<FileFinding> {
        let content = fs::read_to_string(file_path)?;
        let findings = self.linter.lint(&content)?;

        Ok(FileFinding {
            file_path: file_path.to_path_buf(),
            findings,
        })
    }

    fn collect_files(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        if path.is_file() {
            if self.is_ansible_file(path) {
                files.push(path.to_path_buf());
            }
        } else {
            for entry in WalkDir::new(path)
                .follow_links(true)
                .into_iter()
                .filter_entry(|e| !self.is_excluded(e.path()))
            {
                let entry = entry.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                if entry.file_type().is_file() && self.is_ansible_file(entry.path()) {
                    // Check file size
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.len() <= self.config.general.max_file_size as u64 {
                            files.push(entry.path().to_path_buf());
                        }
                    }
                }
            }
        }

        Ok(files)
    }

    fn is_ansible_file(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy();
            if ext_str == "yml" || ext_str == "yaml" {
                return true;
            }
        }

        // Check for common Ansible file names
        if let Some(name) = path.file_name() {
            let name_str = name.to_string_lossy();
            if name_str.contains("playbook")
                || name_str.contains("tasks")
                || name_str.contains("handlers")
                || name_str == "site.yml"
                || name_str == "main.yml"
            {
                return true;
            }
        }

        false
    }

    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.config
            .general
            .exclude_paths
            .iter()
            .any(|exclude| path_str.contains(exclude))
    }

    fn aggregate_findings(&self, results: Vec<FileFinding>, files_scanned: usize) -> ScanFindings {
        let mut summary = Summary {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };

        let mut secrets = Vec::new();
        let mut policy_violations = Vec::new();
        let mut lint_issues = Vec::new();

        for file_finding in results {
            let has_findings = !file_finding.findings.is_empty();

            for finding in &file_finding.findings {
                match finding.severity.as_str() {
                    "CRITICAL" => summary.critical += 1,
                    "HIGH" => summary.high += 1,
                    "MEDIUM" => summary.medium += 1,
                    "LOW" => summary.low += 1,
                    "INFO" => summary.info += 1,
                    _ => {}
                }
            }

            if has_findings {
                if file_finding
                    .findings
                    .iter()
                    .any(|f| f.rule_id.starts_with("SECRET"))
                {
                    secrets.push(file_finding.clone());
                }
                if file_finding
                    .findings
                    .iter()
                    .any(|f| f.rule_id.starts_with("POLICY"))
                {
                    policy_violations.push(file_finding.clone());
                }
                if file_finding
                    .findings
                    .iter()
                    .any(|f| f.rule_id.starts_with("LINT"))
                {
                    lint_issues.push(file_finding.clone());
                }
            }
        }

        ScanFindings {
            files_scanned,
            secrets,
            policy_violations,
            lint_issues,
            summary,
        }
    }
}

impl ScanFindings {
    pub fn has_critical(&self) -> bool {
        self.summary.critical > 0
    }

    pub fn has_high(&self) -> bool {
        self.summary.high > 0
    }

    pub fn has_errors(&self) -> bool {
        self.has_critical() || self.has_high()
    }

    pub fn total_findings(&self) -> usize {
        self.summary.critical
            + self.summary.high
            + self.summary.medium
            + self.summary.low
            + self.summary.info
    }
}
