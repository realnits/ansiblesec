use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::errors::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub secrets: SecretsConfig,
    pub policies: PoliciesConfig,
    pub linting: LintingConfig,
    pub general: GeneralConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    pub enabled: bool,
    pub entropy_threshold: f64,
    pub rules_file: Option<String>,
    pub min_entropy_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoliciesConfig {
    pub enabled: bool,
    pub rules_file: Option<String>,
    pub disallow_modules: Vec<String>,
    pub require_vault: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintingConfig {
    pub enabled: bool,
    pub max_line_length: usize,
    pub require_name: bool,
    pub check_permissions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub max_depth: usize,
    pub max_file_size: usize,
    pub parallel_jobs: usize,
    pub cache_enabled: bool,
    pub cache_dir: Option<PathBuf>,
    pub exclude_paths: Vec<String>,
    pub exclude_patterns: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            secrets: SecretsConfig {
                enabled: true,
                entropy_threshold: 4.5,
                rules_file: Some("rules/secrets.yml".to_string()),
                min_entropy_length: 20,
            },
            policies: PoliciesConfig {
                enabled: true,
                rules_file: Some("rules/policies.yml".to_string()),
                disallow_modules: vec![
                    "shell".to_string(),
                    "command".to_string(),
                    "raw".to_string(),
                ],
                require_vault: true,
            },
            linting: LintingConfig {
                enabled: true,
                max_line_length: 120,
                require_name: true,
                check_permissions: true,
            },
            general: GeneralConfig {
                max_depth: 10,
                max_file_size: 10 * 1024 * 1024, // 10MB
                parallel_jobs: 0,                // 0 = auto
                cache_enabled: true,
                cache_dir: Some(PathBuf::from(".ansiblesec_cache")),
                exclude_paths: vec![
                    ".git".to_string(),
                    "venv".to_string(),
                    "node_modules".to_string(),
                    "vendor".to_string(),
                ],
                exclude_patterns: vec!["*.retry".to_string(), "*.swp".to_string()],
            },
        }
    }
}

impl Config {
    pub fn load(config_file: Option<PathBuf>) -> Result<Self> {
        let mut config = Self::default();

        // Try to load from specified config file or default
        if let Some(ref path) = config_file {
            let content = fs::read_to_string(path)?;
            config = serde_yaml::from_str(&content)?;
        } else if let Ok(content) = fs::read_to_string(".ansiblesec.yml") {
            config = serde_yaml::from_str(&content)?;
        }

        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self)?;
        fs::write(path, yaml)?;
        Ok(())
    }
}
