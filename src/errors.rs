use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnsibleSecError {
    #[error("Failed to parse YAML file: {0}")]
    YamlParseError(#[from] serde_yaml::Error),
    
    #[error("Failed to parse JSON: {0}")]
    JsonParseError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Rule validation error: {0}")]
    RuleValidationError(String),
    
    #[error("Secrets detected: {0} violations found")]
    SecretsDetected(usize),
    
    #[error("Policy violations: {0} violations found")]
    PolicyViolations(usize),
    
    #[error("Linting errors: {0} errors found")]
    LintingErrors(usize),
    
    #[error("File not found: {0}")]
    FileNotFound(String),
    
    #[error("Invalid rule format: {0}")]
    InvalidRuleFormat(String),
    
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Cache error: {0}")]
    CacheError(String),
}

pub type Result<T> = std::result::Result<T, AnsibleSecError>;
