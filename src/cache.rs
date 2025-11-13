use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::scanner::FileFinding;

pub struct Cache {
    cache_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    file_hash: String,
    findings: FileFinding,
    timestamp: i64,
}

impl Cache {
    pub fn new(cache_dir: Option<PathBuf>) -> Self {
        let dir = cache_dir.unwrap_or_else(|| {
            let mut path = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push("ansiblesec");
            path
        });

        // Create cache directory if it doesn't exist
        fs::create_dir_all(&dir).ok();

        Self { cache_dir: dir }
    }

    pub fn get(&self, file_path: &Path) -> crate::errors::Result<FileFinding> {
        let hash = self.hash_file(file_path)?;
        let cache_file = self.cache_file_path(file_path);

        if !cache_file.exists() {
            return Err(crate::errors::AnsibleSecError::CacheError(
                "Cache miss".to_string(),
            ));
        }

        let content = fs::read_to_string(&cache_file)?;
        let entry: CacheEntry = serde_json::from_str(&content)?;

        // Validate hash
        if entry.file_hash != hash {
            return Err(crate::errors::AnsibleSecError::CacheError(
                "Hash mismatch".to_string(),
            ));
        }

        Ok(entry.findings)
    }

    pub fn set(&self, file_path: &Path, findings: &FileFinding) -> crate::errors::Result<()> {
        let hash = self.hash_file(file_path)?;
        let cache_file = self.cache_file_path(file_path);

        let entry = CacheEntry {
            file_hash: hash,
            findings: findings.clone(),
            timestamp: chrono::Utc::now().timestamp(),
        };

        let json = serde_json::to_string(&entry)?;

        // Create parent directory if needed
        if let Some(parent) = cache_file.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&cache_file, json)?;
        Ok(())
    }

    pub fn clear(&self) -> crate::errors::Result<()> {
        if self.cache_dir.exists() {
            fs::remove_dir_all(&self.cache_dir)?;
            fs::create_dir_all(&self.cache_dir)?;
        }
        Ok(())
    }

    fn hash_file(&self, file_path: &Path) -> crate::errors::Result<String> {
        let content = fs::read(file_path)?;
        let mut hasher = Hasher::new();
        hasher.update(&content);
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn cache_file_path(&self, file_path: &Path) -> PathBuf {
        let mut hasher = Hasher::new();
        hasher.update(file_path.to_string_lossy().as_bytes());
        let hash = hasher.finalize().to_hex().to_string();

        self.cache_dir.join(format!("{}.json", hash))
    }
}
