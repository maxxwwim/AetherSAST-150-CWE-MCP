use crate::sca::osv::{OsvQueryResponse, OsvVulnerability};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Cache record stored in `.aether/cache/osv/<hash>.json`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvCacheEntry {
    pub cache_version: u32,
    pub key: String,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub queried_at: String,
    pub vulns: Vec<OsvVulnerability>,
}

/// Computes the deterministic BLAKE3 64-char hex hash key for an ecosystem dependency
pub fn derive_osv_cache_key(ecosystem: &str, package: &str, version: &str) -> String {
    let raw_key = format!("{}:{}:{}", ecosystem, package, version);
    blake3::hash(raw_key.as_bytes()).to_hex().to_string()
}

/// Local persistent disk cache for OSV.dev advisories
#[derive(Debug, Clone)]
pub struct OsvCache {
    pub cache_dir: PathBuf,
}

impl OsvCache {
    /// Creates a new cache manager targeting the specified directory
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Self {
        Self {
            cache_dir: cache_dir.as_ref().to_path_buf(),
        }
    }

    /// Default cache directory for a given project root (`<project_root>/.aether/cache/osv`)
    pub fn default_for_project<P: AsRef<Path>>(project_root: P) -> Self {
        Self::new(project_root.as_ref().join(".aether").join("cache").join("osv"))
    }

    /// Derives the cache file path for the given dependency
    pub fn cache_file_path(&self, ecosystem: &str, package: &str, version: &str) -> PathBuf {
        let key_hash = derive_osv_cache_key(ecosystem, package, version);
        self.cache_dir.join(format!("{}.json", key_hash))
    }

    /// Retrieves cached vulnerabilities if present on disk
    pub fn get(&self, ecosystem: &str, package: &str, version: &str) -> Option<Vec<OsvVulnerability>> {
        let cache_file = self.cache_file_path(ecosystem, package, version);
        if !cache_file.exists() {
            return None;
        }

        let content = fs::read_to_string(&cache_file).ok()?;

        // 1. Try parsing as OsvCacheEntry
        if let Ok(entry) = serde_json::from_str::<OsvCacheEntry>(&content) {
            return Some(entry.vulns);
        }

        // 2. Try parsing as OsvQueryResponse ({"vulns": [...]})
        if let Ok(resp) = serde_json::from_str::<OsvQueryResponse>(&content) {
            return Some(resp.vulns);
        }

        // 3. Try parsing as raw Vec<OsvVulnerability>
        if let Ok(vulns) = serde_json::from_str::<Vec<OsvVulnerability>>(&content) {
            return Some(vulns);
        }

        None
    }

    /// Persists vulnerability records into the local disk cache
    pub fn put(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        vulns: &[OsvVulnerability],
    ) -> std::io::Result<()> {
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir)?;
        }

        let cache_file = self.cache_file_path(ecosystem, package, version);
        let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => format!("{}.{}", d.as_secs(), d.subsec_millis()),
            Err(_) => "0".to_string(),
        };

        let entry = OsvCacheEntry {
            cache_version: 1,
            key: format!("{}:{}:{}", ecosystem, package, version),
            ecosystem: ecosystem.to_string(),
            package: package.to_string(),
            version: version.to_string(),
            queried_at: timestamp,
            vulns: vulns.to_vec(),
        };

        let json = serde_json::to_string_pretty(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        fs::write(&cache_file, json)
    }
}
