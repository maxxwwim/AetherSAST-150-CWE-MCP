//! Embedded Semgrep Community Rule Bundle (OWASP Top 10 & CWE Top 25)
//! Compiles canonical Semgrep OSS rules into the binary for 100% offline air-gapped readiness.

use crate::plugin::PluginManifest;
use crate::semgrep_importer::SemgrepImporter;
use std::fs;
use std::path::{Path, PathBuf};

pub const EMBEDDED_COMMUNITY_YAML: &str = include_str!("../rules/community_owasp_cwe.yaml");
pub const DEFAULT_COMMUNITY_BUNDLE_NAME: &str = "community";

pub struct CommunityBundle;

impl CommunityBundle {
    /// Returns the raw embedded Semgrep YAML string.
    pub fn raw_yaml() -> &'static str {
        EMBEDDED_COMMUNITY_YAML
    }

    /// Converts the embedded YAML into a ready-to-run PluginManifest.
    pub fn load_embedded_manifest() -> Result<PluginManifest, Box<dyn std::error::Error>> {
        let rule_file = SemgrepImporter::parse_yaml(EMBEDDED_COMMUNITY_YAML)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let manifest = SemgrepImporter::to_plugin_manifest(&rule_file, DEFAULT_COMMUNITY_BUNDLE_NAME)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(manifest)
    }

    /// Safely unpacks the embedded bundle to disk at `<target_dir>/community/plugin.yaml`
    /// (or directly in `<target_dir>/plugin.yaml` if target_dir is already named `community`).
    /// Returns the absolute path of the generated `plugin.yaml`.
    pub fn unpack_to_directory<P: AsRef<Path>>(target_dir: P) -> std::io::Result<PathBuf> {
        let base = target_dir.as_ref();
        let community_dir = if base.file_name().and_then(|s| s.to_str()) == Some("community") {
            base.to_path_buf()
        } else {
            base.join("community")
        };

        fs::create_dir_all(&community_dir)?;

        let manifest = Self::load_embedded_manifest()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let yaml_str = serde_yaml::to_string(&manifest)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let plugin_file = community_dir.join("plugin.yaml");
        fs::write(&plugin_file, yaml_str)?;

        Ok(plugin_file)
    }
}
