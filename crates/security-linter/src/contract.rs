use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityRules {
    #[serde(default)]
    pub no_raw_sql: bool,
    #[serde(default)]
    pub no_env_access: bool,
    #[serde(default)]
    pub untrusted_client_input: bool,
    #[serde(default)]
    pub deterministic_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadmeFrontmatter {
    pub id: String,
    pub layer: String,
    #[serde(default = "default_max_lines")]
    pub max_lines_per_file: usize,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub file_max_lines: HashMap<String, usize>,
    #[serde(default)]
    pub allowed_imports: Vec<String>,
    #[serde(default)]
    pub forbidden_imports: Vec<String>,
    #[serde(default)]
    pub security_rules: SecurityRules,
}

fn default_max_lines() -> usize {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarsRequirement {
    pub raw: String,
    pub trigger: String, // "WHEN ..."
    pub system_shall: String, // "THE SYSTEM SHALL ..."
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadmeContract {
    pub folder_path: String,
    pub frontmatter: ReadmeFrontmatter,
    pub ears_requirements: Vec<EarsRequirement>,
    pub exported_signatures: Vec<String>,
    pub blake3_hash: String,
}

impl ReadmeContract {
    /// Parse un README.md avec frontmatter YAML et syntaxe EARS
    pub fn parse(folder_path: &str, content: &str) -> Result<Self, String> {
        let blake3_hash = blake3::hash(content.as_bytes()).to_hex().to_string();

        let mut frontmatter_str = "";
        let mut body_str = content;

        if content.starts_with("---") {
            if let Some(end_idx) = content[3..].find("---") {
                frontmatter_str = &content[3..end_idx + 3];
                body_str = &content[end_idx + 6..];
            }
        }

        let frontmatter: ReadmeFrontmatter = if !frontmatter_str.trim().is_empty() {
            serde_yaml::from_str(frontmatter_str)
                .map_err(|e| format!("YAML frontmatter parse error in {}: {}", folder_path, e))?
        } else {
            ReadmeFrontmatter {
                id: folder_path.replace(['/', '\\'], "-"),
                layer: "utility".to_string(),
                max_lines_per_file: 300,
                file_max_lines: HashMap::new(),
                allowed_imports: Vec::new(),
                forbidden_imports: Vec::new(),
                security_rules: SecurityRules::default(),
            }
        };

        // Extraction des règles EARS (WHEN ... THE SYSTEM SHALL ...)
        let mut ears = Vec::new();
        for line in body_str.lines() {
            let trimmed = line.trim();
            if trimmed.to_uppercase().contains("WHEN ") && trimmed.to_uppercase().contains("THE SYSTEM SHALL") {
                let upper = trimmed.to_uppercase();
                if let (Some(w_idx), Some(s_idx)) = (upper.find("WHEN "), upper.find("THE SYSTEM SHALL")) {
                    if s_idx > w_idx {
                        let trigger = trimmed[w_idx + 5..s_idx].trim().trim_end_matches(',').to_string();
                        let system_shall = trimmed[s_idx + 16..].trim().to_string();
                        ears.push(EarsRequirement {
                            raw: trimmed.to_string(),
                            trigger,
                            system_shall,
                        });
                    }
                }
            }
        }

        // Extraction des signatures de code dans les blocs de code markdown
        let mut signatures = Vec::new();
        let mut inside_code_block = false;
        for line in body_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("```") {
                inside_code_block = !inside_code_block;
                continue;
            }
            if inside_code_block && (trimmed.starts_with("pub fn ") || trimmed.starts_with("export function ") || trimmed.starts_with("def ")) {
                signatures.push(trimmed.to_string());
            }
        }

        Ok(Self {
            folder_path: folder_path.to_string(),
            frontmatter,
            ears_requirements: ears,
            exported_signatures: signatures,
            blake3_hash,
        })
    }

    /// Vérifie si le hash BLAKE3 correspond au lockfile
    pub fn verify_lock(&self, expected_hash: &str) -> bool {
        self.blake3_hash == expected_hash
    }

    /// Retourne la limite de lignes spécifique au fichier si définie dans `file_max_lines`
    pub fn file_override_for(&self, file_path: &str) -> Option<usize> {
        if self.frontmatter.file_max_lines.is_empty() {
            return None;
        }
        let norm_path = file_path
            .trim_start_matches("./")
            .trim_start_matches('/')
            .replace('\\', "/");
        let file_name = norm_path.rsplit('/').next().unwrap_or(&norm_path);
        let rel_to_folder = if self.folder_path != "root" && !self.folder_path.is_empty() {
            let prefix = format!("{}/", self.folder_path.trim_matches('/'));
            norm_path.strip_prefix(&prefix).unwrap_or(&norm_path)
        } else {
            norm_path.as_str()
        };

        if let Some(&v) = self.frontmatter.file_max_lines.get(&norm_path) {
            return Some(v);
        }
        if let Some(&v) = self.frontmatter.file_max_lines.get(rel_to_folder) {
            return Some(v);
        }
        if let Some(&v) = self.frontmatter.file_max_lines.get(file_name) {
            return Some(v);
        }

        let norm_lower = norm_path.to_lowercase();
        let rel_lower = rel_to_folder.to_lowercase();
        let name_lower = file_name.to_lowercase();
        for (k, &v) in &self.frontmatter.file_max_lines {
            let kl = k
                .trim_start_matches("./")
                .trim_start_matches('/')
                .replace('\\', "/")
                .to_lowercase();
            if kl == norm_lower || kl == rel_lower || kl == name_lower || norm_lower.ends_with(&format!("/{}", kl)) {
                return Some(v);
            }
        }
        None
    }

    /// Calcule la limite effective de lignes pour un fichier selon le contrat (fichier ou dossier)
    pub fn effective_max_lines(&self, file_path: &str) -> usize {
        if let Some(file_limit) = self.file_override_for(file_path) {
            return file_limit;
        }
        let norm_path = file_path.replace('\\', "/").to_lowercase();
        if self.frontmatter.max_lines_per_file != 300 {
            return self.frontmatter.max_lines_per_file;
        }
        if norm_path.ends_with(".java") {
            10_000
        } else if norm_path.ends_with(".sol") {
            600
        } else {
            self.frontmatter.max_lines_per_file
        }
    }

    /// Met à jour ou crée le contenu d'un contrat README.md (frontmatter YAML + corps EARS)
    pub fn upsert_contract_content(
        existing_content: Option<&str>,
        folder_path: &str,
        folder_max_lines: Option<usize>,
        file_override: Option<(&str, Option<usize>)>,
        allowed_imports: Option<Vec<String>>,
        forbidden_imports: Option<Vec<String>>,
    ) -> String {
        let clean_folder = if folder_path.is_empty() || folder_path == "." {
            "root"
        } else {
            folder_path
        };

        let mut frontmatter = ReadmeFrontmatter {
            id: clean_folder.replace(['/', '\\'], "-"),
            layer: "domain".to_string(),
            max_lines_per_file: 300,
            file_max_lines: HashMap::new(),
            allowed_imports: Vec::new(),
            forbidden_imports: Vec::new(),
            security_rules: SecurityRules::default(),
        };

        let mut body = format!(
            "# 📜 Contrat Architectural — `{}`\n\n## 🛡️ Règles EARS\n- WHEN a file of this folder exceeds `max_lines_per_file` THE SYSTEM SHALL report a `RULE_MAX_LINES` warning.\n",
            clean_folder
        );

        if let Some(raw) = existing_content {
            if let Ok(parsed) = Self::parse(clean_folder, raw) {
                frontmatter = parsed.frontmatter;
            }
            if raw.starts_with("---") {
                if let Some(end_idx) = raw[3..].find("---") {
                    let rest = &raw[end_idx + 6..];
                    body = rest.trim_start_matches(['\r', '\n']).to_string();
                } else {
                    body = raw.to_string();
                }
            } else if !raw.trim().is_empty() {
                body = raw.to_string();
            }
        }

        if let Some(max_l) = folder_max_lines {
            frontmatter.max_lines_per_file = max_l.max(1);
        }

        if let Some((raw_file_key, limit_opt)) = file_override {
            let norm_key = raw_file_key
                .trim_start_matches("./")
                .trim_start_matches('/')
                .replace('\\', "/");
            let short_key = if clean_folder != "root" {
                let prefix = format!("{}/", clean_folder.trim_matches('/'));
                norm_key.strip_prefix(&prefix).unwrap_or(&norm_key).to_string()
            } else {
                norm_key.clone()
            };
            let bare_name = norm_key.rsplit('/').next().unwrap_or(&norm_key).to_string();

            // Nettoyer les clés équivalentes existantes avant insertion/suppression
            frontmatter.file_max_lines.retain(|k, _| {
                let kl = k.trim_start_matches("./").trim_start_matches('/').replace('\\', "/");
                kl != norm_key && kl != short_key && kl != bare_name
            });

            if let Some(lim) = limit_opt {
                frontmatter.file_max_lines.insert(short_key, lim.max(1));
            }
        }

        if let Some(allowed) = allowed_imports {
            frontmatter.allowed_imports = allowed;
        }
        if let Some(forbidden) = forbidden_imports {
            frontmatter.forbidden_imports = forbidden;
        }

        let yaml = serde_yaml::to_string(&frontmatter).unwrap_or_else(|_| {
            format!(
                "id: {}\nlayer: {}\nmax_lines_per_file: {}\n",
                frontmatter.id, frontmatter.layer, frontmatter.max_lines_per_file
            )
        });
        let clean_yaml = yaml.trim_start_matches("---\n").trim_end();
        if body.ends_with('\n') {
            format!("---\n{}\n---\n{}", clean_yaml, body)
        } else {
            format!("---\n{}\n---\n{}\n", clean_yaml, body)
        }
    }

    /// Calcule l'empreinte BLAKE3 hexadécimale d'un contenu de fichier ou de contrat
    pub fn compute_blake3_hex(content: &str) -> String {
        blake3::hash(content.as_bytes()).to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_folder_and_file_max_lines_blake3() {
        let initial = ReadmeContract::upsert_contract_content(
            None,
            "crates/core-graph",
            Some(350),
            Some(("crates/core-graph/src/bubble.rs", Some(600))),
            None,
            None,
        );
        let parsed = ReadmeContract::parse("crates/core-graph", &initial).unwrap();
        assert_eq!(parsed.frontmatter.max_lines_per_file, 350);
        assert_eq!(parsed.effective_max_lines("crates/core-graph/src/bubble.rs"), 600);
        assert_eq!(parsed.effective_max_lines("crates/core-graph/src/edge.rs"), 350);
        assert_eq!(parsed.blake3_hash.len(), 64);

        let cleared = ReadmeContract::upsert_contract_content(
            Some(&initial),
            "crates/core-graph",
            None,
            Some(("crates/core-graph/src/bubble.rs", None)),
            None,
            None,
        );
        let parsed2 = ReadmeContract::parse("crates/core-graph", &cleared).unwrap();
        assert_eq!(parsed2.effective_max_lines("crates/core-graph/src/bubble.rs"), 350);
        assert_ne!(parsed.blake3_hash, parsed2.blake3_hash);
    }
}
