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
    #[serde(default = "default_id")]
    pub id: String,
    #[serde(default = "default_layer")]
    pub layer: String,
    #[serde(default = "default_max_lines")]
    pub max_lines_per_file: usize,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub file_max_lines: HashMap<String, usize>,
    #[serde(default)]
    pub allowed_imports: Vec<String>,
    #[serde(default)]
    pub forbidden_imports: Vec<String>,
    /// Fonctions / macros dont l'appel est interdit dans le dossier (ex: `eval`, `unwrap`, `println!`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_functions: Vec<String>,
    /// Liste blanche d'extensions de fichiers (ex: `rs`, `toml`). Vide = tout est autorisé.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_extensions: Vec<String>,
    /// Liste noire d'extensions de fichiers (ex: `exe`, `js`, `d.ts`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_extensions: Vec<String>,
    /// Nombre maximal de fichiers directement présents dans un dossier couvert par ce contrat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_files_per_folder: Option<usize>,
    #[serde(default)]
    pub security_rules: SecurityRules,
}

/// Normalise une extension déclarée dans un contrat : `.EXE`, `*.exe` et `exe` → `exe`.
fn normalize_extension(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('*')
        .trim_start_matches('.')
        .to_lowercase()
}

/// Vrai si `line` contient un appel à la fonction (ou macro `nom!`) `pattern`, hors déclaration
/// (`fn nom(`, `def nom(`, `function nom(`) et hors identifiant plus long (`retrieval(` ≠ `eval(`).
pub fn line_calls_function(line: &str, pattern: &str) -> bool {
    let name = pattern.trim().trim_end_matches("()");
    let is_macro = name.ends_with('!');
    let core = name.trim_end_matches('!');
    if core.is_empty() {
        return false;
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = line.as_bytes();
    let mut start = 0usize;
    while let Some(pos) = line[start..].find(core) {
        let abs = start + pos;
        let end = abs + core.len();
        let before_ok = abs == 0 || !is_ident(bytes[abs - 1]);
        let rest = line[end..].trim_start();
        let after_ok = if is_macro {
            rest.starts_with('!')
        } else {
            rest.starts_with('(')
        };
        if before_ok && after_ok {
            let prefix = line[..abs].trim_end();
            let is_declaration = ["fn", "def", "function"].iter().any(|kw| {
                prefix.ends_with(kw)
                    && (prefix.len() == kw.len()
                        || !is_ident(prefix.as_bytes()[prefix.len() - kw.len() - 1]))
            });
            if !is_declaration {
                return true;
            }
        }
        start = end;
    }
    false
}

/// Mise à jour optionnelle des règles « structure » d'un contrat (`None` = champ inchangé).
#[derive(Debug, Clone, Default)]
pub struct ContractStructureUpdate {
    pub forbidden_functions: Option<Vec<String>>,
    pub allowed_extensions: Option<Vec<String>>,
    pub forbidden_extensions: Option<Vec<String>>,
    pub max_files_per_folder: Option<usize>,
}

fn default_id() -> String {
    "module".to_string()
}

fn default_layer() -> String {
    "domain".to_string()
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

        if let Some(after_open) = content.strip_prefix("---") {
            if let Some(end_idx) = after_open.find("---") {
                frontmatter_str = &after_open[..end_idx];
                body_str = &after_open[end_idx + 3..];
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
                forbidden_functions: Vec::new(),
                allowed_extensions: Vec::new(),
                forbidden_extensions: Vec::new(),
                max_files_per_folder: None,
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

    /// Vérifie l'extension d'un fichier vis-à-vis de `forbidden_extensions` / `allowed_extensions`.
    /// Retourne `Some(raison)` si le fichier viole le contrat. Le `README.md` du contrat est toujours exempté.
    pub fn extension_violation(&self, file_path: &str) -> Option<String> {
        let name = file_path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(file_path)
            .to_lowercase();
        if name == "readme.md" {
            return None;
        }
        let matches_ext = |ext: &String| {
            let norm = normalize_extension(ext);
            !norm.is_empty() && name.ends_with(&format!(".{}", norm))
        };
        if let Some(bad) = self
            .frontmatter
            .forbidden_extensions
            .iter()
            .find(|e| matches_ext(e))
        {
            return Some(format!(
                "extension '.{}' is forbidden by folder contract",
                normalize_extension(bad)
            ));
        }
        let allowed = &self.frontmatter.allowed_extensions;
        let has_extension = name
            .rfind('.')
            .map(|idx| idx > 0 && idx + 1 < name.len())
            .unwrap_or(false);
        if !allowed.is_empty() && has_extension && !allowed.iter().any(matches_ext) {
            let list = allowed
                .iter()
                .map(|e| format!(".{}", normalize_extension(e)))
                .collect::<Vec<_>>()
                .join(", ");
            return Some(format!(
                "extension of '{}' is not in the allowed list ({})",
                name, list
            ));
        }
        None
    }

    /// Retourne la première fonction interdite appelée sur cette ligne, si elle existe.
    pub fn forbidden_function_on_line<'a>(&'a self, line: &str) -> Option<&'a String> {
        self.frontmatter
            .forbidden_functions
            .iter()
            .find(|pat| line_calls_function(line, pat))
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
        Self::upsert_contract_content_with_structure(
            existing_content,
            folder_path,
            folder_max_lines,
            file_override,
            allowed_imports,
            forbidden_imports,
            &ContractStructureUpdate::default(),
        )
    }

    /// Variante complète : met aussi à jour fonctions interdites, extensions et limite de fichiers.
    pub fn upsert_contract_content_with_structure(
        existing_content: Option<&str>,
        folder_path: &str,
        folder_max_lines: Option<usize>,
        file_override: Option<(&str, Option<usize>)>,
        allowed_imports: Option<Vec<String>>,
        forbidden_imports: Option<Vec<String>>,
        structure: &ContractStructureUpdate,
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
            forbidden_functions: Vec::new(),
            allowed_extensions: Vec::new(),
            forbidden_extensions: Vec::new(),
            max_files_per_folder: None,
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
            if let Some(after_open) = raw.strip_prefix("---") {
                if let Some(end_idx) = after_open.find("---") {
                    let rest = &after_open[end_idx + 3..];
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
        if let Some(funcs) = &structure.forbidden_functions {
            frontmatter.forbidden_functions = funcs.clone();
        }
        if let Some(exts) = &structure.allowed_extensions {
            frontmatter.allowed_extensions = exts.clone();
        }
        if let Some(exts) = &structure.forbidden_extensions {
            frontmatter.forbidden_extensions = exts.clone();
        }
        if let Some(max_files) = structure.max_files_per_folder {
            // 0 = supprimer la limite
            frontmatter.max_files_per_folder = if max_files == 0 { None } else { Some(max_files) };
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

    #[test]
    fn test_line_calls_function_boundaries() {
        assert!(line_calls_function("let x = eval(input);", "eval"));
        assert!(line_calls_function("window.eval (code)", "eval"));
        assert!(line_calls_function("opt.unwrap();", "unwrap"));
        assert!(line_calls_function("println!(\"x\");", "println!"));
        assert!(!line_calls_function("let y = retrieval(a);", "eval"));
        assert!(!line_calls_function("eprintln!(\"x\");", "println!"));
        assert!(!line_calls_function("fn eval(x: i32) {}", "eval"));
        assert!(!line_calls_function("def eval(x):", "eval"));
        assert!(!line_calls_function("let eval = 3;", "eval"));
    }

    #[test]
    fn test_contract_structure_rules_roundtrip() {
        let content = "---\nid: svc\nlayer: domain\nforbidden_functions: [\"eval\", \"unwrap\"]\nallowed_extensions: [\"rs\", \".toml\"]\nforbidden_extensions: [\"exe\", \"d.ts\"]\nmax_files_per_folder: 3\n---\n# Svc\n";
        let c = ReadmeContract::parse("svc", content).unwrap();
        assert_eq!(c.frontmatter.max_files_per_folder, Some(3));
        assert!(c.forbidden_function_on_line("x.unwrap();").is_some());
        assert!(c.forbidden_function_on_line("x.unwrap_or(1);").is_none());
        assert!(c.extension_violation("svc/run.exe").is_some());
        assert!(c.extension_violation("svc/types.d.ts").is_some());
        assert!(c.extension_violation("svc/main.rs").is_none());
        assert!(c.extension_violation("svc/Cargo.TOML").is_none());
        assert!(c.extension_violation("svc/app.py").is_some(), "not in allowed list");
        assert!(c.extension_violation("svc/LICENSE").is_none(), "no extension => ignored");
        assert!(c.extension_violation("svc/README.md").is_none(), "contract itself is exempt");

        let updated = ReadmeContract::upsert_contract_content_with_structure(
            Some(content),
            "svc",
            None,
            None,
            None,
            None,
            &ContractStructureUpdate {
                forbidden_functions: Some(vec!["dbg!".to_string()]),
                max_files_per_folder: Some(0),
                ..Default::default()
            },
        );
        let c2 = ReadmeContract::parse("svc", &updated).unwrap();
        assert_eq!(c2.frontmatter.forbidden_functions, vec!["dbg!".to_string()]);
        assert_eq!(c2.frontmatter.max_files_per_folder, None);
        assert_eq!(c2.frontmatter.forbidden_extensions.len(), 2, "untouched fields preserved");
    }
}