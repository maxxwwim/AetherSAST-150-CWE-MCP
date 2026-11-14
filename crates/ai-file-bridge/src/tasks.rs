use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    #[default]
    Function,
    Research,
    SecurityFix,
    ArchRefactor,
    Documentation,
    Test,
    Other,
}

impl TaskKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Research => "research",
            Self::SecurityFix => "security_fix",
            Self::ArchRefactor => "arch_refactor",
            Self::Documentation => "documentation",
            Self::Test => "test",
            Self::Other => "other",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "function" | "func" | "code" | "feat" | "feature" => Self::Function,
            "research" | "recherche" | "investigation" | "audit_explore" => Self::Research,
            "security" | "security_fix" | "cve" | "sast" => Self::SecurityFix,
            "refactor" | "arch" | "arch_refactor" | "architecture" => Self::ArchRefactor,
            "doc" | "documentation" | "spec" => Self::Documentation,
            "test" | "tests" | "unit_test" => Self::Test,
            _ => Self::Other,
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Function => "⚙️",
            Self::Research => "🔍",
            Self::SecurityFix => "🛡️",
            Self::ArchRefactor => "🏛️",
            Self::Documentation => "📖",
            Self::Test => "🧪",
            Self::Other => "📌",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    #[default]
    Pending,
    InProgress,
    Blocked,
    Done,
    Cancelled,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Blocked => "blocked",
            Self::Done => "done",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "in_progress" | "inprogress" | "doing" | "active" => Self::InProgress,
            "blocked" | "bloque" | "bloqué" | "waiting" => Self::Blocked,
            "done" | "completed" | "fini" | "resolu" => Self::Done,
            "cancelled" | "abandoned" | "annule" | "annulé" => Self::Cancelled,
            _ => Self::Pending,
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            Self::Pending => "⏳ EN ATTENTE",
            Self::InProgress => "⚡ EN COURS",
            Self::Blocked => "⛔ BLOQUÉ",
            Self::Done => "✅ TERMINÉ",
            Self::Cancelled => "⚪ ANNULÉ",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskItem {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub kind: TaskKind,
    #[serde(default)]
    pub status: TaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_file: Option<String>,
    #[serde(default = "default_author")]
    pub author: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub progress: u8,
    #[serde(default)]
    pub readme_summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_readme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readme: Option<String>,
}

fn default_author() -> String { "user".to_string() }
fn default_priority() -> String { "medium".to_string() }

pub struct TaskManager;

impl TaskManager {
    pub fn tasks_dir(project_root: &Path) -> PathBuf {
        project_root.join(".aether").join("tasks")
    }

    pub fn list_tasks(project_root: &Path) -> Vec<TaskItem> {
        let dir = Self::tasks_dir(project_root);
        let Ok(entries) = fs::read_dir(&dir) else { return Vec::new() };
        let mut tasks = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(id) = entry.file_name().to_str() {
                    if let Some(t) = Self::get_task(project_root, id) {
                        if seen_ids.insert(t.id.clone()) {
                            tasks.push(t);
                        }
                    }
                }
            } else if path.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".json") && name != "TASKS_SUMMARY.json" && name != "task.json" {
                        let id = name.strip_suffix(".json").unwrap_or(name);
                        if let Some(t) = Self::get_task(project_root, id) {
                            if seen_ids.insert(t.id.clone()) {
                                tasks.push(t);
                            }
                        }
                    }
                }
            }
        }
        tasks.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        tasks
    }

    pub fn get_task(project_root: &Path, task_id: &str) -> Option<TaskItem> {
        let clean_id = task_id.strip_suffix(".json").unwrap_or(task_id);
        let tasks_dir = Self::tasks_dir(project_root);
        let folder = tasks_dir.join(clean_id);
        let folder_meta = folder.join("task.json");
        let direct_file = tasks_dir.join(format!("{}.json", clean_id));

        let (meta_file, readme_file) = if folder_meta.exists() {
            (folder_meta, Some(folder.join("README.md")))
        } else if direct_file.exists() {
            let rf = if folder.join("README.md").exists() {
                Some(folder.join("README.md"))
            } else {
                None
            };
            (direct_file, rf)
        } else {
            return None;
        };

        let json_str = fs::read_to_string(&meta_file).ok()?;
        let mut task: TaskItem = serde_json::from_str(&json_str).ok()?;
        if task.id.is_empty() {
            task.id = clean_id.to_string();
        }

        if let Some(ref rf) = readme_file {
            if let Ok(readme_content) = fs::read_to_string(rf) {
                task.readme_summary = extract_summary(&readme_content);
                task.full_readme = Some(readme_content.clone());
                task.readme = Some(readme_content);
            }
        }
        if task.readme.is_none() {
            if let Some(ref fr) = task.full_readme {
                task.readme = Some(fr.clone());
            } else if !task.readme_summary.is_empty() {
                task.readme = Some(task.readme_summary.clone());
            }
        }
        Some(task)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_task(
        project_root: &Path,
        title: &str,
        kind: TaskKind,
        target_symbol: Option<&str>,
        target_file: Option<&str>,
        author: &str,
        priority: Option<&str>,
        initial_readme: Option<&str>,
    ) -> std::io::Result<TaskItem> {
        Self::create_task_with_agent(
            project_root,
            title,
            kind,
            target_symbol,
            target_file,
            author,
            priority,
            initial_readme,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_task_with_agent(
        project_root: &Path,
        title: &str,
        kind: TaskKind,
        target_symbol: Option<&str>,
        target_file: Option<&str>,
        author: &str,
        priority: Option<&str>,
        initial_readme: Option<&str>,
        agent_id: Option<&str>,
        agent_name: Option<&str>,
        color: Option<&str>,
    ) -> std::io::Result<TaskItem> {
        let tasks_dir = Self::tasks_dir(project_root);
        fs::create_dir_all(&tasks_dir)?;

        let now_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let task_id = format!("task_{}_{}", timestamp_ms % 1_000_000, slugify(title));
        let task_folder = tasks_dir.join(&task_id);
        fs::create_dir_all(&task_folder)?;

        let target_sym_owned = target_symbol.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let target_file_owned = target_file.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);

        let readme_content = match initial_readme {
            Some(r) if !r.trim().is_empty() => r.trim().to_string(),
            _ => generate_default_readme(title, &kind, target_sym_owned.as_deref(), target_file_owned.as_deref(), &now_str),
        };

        let resolved_agent_id = agent_id.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let resolved_agent_name = agent_name.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let resolved_color = color.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let resolved_author = if !author.trim().is_empty() && author.trim() != "model" {
            author.trim().to_string()
        } else {
            resolved_agent_name
                .clone()
                .or_else(|| resolved_agent_id.clone())
                .unwrap_or_else(|| if author.trim().is_empty() { "user".to_string() } else { author.trim().to_string() })
        };

        let task = TaskItem {
            id: task_id,
            title: title.trim().to_string(),
            kind,
            status: TaskStatus::Pending,
            target_symbol: target_sym_owned,
            target_file: target_file_owned,
            author: resolved_author,
            agent_id: resolved_agent_id,
            agent_name: resolved_agent_name,
            color: resolved_color,
            priority: priority.unwrap_or("medium").to_string(),
            created_at: now_str.clone(),
            updated_at: now_str,
            progress: 0,
            readme_summary: extract_summary(&readme_content),
            full_readme: Some(readme_content.clone()),
            readme: Some(readme_content.clone()),
        };

        fs::write(task_folder.join("task.json"), serde_json::to_string_pretty(&task)?)?;
        fs::write(task_folder.join("README.md"), &readme_content)?;
        let _ = Self::sync_tasks_summary_markdown(project_root);
        Ok(task)
    }

    pub fn update_task(
        project_root: &Path,
        task_id: &str,
        status: Option<TaskStatus>,
        progress: Option<u8>,
        append_note: Option<&str>,
        full_readme: Option<&str>,
    ) -> std::io::Result<Option<TaskItem>> {
        Self::update_task_with_meta(
            project_root,
            task_id,
            status,
            progress,
            append_note,
            full_readme,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_task_with_meta(
        project_root: &Path,
        task_id: &str,
        status: Option<TaskStatus>,
        progress: Option<u8>,
        append_note: Option<&str>,
        full_readme: Option<&str>,
        title: Option<&str>,
        target_symbol: Option<&str>,
        target_file: Option<&str>,
        priority: Option<&str>,
        agent_id: Option<&str>,
        agent_name: Option<&str>,
        color: Option<&str>,
    ) -> std::io::Result<Option<TaskItem>> {
        let clean_id = task_id.strip_suffix(".json").unwrap_or(task_id);
        let tasks_dir = Self::tasks_dir(project_root);
        let task_folder = tasks_dir.join(clean_id);
        let folder_meta = task_folder.join("task.json");
        let direct_file = tasks_dir.join(format!("{}.json", clean_id));

        let (meta_file, readme_file) = if folder_meta.exists() {
            (folder_meta, Some(task_folder.join("README.md")))
        } else if direct_file.exists() {
            let rf = if task_folder.join("README.md").exists() {
                Some(task_folder.join("README.md"))
            } else {
                None
            };
            (direct_file, rf)
        } else {
            return Ok(None);
        };

        let mut task: TaskItem = serde_json::from_str(&fs::read_to_string(&meta_file)?)?;
        if task.id.is_empty() {
            task.id = clean_id.to_string();
        }
        let now_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        task.updated_at = now_str.clone();

        if let Some(t) = title.map(str::trim).filter(|s| !s.is_empty()) {
            task.title = t.to_string();
        }
        if let Some(sym) = target_symbol.map(str::trim).filter(|s| !s.is_empty()) {
            task.target_symbol = Some(sym.to_string());
        }
        if let Some(f) = target_file.map(str::trim).filter(|s| !s.is_empty()) {
            task.target_file = Some(f.to_string());
        }
        if let Some(prio) = priority.map(str::trim).filter(|s| !s.is_empty()) {
            task.priority = prio.to_string();
        }
        if let Some(aid) = agent_id.map(str::trim).filter(|s| !s.is_empty()) {
            task.agent_id = Some(aid.to_string());
            if task.author == "user" || task.author == "model" {
                task.author = agent_name.map(str::trim).filter(|s| !s.is_empty()).unwrap_or(aid).to_string();
            }
        }
        if let Some(aname) = agent_name.map(str::trim).filter(|s| !s.is_empty()) {
            task.agent_name = Some(aname.to_string());
            if task.author == "user" || task.author == "model" {
                task.author = aname.to_string();
            }
        }
        if let Some(c) = color.map(str::trim).filter(|s| !s.is_empty()) {
            task.color = Some(c.to_string());
        }

        if let Some(new_status) = status {
            task.status = new_status;
            if task.status == TaskStatus::Done && task.progress < 100 {
                task.progress = 100;
            }
        }
        if let Some(p) = progress {
            task.progress = p.min(100);
            if task.progress == 100 && task.status == TaskStatus::Pending {
                task.status = TaskStatus::Done;
            } else if task.progress > 0 && task.status == TaskStatus::Pending {
                task.status = TaskStatus::InProgress;
            }
        }

        let mut current_readme = full_readme
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                readme_file.as_ref()
                    .and_then(|rf| fs::read_to_string(rf).ok())
                    .or_else(|| task.full_readme.clone())
                    .unwrap_or_default()
            });

        if let Some(note) = append_note.map(str::trim).filter(|s| !s.is_empty()) {
            let author_tag = task
                .agent_name
                .as_deref()
                .or(task.agent_id.as_deref())
                .unwrap_or(&task.author);
            current_readme.push_str(&format!("\n\n### 📝 Note d'avancement ({} — `{}`)\n{}\n", now_str, author_tag, note));
        }

        task.readme_summary = extract_summary(&current_readme);
        task.full_readme = Some(current_readme.clone());
        task.readme = Some(current_readme.clone());

        fs::write(&meta_file, serde_json::to_string_pretty(&task)?)?;
        if let Some(ref rf) = readme_file {
            let _ = fs::write(rf, &current_readme);
        } else if task_folder.is_dir() {
            let _ = fs::write(task_folder.join("README.md"), &current_readme);
        }
        let _ = Self::sync_tasks_summary_markdown(project_root);
        Ok(Some(task))
    }

    pub fn delete_task(project_root: &Path, task_id: &str) -> std::io::Result<bool> {
        let clean_id = task_id.strip_suffix(".json").unwrap_or(task_id);
        let tasks_dir = Self::tasks_dir(project_root);
        let task_folder = tasks_dir.join(clean_id);
        let direct_file = tasks_dir.join(format!("{}.json", clean_id));
        let mut deleted = false;
        if task_folder.exists() && task_folder.is_dir() {
            fs::remove_dir_all(&task_folder)?;
            deleted = true;
        }
        if direct_file.exists() && direct_file.is_file() {
            fs::remove_file(&direct_file)?;
            deleted = true;
        }
        if deleted {
            let _ = Self::sync_tasks_summary_markdown(project_root);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn sync_tasks_summary_markdown(project_root: &Path) -> std::io::Result<String> {
        let aether_dir = project_root.join(".aether");
        fs::create_dir_all(&aether_dir)?;

        let tasks = Self::list_tasks(project_root);
        let now_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let mut md = format!(
            "# 📋 AETHERSCOPE — JOURNAL DE BORD DES TÂCHES DU PROJET\n\n> Synchronisé le `{}` | Total Tâches : `{}`\n\n",
            now_str,
            tasks.len()
        );

        if tasks.is_empty() {
            md.push_str("*(Aucune tâche active dans le cockpit AetherScope. L'IA ou l'utilisateur peut en ajouter via `aetherscope_create_task`)*\n");
        } else {
            let active: Vec<&TaskItem> = tasks.iter().filter(|t| t.status != TaskStatus::Done && t.status != TaskStatus::Cancelled).collect();
            let completed: Vec<&TaskItem> = tasks.iter().filter(|t| t.status == TaskStatus::Done).collect();

            if !active.is_empty() {
                md.push_str(&format!("## ⚡ Tâches en cours & à faire ({})\n\n| ID | Type | Statut | Progrès | Titre | Cible | Auteur |\n| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n", active.len()));
                for t in &active {
                    let target = t.target_symbol.as_deref().or(t.target_file.as_deref()).unwrap_or("-");
                    md.push_str(&format!(
                        "| `{}` | {} {} | {} | {}% | **{}** | `{}` | {} |\n",
                        t.id, t.kind.icon(), t.kind.as_str(), t.status.badge(), t.progress, t.title, target, t.author
                    ));
                }
                md.push('\n');
            }

            if !completed.is_empty() {
                md.push_str(&format!("## ✅ Tâches terminées ({})\n\n", completed.len()));
                for t in completed {
                    let target = t.target_symbol.as_deref().or(t.target_file.as_deref()).unwrap_or("-");
                    md.push_str(&format!("- [x] **{}** (`{}`) — {} (*{}*)\n", t.title, t.id, target, t.updated_at));
                }
                md.push('\n');
            }

            md.push_str("## 📖 Détails des tâches actives :\n\n");
            for t in active.into_iter().take(5) {
                md.push_str(&format!("### {} `{}` : {}\n- **Statut :** {} ({}%)\n", t.kind.icon(), t.id, t.title, t.status.badge(), t.progress));
                if let Some(target) = &t.target_symbol {
                    md.push_str(&format!("- **Symbole cible :** `{}`\n", target));
                }
                if let Some(file) = &t.target_file {
                    md.push_str(&format!("- **Fichier cible :** `{}`\n", file));
                }
                if let Some(readme) = &t.full_readme {
                    md.push_str(&format!("\n```markdown\n{}\n```\n\n", readme.trim()));
                }
            }
        }

        fs::write(aether_dir.join("TASKS_SUMMARY.md"), &md)?;
        Ok(md)
    }
}

fn extract_summary(readme: &str) -> String {
    let lines: Vec<&str> = readme
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .take(3)
        .collect();
    if lines.is_empty() {
        "Aucun détail d'avancement pour le moment.".to_string()
    } else {
        lines.join(" ")
    }
}

fn slugify(text: &str) -> String {
    let clean: String = text.chars().map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect();
    let parts: Vec<&str> = clean.split('_').filter(|s| !s.is_empty()).take(4).collect();
    if parts.is_empty() { "task".to_string() } else { parts.join("_") }
}

fn generate_default_readme(
    title: &str,
    kind: &TaskKind,
    target_symbol: Option<&str>,
    target_file: Option<&str>,
    created_at: &str,
) -> String {
    let kind_title = match kind {
        TaskKind::Function => "Implémentation / Refactorisation de Fonction",
        TaskKind::Research => "Recherche & Exploration d'Architecture",
        TaskKind::SecurityFix => "Correction de Sécurité & Garde-fous",
        TaskKind::ArchRefactor => "Refactorisation Architecturale & Couplage",
        TaskKind::Documentation => "Documentation & Spécifications EARS",
        TaskKind::Test => "Tests Unitaires & Intégration",
        TaskKind::Other => "Tâche de Développement",
    };
    let target_str = match (target_symbol, target_file) {
        (Some(s), Some(f)) => format!("`{}` ({})", s, f),
        (Some(s), None) | (None, Some(s)) => format!("`{}`", s),
        (None, None) => "Projet Global".to_string(),
    };
    format!(
        "# {} {} : {}\n\n- **Cible :** {}\n- **Créée le :** `{}`\n- **Statut Initial :** `⏳ EN ATTENTE (0%)`\n\n---\n\n## 🎯 Objectif\n{}\n\n## 📋 Plan d'Action & Étapes\n- [ ] 1. Analyse initiale des dépendances et contrats\n- [ ] 2. Conception de la solution chirurgicale (< 35 lignes par fonction)\n- [ ] 3. Validation de l'audit de sécurité (`LIVE_AUDIT.md`)\n\n## 📝 Journal d'Avancement\n*(Initialisé. L'IA ou l'utilisateur mettra à jour cette section au fur et à mesure)*\n",
        kind.icon(), kind_title, title, target_str, created_at, title
    )
}
