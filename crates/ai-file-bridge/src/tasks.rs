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
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                if let Some(id) = entry.file_name().to_str() {
                    if let Some(t) = Self::get_task(project_root, id) {
                        tasks.push(t);
                    }
                }
            }
        }
        tasks.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        tasks
    }

    pub fn get_task(project_root: &Path, task_id: &str) -> Option<TaskItem> {
        let folder = Self::tasks_dir(project_root).join(task_id);
        let json_str = fs::read_to_string(folder.join("task.json")).ok()?;
        let mut task: TaskItem = serde_json::from_str(&json_str).ok()?;
        if let Ok(readme_content) = fs::read_to_string(folder.join("README.md")) {
            task.readme_summary = extract_summary(&readme_content);
            task.full_readme = Some(readme_content);
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

        let task = TaskItem {
            id: task_id,
            title: title.trim().to_string(),
            kind,
            status: TaskStatus::Pending,
            target_symbol: target_sym_owned,
            target_file: target_file_owned,
            author: author.trim().to_string(),
            priority: priority.unwrap_or("medium").to_string(),
            created_at: now_str.clone(),
            updated_at: now_str,
            progress: 0,
            readme_summary: extract_summary(&readme_content),
            full_readme: Some(readme_content.clone()),
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
        let task_folder = Self::tasks_dir(project_root).join(task_id);
        let meta_file = task_folder.join("task.json");
        let readme_file = task_folder.join("README.md");
        if !meta_file.exists() {
            return Ok(None);
        }

        let mut task: TaskItem = serde_json::from_str(&fs::read_to_string(&meta_file)?)?;
        let now_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        task.updated_at = now_str.clone();

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
            .map(str::to_string)
            .unwrap_or_else(|| fs::read_to_string(&readme_file).unwrap_or_default());

        if let Some(note) = append_note.map(str::trim).filter(|s| !s.is_empty()) {
            current_readme.push_str(&format!("\n\n### 📝 Note d'avancement ({})\n{}\n", now_str, note));
        }

        task.readme_summary = extract_summary(&current_readme);
        task.full_readme = Some(current_readme.clone());

        fs::write(&meta_file, serde_json::to_string_pretty(&task)?)?;
        fs::write(&readme_file, &current_readme)?;
        let _ = Self::sync_tasks_summary_markdown(project_root);
        Ok(Some(task))
    }

    pub fn delete_task(project_root: &Path, task_id: &str) -> std::io::Result<bool> {
        let task_folder = Self::tasks_dir(project_root).join(task_id);
        if task_folder.exists() {
            fs::remove_dir_all(&task_folder)?;
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
