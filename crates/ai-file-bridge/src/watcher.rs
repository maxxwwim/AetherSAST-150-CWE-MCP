use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Mutex;
use std::time::Duration;

const EXCLUDED_WATCH_DIRS: &[&str] = &[
    "target",
    "node_modules",
    "dist",
    "build",
    "out",
    "w64devkit",
    "mingw64",
    "mingw32",
    "res",
    "resources",
    "assets",
    "imgs",
    "images",
    "icons",
    "fonts",
    "country_flags",
    "libs",
    "lang",
    "locales",
    "i18n",
    "vendor",
    "third_party",
    "client_apk",
    "client_c",
    "cpp_builder",
    "python_utils_testing",
    "cosmoscope_output",
    "coverage",
    "venv",
    "__pycache__",
];

const WATCHED_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "md", "mdx", "svelte", "vue", "html",
    "css", "scss", "cpp", "hpp", "cc", "hh", "cxx", "hxx", "c", "h", "inl", "java", "sol", "yul",
    "php", "phtml", "zig", "cs", "lua", "luau", "json", "toml", "yaml", "yml", "glsl",
];

fn is_watched_ext(ext: &str) -> bool {
    WATCHED_EXTENSIONS.contains(&ext)
}

fn is_excluded_dir_name(name: &str) -> bool {
    if name == ".aether" {
        return false;
    }
    name.starts_with('.')
        || name.contains("WebView2")
        || EXCLUDED_WATCH_DIRS
            .iter()
            .any(|d| name.eq_ignore_ascii_case(d))
}

fn is_ignored_file_name(name: &str) -> bool {
    name.ends_with(".log")
        || name == "aetherscope_viewer.html"
        || name == "AETHER_AI_RULES.md"
        || (name.starts_with('.') && name.contains(".tmp."))
        || name.starts_with(".tmp_")
}

fn has_excluded_relative_component(path: &Path, root: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let mut in_dot_aether = false;
    for comp in rel.components() {
        let std::path::Component::Normal(os_str) = comp else {
            continue;
        };
        let s = os_str.to_string_lossy();
        if in_dot_aether {
            if s != "plugins" {
                return true;
            }
            in_dot_aether = false;
            continue;
        }
        if s == ".aether" {
            in_dot_aether = true;
            continue;
        }
        if is_excluded_dir_name(&s) {
            return true;
        }
    }
    false
}

fn collect_watched_files_in_dir(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if has_excluded_relative_component(&path, root) {
            continue;
        }
        if path.is_dir() {
            collect_watched_files_in_dir(&path, root, out);
        } else if path.is_file() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if is_ignored_file_name(&file_name) {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if is_watched_ext(&ext) && !out.contains(&path) {
                out.push(path);
            }
        }
    }
}

fn watch_filtered_tree(
    watcher: &mut RecommendedWatcher,
    dir: &Path,
    depth: usize,
) -> Result<(), notify::Error> {
    if !dir.is_dir() {
        return Ok(());
    }
    if depth >= 2 {
        let _ = watcher.watch(dir, RecursiveMode::Recursive);
        return Ok(());
    }
    let _ = watcher.watch(dir, RecursiveMode::NonRecursive);
    if let Ok(entries) = std::fs::read_dir(dir) {
        let is_in_dot_aether = dir.file_name().map(|n| n == ".aether").unwrap_or(false);
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if is_in_dot_aether && name != "plugins" {
                    continue;
                }
                if !is_excluded_dir_name(&name) {
                    let _ = watch_filtered_tree(watcher, &path, depth + 1);
                }
            }
        }
    }
    Ok(())
}

pub struct FileWatcherBridge {
    watcher: Mutex<RecommendedWatcher>,
    rx: Receiver<notify::Result<Event>>,
    pub project_root: PathBuf,
}

impl FileWatcherBridge {
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, notify::Error> {
        let root_buf = root.as_ref().to_path_buf();
        let (tx, rx) = channel();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_millis(100)),
        )?;

        let aether_plugins = root_buf.join(".aether").join("plugins");
        let _ = std::fs::create_dir_all(&aether_plugins);

        watch_filtered_tree(&mut watcher, root.as_ref(), 0)?;

        Ok(Self {
            watcher: Mutex::new(watcher),
            rx,
            project_root: root_buf,
        })
    }

    /// Met à jour dynamiquement le dossier racine surveillé lorsque l'utilisateur change de projet
    pub fn switch_root<P: AsRef<Path>>(&mut self, new_root: P) -> Result<(), notify::Error> {
        let new_buf = new_root.as_ref().to_path_buf();
        if self.project_root != new_buf && new_buf.is_dir() {
            let aether_plugins = new_buf.join(".aether").join("plugins");
            let _ = std::fs::create_dir_all(&aether_plugins);
            if let Ok(mut w) = self.watcher.lock() {
                let _ = w.unwatch(&self.project_root);
                watch_filtered_tree(&mut w, &new_buf, 0)?;
            }
            self.project_root = new_buf;
        }
        Ok(())
    }

    /// Récupère les chemins de fichiers et dossiers modifiés lors de cette boucle
    pub fn poll_changed_files(&self) -> Vec<PathBuf> {
        let mut changed = Vec::new();
        while let Ok(res) = self.rx.try_recv() {
            if let Ok(event) = res {
                if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                    for path in event.paths {
                        if path == self.project_root {
                            continue;
                        }
                        let file_name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if is_ignored_file_name(&file_name) {
                            continue;
                        }
                        let p_str = path.to_string_lossy();
                        if p_str.contains(".aether")
                            && !p_str.contains(".aether/plugins")
                            && !p_str.contains(r".aether\plugins")
                        {
                            continue;
                        }
                        if has_excluded_relative_component(&path, &self.project_root) {
                            continue;
                        }

                        if path.is_dir() {
                            // Nouveau dossier créé, déplacé ou renommé : on l'attache dynamiquement au watcher
                            let rel_depth = path
                                .strip_prefix(&self.project_root)
                                .map(|r| r.components().count())
                                .unwrap_or(2);
                            if let Ok(mut w) = self.watcher.lock() {
                                let _ = watch_filtered_tree(&mut w, &path, rel_depth);
                            }
                            // Collecte immédiate des fichiers déjà présents dans ce dossier (ex: copie/déplacement de dossier)
                            collect_watched_files_in_dir(&path, &self.project_root, &mut changed);
                            if !changed.contains(&path) {
                                changed.push(path);
                            }
                            continue;
                        }

                        if path.is_file() {
                            let ext = path
                                .extension()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_lowercase();
                            if is_watched_ext(&ext) && !changed.contains(&path) {
                                changed.push(path);
                            }
                            continue;
                        }

                        // Chemin supprimé ou renommé (!path.exists())
                        if !path.exists() {
                            let ext = path
                                .extension()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .to_lowercase();
                            if ext.is_empty() {
                                // Dossier supprimé ou renommé
                                if let Ok(mut w) = self.watcher.lock() {
                                    let _ = w.unwatch(&path);
                                }
                                if !changed.contains(&path) {
                                    changed.push(path);
                                }
                            } else if is_watched_ext(&ext) && !changed.contains(&path) {
                                changed.push(path);
                            }
                        }
                    }
                }
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::thread::sleep;

    #[test]
    fn test_watcher_detects_file_deletion() {
        let temp_dir = std::env::temp_dir().join(format!("aether_watcher_del_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).expect("Create temp dir");

        let test_file = temp_dir.join("test_deleted.rs");
        fs::write(&test_file, "// will be deleted\n").expect("Write test file");

        let watcher = FileWatcherBridge::new(&temp_dir).expect("Create watcher");
        sleep(Duration::from_millis(300));
        let _ = watcher.poll_changed_files(); // drain initial events

        // Delete the file
        fs::remove_file(&test_file).expect("Delete file");
        sleep(Duration::from_millis(800));

        let changed = watcher.poll_changed_files();
        assert!(
            changed.iter().any(|p| p.ends_with("test_deleted.rs")),
            "Expected test_deleted.rs in changed files after deletion, but got: {:?}",
            changed
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_watcher_detects_new_folder_and_nested_files() {
        let temp_dir = std::env::temp_dir().join(format!("aether_watcher_dir_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).expect("Create temp dir");

        let watcher = FileWatcherBridge::new(&temp_dir).expect("Create watcher");
        sleep(Duration::from_millis(250));
        let _ = watcher.poll_changed_files();

        // 1. Create a brand new directory at depth 0
        let new_folder = temp_dir.join("new_module");
        fs::create_dir_all(&new_folder).expect("Create new_module dir");
        sleep(Duration::from_millis(350));
        let folder_events = watcher.poll_changed_files();
        assert!(
            folder_events.iter().any(|p| p.ends_with("new_module")),
            "Expected new_module folder creation to be detected, got: {:?}",
            folder_events
        );

        // 2. Create a file inside the newly created directory (tests dynamic watch attachment)
        let nested_file = new_folder.join("feature.rs");
        fs::write(&nested_file, "pub fn hello() {}\n").expect("Write nested file");
        sleep(Duration::from_millis(350));
        let file_events = watcher.poll_changed_files();
        assert!(
            file_events.iter().any(|p| p.ends_with("feature.rs")),
            "Expected feature.rs inside newly created folder to be watched, got: {:?}",
            file_events
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

