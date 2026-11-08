//! Integration test verifying hot-reload detection of .aether/plugins/ YAML files

use ai_file_bridge::FileWatcherBridge;
use security_linter::CommunityBundle;
use std::fs;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

#[test]
fn test_watcher_detects_aether_plugins_yaml_change() {
    let temp_root = std::env::temp_dir().join(format!("aether_watch_test_{}", std::process::id()));
    if temp_root.exists() {
        let _ = fs::remove_dir_all(&temp_root);
    }
    fs::create_dir_all(&temp_root).unwrap();

    // Create a dummy source file so root is non-empty
    fs::write(temp_root.join("main.rs"), "fn main() {}\n").unwrap();

    let watcher = FileWatcherBridge::new(&temp_root).expect("Watcher should initialize");
    sleep(Duration::from_millis(300));

    // Unpack community bundle into .aether/plugins
    let plugins_dir = temp_root.join(".aether").join("plugins");
    let plugin_file = CommunityBundle::unpack_to_directory(&plugins_dir)
        .expect("CommunityBundle unpack should succeed");
    assert!(plugin_file.exists());

    // Give watcher time to capture notify events
    sleep(Duration::from_millis(1000));

    let changed = watcher.poll_changed_files();
    assert!(
        changed.iter().any(|p| p.ends_with(Path::new("community").join("plugin.yaml"))),
        "Expected .aether/plugins/community/plugin.yaml to be detected by watcher, but got: {:?}",
        changed
    );

    let _ = fs::remove_dir_all(&temp_root);
}
