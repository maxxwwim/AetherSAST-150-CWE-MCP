mod installer;
mod manifest;
mod runner;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use installer::AetherInstaller;
use manifest::ServerManifest;
use runner::AetherRunner;
use std::path::{Component, Path, PathBuf};

fn validate_server_id(server_id: &str) -> Result<&str> {
    if server_id.trim().is_empty()
        || server_id != server_id.trim()
        || server_id.contains('\0')
        || server_id.contains('/')
        || server_id.contains('\\')
        || server_id.contains(':')
        || server_id.contains("..")
        || server_id == "."
    {
        anyhow::bail!("Identifiant de serveur invalide : {:?}", server_id);
    }
    let p = Path::new(server_id);
    if p.is_absolute() || p.has_root() {
        anyhow::bail!("Identifiant de serveur absolu ou enraciné interdit : {:?}", server_id);
    }
    let mut comps = p.components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(_)), None) => Ok(server_id),
        _ => anyhow::bail!(
            "Identifiant de serveur doit être un segment relatif unique : {:?}",
            server_id
        ),
    }
}

fn resolve_default_instance_dir(dir: Option<PathBuf>, server_id: &str) -> Result<PathBuf> {
    if let Some(explicit) = dir {
        return Ok(explicit);
    }
    let clean_id = validate_server_id(server_id)?;
    let p = Path::new(clean_id);
    if p.is_absolute() || p.has_root() {
        anyhow::bail!("Identifiant de serveur non confiné : {:?}", server_id);
    }
    match p.components().next() {
        Some(Component::Normal(seg)) => Ok(PathBuf::from("instances").join(seg)),
        _ => anyhow::bail!("Identifiant de serveur non normal : {:?}", server_id),
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "aether-mc-runner",
    about = "🪐 Runner & Installer de Serveurs Minecraft Haute Performance Aether",
    version = "1.0.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Télécharge et installe les composants spécifiés dans le manifest
    Install {
        /// Chemin local ou URL HTTP(S) vers le manifest JSON
        #[arg(short, long)]
        manifest: String,

        /// Répertoire cible de l'instance (par défaut: ./instances/<server_id>)
        #[arg(short, long)]
        dir: Option<PathBuf>,
    },

    /// Lance une instance Minecraft préalablement installée
    Run {
        /// Répertoire de l'instance contenant le fichier .aether-manifest.json
        #[arg(short, long)]
        dir: PathBuf,
    },

    /// Installe puis démarre immédiatement le serveur
    InstallAndRun {
        /// Chemin local ou URL HTTP(S) vers le manifest JSON
        #[arg(short, long)]
        manifest: String,

        /// Répertoire cible de l'instance
        #[arg(short, long)]
        dir: Option<PathBuf>,
    },

    /// Vérifie les prérequis de l'environnement (Java 21, connectivité, etc.)
    Doctor,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!(
        "{}",
        "🪐 AETHER MINECRAFT RUNNER & INSTALLER (Rust Tokio)"
            .bold()
            .cyan()
    );

    match cli.command {
        Commands::Install { manifest, dir } => {
            let m = ServerManifest::load(&manifest).await?;
            let target_dir = resolve_default_instance_dir(dir, &m.server_id)?;
            let installer = AetherInstaller::new(&target_dir);
            installer.install(&m).await?;
        }

        Commands::Run { dir } => {
            let manifest_path = dir.join(".aether-manifest.json");
            if !manifest_path.exists() {
                anyhow::bail!(
                    "Fichier .aether-manifest.json introuvable dans {}",
                    dir.display()
                );
            }
            let raw = tokio::fs::read_to_string(&manifest_path).await?;
            let m: ServerManifest = serde_json::from_str(&raw)?;
            let runner = AetherRunner::new(&dir);
            runner.run(&m).await?;
        }

        Commands::InstallAndRun { manifest, dir } => {
            let m = ServerManifest::load(&manifest).await?;
            let target_dir = resolve_default_instance_dir(dir, &m.server_id)?;
            let installer = AetherInstaller::new(&target_dir);
            installer.install(&m).await?;

            let runner = AetherRunner::new(&target_dir);
            runner.run(&m).await?;
        }

        Commands::Doctor => {
            println!("{}", "🩺 Diagnostic des prérequis Aether...".bold());

            // 1. Détection Java
            match AetherRunner::detect_java().await {
                Ok(_) => println!("  {} Runtime Java opérationnel", "✅".green()),
                Err(e) => println!("  {} Attention : {}", "⚠️".yellow(), e),
            }

            // 2. Test connectivité PaperMC
            let client = reqwest::Client::builder()
                .user_agent("Aether-MC-Runner/1.0")
                .timeout(std::time::Duration::from_secs(5))
                .build()?;
            match client.get("https://api.papermc.io/v2/projects").send().await {
                Ok(res) if res.status().is_success() => {
                    println!("  {} Connectivité PaperMC API : OK", "✅".green())
                }
                _ => println!("  {} Connectivité PaperMC API : Erreur ou hors-ligne", "⚠️".yellow()),
            }

            println!("{}", "Diagnostic terminé !".bold());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_server_id_accepts_valid_single_segments() {
        assert_eq!(validate_server_id("survival-1.21").unwrap(), "survival-1.21");
        assert_eq!(validate_server_id("lobby_01").unwrap(), "lobby_01");
        assert_eq!(validate_server_id("a").unwrap(), "a");
    }

    #[test]
    fn test_validate_server_id_rejects_traversal_and_absolute_inputs() {
        let invalid = [
            "",
            ".",
            "..",
            "../evil",
            "a/b",
            r"a\b",
            "/etc/passwd",
            r"\Windows",
            r"\\?\C:\Windows",
            r"\\server\share",
            "C:foo",
            r"C:\foo",
            "foo:bar",
            "bad\0id",
            "foo..bar",
        ];
        for case in invalid {
            assert!(
                validate_server_id(case).is_err(),
                "Expected validate_server_id({:?}) to fail",
                case
            );
            assert!(
                resolve_default_instance_dir(None, case).is_err(),
                "Expected resolve_default_instance_dir(None, {:?}) to fail",
                case
            );
        }
    }

    #[test]
    fn test_resolve_default_instance_dir_joins_instances_and_preserves_explicit_dir() {
        let default_dir = resolve_default_instance_dir(None, "survival-1.21").unwrap();
        assert_eq!(default_dir, PathBuf::from("instances").join("survival-1.21"));

        let explicit = PathBuf::from("/opt/mc-custom");
        let preserved = resolve_default_instance_dir(Some(explicit.clone()), "../ignored").unwrap();
        assert_eq!(preserved, explicit);
    }
}
