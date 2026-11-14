#![recursion_limit = "512"]
mod mcp;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "AetherScope V2.4 - Dedicated MCP Server for AI Agents", long_about = None)]
pub struct Args {
    #[arg(short, long, default_value = ".")]
    pub path: String,

    #[arg(long, default_value_t = 3030)]
    pub port: u16,

    #[arg(long, default_value_t = false)]
    pub mcp: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let port = args.port;
    let path = args.path.clone();

    if !mcp::check_server_listening(port) {
        eprintln!("📡 [AetherScope MCP] Serveur non detecte sur le port {}. Demarrage automatique du backend Axum...", port);
        let current_exe_opt = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|dir| dir.join("aether-engine.exe")))
            .filter(|p| p.exists());

        if let Some(current_exe_bin) = current_exe_opt {
            let _ = std::process::Command::new(current_exe_bin)
                .arg("--no-gui")
                .arg("--port")
                .arg(port.to_string())
                .arg("--path")
                .arg(&path)
                .spawn();
            for _ in 0..10 {
                tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
                if mcp::check_server_listening(port) {
                    eprintln!("📡 [AetherScope MCP] Backend demarre avec succes sur http://127.0.0.1:{}", port);
                    break;
                }
            }
        }
    } else {
        eprintln!("📡 [AetherScope MCP] Connecte a l'instance active AetherScope sur http://127.0.0.1:{}", port);
    }

    mcp::run_mcp_stdio_loop(port, &path).await
}
