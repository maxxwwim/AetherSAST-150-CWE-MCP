use core_graph::manifest::{GalaxyManifest, GuardrailSettings, ProjectManifest, StackType, TopologyMode};
use std::collections::HashMap;

fn gm(path: &str, role: &str) -> GalaxyManifest {
    GalaxyManifest {
        path: path.to_string(),
        role: role.to_string(),
        remote_sync: false,
        remote_endpoint: None,
        readme_blake3: None,
    }
}

pub struct ArchScaffolder;

impl ArchScaffolder {
    pub fn create_manifest(project_id: &str, stack: StackType, topology: TopologyMode) -> ProjectManifest {
        let mut galaxies = HashMap::new();
        let mut add = |name: &str, path: &str, role: &str| {
            galaxies.insert(name.to_string(), gm(path, role));
        };

        match stack {
            StackType::PureRust => {
                add("contracts", "./contracts", "Common DTOs, wire types and API schemas");
                add("client", "./client", "Desktop/Web frontend view and state management");
                add("server", "./server", "Axum backend, domain logic and API routes");
                add("data-nodes", "./data-nodes", "SQLx / SeaORM migrations and database repositories");
            }
            StackType::PurePythonUv => {
                add("contracts", "./contracts", "Pydantic v2 schemas and shared domain interfaces");
                add("client", "./client", "Streamlit / Reflex or frontend SPA");
                add("server", "./server", "FastAPI REST API, background workers and domain services");
                add("data-nodes", "./data-nodes", "SQLAlchemy 2 models, Alembic migrations and Redis cache");
            }
            StackType::PureNodePnpm => {
                add("contracts", "./contracts", "Zod schemas, tRPC routers, API request/response types");
                add("client", "./client", "Next.js / Vite UI, components and client forms");
                add("server", "./server", "Hono / Fastify server, domain use-cases and WebSocket handlers");
                add("data-nodes", "./data-nodes", "Drizzle / Prisma schema, migrations and repositories");
            }
            StackType::HybridMmoWeb3 => {
                add("contracts", "./contracts", "Smart contracts ABI, WebSocket packet definitions, shared types");
                add("client", "./client", "PixiJS / Svelte WebGL presentation, UI forms and local states");
                add("data-nodes", "./data-nodes", "PostgreSQL player state, Redis pub/sub and Web3 indexers");
                let mut srv = gm("./server", "Rust WebSocket high-concurrency game loop and domain services");
                if topology == TopologyMode::Dissociated {
                    srv.remote_sync = true;
                    srv.remote_endpoint = Some("wss://game-server.internal/aether-sync".to_string());
                }
                galaxies.insert("server".to_string(), srv);
            }
            StackType::RobloxLuau => {
                add("contracts", "./contracts", "Shared Luau types, RemoteEvent/RemoteFunction definitions & EARS contracts");
                add("server", "./server", "Authoritative server loop, hit validation, anti-exploit & domain services");
                add("client", "./client", "Client controllers, local prediction, camera and UI interaction");
                add("data-nodes", "./data-nodes", "DataStoreService adapter, ProfileService session locking & auto-save");
            }
            StackType::MinecraftServer => {
                add("contracts", "./contracts", "Plugin communication protocols, EARS specs and manifest contracts");
                add("server", "./server", "Paper/Purpur server configs, Aikar JVM scripts and engine tuning");
                add("plugins", "./plugins", "Paper/Spigot plugins, extensions and event handlers");
                add("data-nodes", "./data-nodes", "World saves, SQLite/MySQL player stores and backups");
            }
            StackType::ClassicMvc => {
                add("models", "./models", "Domain entities, data transfer schemas and business models (M)");
                add("views", "./views", "UI templates, presentation components and client forms (V)");
                add("controllers", "./controllers", "Route handlers, request dispatchers and action controllers (C)");
                add("services", "./services", "Core domain services, pure logic and workflow orchestration");
                add("data-nodes", "./data-nodes", "Database repositories, ORM migrations and cache stores");
            }
        }

        ProjectManifest {
            version: 2,
            project_id: project_id.to_string(),
            stack_type: stack,
            topology_mode: topology,
            galaxies,
            guardrails: GuardrailSettings::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roblox_and_minecraft_manifests() {
        let roblox = ArchScaffolder::create_manifest("RobloxGame", StackType::RobloxLuau, TopologyMode::MonorepoLocal);
        assert_eq!(roblox.galaxies.len(), 4);
        assert!(roblox.galaxies.contains_key("contracts"));
        assert!(roblox.galaxies.contains_key("server"));
        assert!(roblox.galaxies.contains_key("client"));
        assert!(roblox.galaxies.contains_key("data-nodes"));

        let mvc = ArchScaffolder::create_manifest("MvcApp", StackType::ClassicMvc, TopologyMode::MonorepoLocal);
        assert_eq!(mvc.galaxies.len(), 5);
        assert!(mvc.galaxies.contains_key("models"));
        assert!(mvc.galaxies.contains_key("views"));
        assert!(mvc.galaxies.contains_key("controllers"));
        assert!(mvc.galaxies.contains_key("services"));
        assert!(mvc.galaxies.contains_key("data-nodes"));

        let mc = ArchScaffolder::create_manifest("McServer", StackType::MinecraftServer, TopologyMode::MonorepoLocal);
        assert_eq!(mc.galaxies.len(), 4);
        assert!(mc.galaxies.contains_key("contracts"));
        assert!(mc.galaxies.contains_key("server"));
        assert!(mc.galaxies.contains_key("plugins"));
        assert!(mc.galaxies.contains_key("data-nodes"));
    }
}
