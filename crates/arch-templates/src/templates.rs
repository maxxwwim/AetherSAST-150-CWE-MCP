use core_graph::manifest::{GalaxyManifest, GuardrailSettings, ProjectManifest, StackType, TopologyMode};
use std::collections::HashMap;

pub struct ArchScaffolder;

impl ArchScaffolder {
    pub fn create_manifest(project_id: &str, stack: StackType, topology: TopologyMode) -> ProjectManifest {
        let mut galaxies = HashMap::new();

        match stack {
            StackType::PureRust => {
                galaxies.insert(
                    "contracts".to_string(),
                    GalaxyManifest {
                        path: "./contracts".to_string(),
                        role: "Common DTOs, wire types and API schemas".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "client".to_string(),
                    GalaxyManifest {
                        path: "./client".to_string(),
                        role: "Desktop/Web frontend view and state management".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "server".to_string(),
                    GalaxyManifest {
                        path: "./server".to_string(),
                        role: "Axum backend, domain logic and API routes".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "data-nodes".to_string(),
                    GalaxyManifest {
                        path: "./data-nodes".to_string(),
                        role: "SQLx / SeaORM migrations and database repositories".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
            }
            StackType::PurePythonUv => {
                galaxies.insert(
                    "contracts".to_string(),
                    GalaxyManifest {
                        path: "./contracts".to_string(),
                        role: "Pydantic v2 schemas and shared domain interfaces".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "client".to_string(),
                    GalaxyManifest {
                        path: "./client".to_string(),
                        role: "Streamlit / Reflex or frontend SPA".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "server".to_string(),
                    GalaxyManifest {
                        path: "./server".to_string(),
                        role: "FastAPI REST API, background workers and domain services".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "data-nodes".to_string(),
                    GalaxyManifest {
                        path: "./data-nodes".to_string(),
                        role: "SQLAlchemy 2 models, Alembic migrations and Redis cache".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
            }
            StackType::PureNodePnpm => {
                galaxies.insert(
                    "contracts".to_string(),
                    GalaxyManifest {
                        path: "./contracts".to_string(),
                        role: "Zod schemas, tRPC routers, API request/response types".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "client".to_string(),
                    GalaxyManifest {
                        path: "./client".to_string(),
                        role: "Next.js / Vite UI, components and client forms".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "server".to_string(),
                    GalaxyManifest {
                        path: "./server".to_string(),
                        role: "Hono / Fastify server, domain use-cases and WebSocket handlers".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "data-nodes".to_string(),
                    GalaxyManifest {
                        path: "./data-nodes".to_string(),
                        role: "Drizzle / Prisma schema, migrations and repositories".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
            }
            StackType::HybridMmoWeb3 => {
                galaxies.insert(
                    "contracts".to_string(),
                    GalaxyManifest {
                        path: "./contracts".to_string(),
                        role: "Smart contracts ABI, WebSocket packet definitions, shared types".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "client".to_string(),
                    GalaxyManifest {
                        path: "./client".to_string(),
                        role: "PixiJS / Svelte WebGL presentation, UI forms and local states".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "server".to_string(),
                    GalaxyManifest {
                        path: "./server".to_string(),
                        role: "Rust WebSocket high-concurrency game loop and domain services".to_string(),
                        remote_sync: topology == TopologyMode::Dissociated,
                        remote_endpoint: if topology == TopologyMode::Dissociated {
                            Some("wss://game-server.internal/aether-sync".to_string())
                        } else {
                            None
                        },
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "data-nodes".to_string(),
                    GalaxyManifest {
                        path: "./data-nodes".to_string(),
                        role: "PostgreSQL player state, Redis pub/sub and Web3 indexers".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
            }
            StackType::RobloxLuau => {
                galaxies.insert(
                    "contracts".to_string(),
                    GalaxyManifest {
                        path: "./contracts".to_string(),
                        role: "Shared Luau types, RemoteEvent/RemoteFunction definitions & EARS contracts".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "server".to_string(),
                    GalaxyManifest {
                        path: "./server".to_string(),
                        role: "Authoritative server loop, hit validation, anti-exploit & domain services".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "client".to_string(),
                    GalaxyManifest {
                        path: "./client".to_string(),
                        role: "Client controllers, local prediction, camera and UI interaction".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "data-nodes".to_string(),
                    GalaxyManifest {
                        path: "./data-nodes".to_string(),
                        role: "DataStoreService adapter, ProfileService session locking & auto-save".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
            }
            StackType::MinecraftServer => {
                galaxies.insert(
                    "contracts".to_string(),
                    GalaxyManifest {
                        path: "./contracts".to_string(),
                        role: "Plugin communication protocols, EARS specs and manifest contracts".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "server".to_string(),
                    GalaxyManifest {
                        path: "./server".to_string(),
                        role: "Paper/Purpur server configs, Aikar JVM scripts and engine tuning".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "plugins".to_string(),
                    GalaxyManifest {
                        path: "./plugins".to_string(),
                        role: "Paper/Spigot plugins, extensions and event handlers".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "data-nodes".to_string(),
                    GalaxyManifest {
                        path: "./data-nodes".to_string(),
                        role: "World saves, SQLite/MySQL player stores and backups".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
            }
            StackType::ClassicMvc => {
                galaxies.insert(
                    "models".to_string(),
                    GalaxyManifest {
                        path: "./models".to_string(),
                        role: "Domain entities, data transfer schemas and business models (M)".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "views".to_string(),
                    GalaxyManifest {
                        path: "./views".to_string(),
                        role: "UI templates, presentation components and client forms (V)".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "controllers".to_string(),
                    GalaxyManifest {
                        path: "./controllers".to_string(),
                        role: "Route handlers, request dispatchers and action controllers (C)".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "services".to_string(),
                    GalaxyManifest {
                        path: "./services".to_string(),
                        role: "Core domain services, pure logic and workflow orchestration".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
                galaxies.insert(
                    "data-nodes".to_string(),
                    GalaxyManifest {
                        path: "./data-nodes".to_string(),
                        role: "Database repositories, ORM migrations and cache stores".to_string(),
                        remote_sync: false,
                        remote_endpoint: None,
                        readme_blake3: None,
                    },
                );
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
