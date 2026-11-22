# AetherScope / aether-engine

Moteur interactif d'intelligence spatiale du code, d'analyse statique de sécurité (SAST) et de gouvernance cryptographique pour l'IA (`v2.6.0`).

<mark style="color:$primary;">**Bienvenue dans la documentation officielle de `aether-engine`.**</mark>

`aether-engine` (**AetherScope / AetherSAST**) est un workspace Rust local-first associé à un Cockpit WebGL 2. Il transforme vos dépôts polyglottes et vos coffres Obsidian en un graphe spatial interactif tout en appliquant des garde-fous déterministes d'architecture et de sécurité.

{% hint style="info" %}
**Version canonique :** `2.6.0` (`Cargo.toml`, `ui/package.json`, `mcp.json`). Publié sous licence **PolyForm Noncommercial 1.0.0** — consultez [Licence](license.md) pour les restrictions commerciales.
{% endhint %}

## Piliers principaux

| Pilier | Capacités de `aether-engine` | Explorer |
|---|---|---|
| **Graphe spatial et flux de données** | Analyse 11 langages en parallèle, projette les symboles et appels sur 4 dispositions (`Z-1`..`Z-4`), exécute un BFS inverse et trace le taint SSA. | [Moteur de graphe spatial](core/graph-engine.md) |
| **SAST, CWE et SCA atteignable** | Exécute **247 règles** (`223` natives + `24` Semgrep, dont `28` détecteurs inédits `AETHER-*`) avec masquage lexical, export SARIF v2.1.0 et atteignabilité OSV.dev. | [Moteur SAST et CWE](core/cwe-sast-engine.md) |
| **Gouvernance BLAKE3 et EARS** | Scelle les contrats `README.md` de chaque dossier dans `aether.lock.toml` via BLAKE3, contrôle les budgets de lignes et `forbidden_imports`, et analyse les clauses `WHEN ... THE SYSTEM SHALL ...`. | [Gouvernance BLAKE3 et contrats EARS](core/blake3-governance.md) |
| **Pare-feu de patch IA et MCP** | Valide chaque modification de code en moins de 50 ms via `PatchVerifier`, génère des paquets XML `<aether_handshake>`, applique `SecretGuard`/`SecretMasker` et expose 10 outils MCP natifs. | [Serveur MCP natif (aetherscope-mcp)](api-mcp/mcp-server.md) |
| **Plugins et Cockpit WebGL 2** | Recharge à chaud des plugins SAST/Taint DSL v2 en YAML et des thèmes GLSL ES 3.00 dans un cockpit WebGL 2 à 60 FPS accompagné d'un IDE multi-onglets plein écran. | [Cockpit spatial WebGL 2](cockpit-ide/webgl-cockpit.md) |
| **Dual-Vision Obsidian** | Classe automatiquement les projets en `PureCode`, `PureObsidianVault` ou `Mixed`, avec bascule instantanée entre graphe AST et graphe de notes (`Alt+V`). | [Coffre Obsidian et mode Dual-Vision](cockpit-ide/obsidian-dual-vision.md) |
| **Générateur et AetherCraft** | Génère 7 architectures multi-stack (`arch-templates`) et orchestre des serveurs Minecraft isolés via le panneau Flask `apps/aethercraft/` et `aether-mc-runner`. | [Générateur d'architecture multi-stack](extensions-dev/arch-scaffolder.md) |

## Navigation rapide

{% content-ref url="introduction.md" %}
[Introduction](introduction.md)
{% endcontent-ref %}

{% content-ref url="getting-started/installation.md" %}
[Installation](getting-started/installation.md)
{% endcontent-ref %}

{% content-ref url="getting-started/quickstart.md" %}
[Démarrage rapide](getting-started/quickstart.md)
{% endcontent-ref %}

{% content-ref url="architecture-overview.md" %}
[Vue d'ensemble de l'architecture](architecture-overview.md)
{% endcontent-ref %}

{% content-ref url="api-mcp/mcp-server.md" %}
[Serveur MCP natif (aetherscope-mcp)](api-mcp/mcp-server.md)
{% endcontent-ref %}

{% content-ref url="api-mcp/rest-api-overview.md" %}
[Vue d'ensemble de l'API REST](api-mcp/rest-api-overview.md)
{% endcontent-ref %}
