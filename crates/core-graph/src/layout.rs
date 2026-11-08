use crate::bubble::{Point2D, SymbolBubble};
use std::collections::HashMap;

const GOLDEN_ANGLE: f64 = 2.399_963_229_728_653; // ~137.507764 degrees

pub fn compute_all_layouts(nodes: &mut [SymbolBubble]) {
    if nodes.is_empty() {
        return;
    }

    compute_obsidian_layout(nodes);
    compute_system_layout(nodes);
    compute_flow_layout(nodes);
    compute_classes_layout(nodes);

    // Initial default position = Obsidian
    for n in nodes.iter_mut() {
        if let Some(obs) = n.layouts.obsidian {
            n.x = obs.x;
            n.y = obs.y;
        }
    }
}

/// 1. Z-1 : Obsidian Galaxy (Clusters nébuleux arborescents mass-aware)
/// Structure les dossiers selon l'arborescence réelle des fichiers sur disque,
/// garantit un espacement proportionnel à la masse des amas et élimine l'empilement au cœur.
pub fn compute_obsidian_layout(nodes: &mut [SymbolBubble]) {
    let mut dir_groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, n) in nodes.iter().enumerate() {
        let clean_path = n.file_path.replace('\\', "/");
        let parts: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();
        let dir = if !n.folder.is_empty() {
            n.folder.replace('\\', "/").trim_matches('/').to_string()
        } else if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            "root".to_string()
        };
        dir_groups.entry(dir).or_default().push(idx);
    }

    // Helper: extrait la branche architecturale parente (ex: crates/desktop-shell, apps/aethercraft)
    let get_branch = |dir: &str| -> (String, String) {
        let clean = dir.trim_matches('/');
        if clean.is_empty() || clean == "root" {
            return ("root".to_string(), String::new());
        }
        let parts: Vec<&str> = clean.split('/').collect();
        if parts.len() >= 2 && (parts[0] == "crates" || parts[0] == "apps" || parts[0] == "packages") {
            let branch = format!("{}/{}", parts[0], parts[1]);
            let sub = if parts.len() > 2 { parts[2..].join("/") } else { String::new() };
            (branch, sub)
        } else if !parts.is_empty() {
            let branch = parts[0].to_string();
            let sub = if parts.len() > 1 { parts[1..].join("/") } else { String::new() };
            (branch, sub)
        } else {
            ("root".to_string(), String::new())
        }
    };

    struct FolderInfo {
        _name: String,
        sub: String,
        indices: Vec<usize>,
        radius: f64,
    }

    struct BranchInfo {
        name: String,
        folders: Vec<FolderInfo>,
        _total_nodes: usize,
        envelope_r: f64,
    }

    let mut branch_map: HashMap<String, Vec<FolderInfo>> = HashMap::new();
    for (dir_name, indices) in dir_groups {
        let (branch, sub) = get_branch(&dir_name);
        let n_len = indices.len();
        // Rayon cellulaire dynamique généreux proportionnel au nombre de symboles
        let radius = ((n_len as f64).sqrt() * 78.0 + 75.0).clamp(120.0, 780.0);
        branch_map.entry(branch).or_default().push(FolderInfo {
            _name: dir_name,
            sub,
            indices,
            radius,
        });
    }

    let mut branches: Vec<BranchInfo> = branch_map
        .into_iter()
        .map(|(name, mut folders)| {
            // Tri des sous-dossiers : le dossier racine du module en premier, puis alphabétique
            folders.sort_by(|a, b| {
                if a.sub.is_empty() && !b.sub.is_empty() {
                    std::cmp::Ordering::Less
                } else if !a.sub.is_empty() && b.sub.is_empty() {
                    std::cmp::Ordering::Greater
                } else {
                    a.sub.cmp(&b.sub)
                }
            });
            let total_nodes: usize = folders.iter().map(|f| f.indices.len()).sum();
            let sum_r: f64 = folders.iter().map(|f| f.radius).sum();
            let envelope_r = if folders.len() == 1 {
                folders[0].radius + 80.0
            } else {
                (sum_r * 0.62 + 200.0).max(folders[0].radius + 150.0)
            };
            BranchInfo {
                name,
                folders,
                _total_nodes: total_nodes,
                envelope_r,
            }
        })
        .collect();

    // Tri déterministe des branches principales
    branches.sort_by(|a, b| a.name.cmp(&b.name));

    let num_branches = branches.len();
    if num_branches == 0 {
        return;
    }

    // Calcul de la distance orbitale globale pour garantir un espacement net entre les grands amas
    let max_envelope = branches.iter().map(|b| b.envelope_r).fold(0.0, f64::max);
    let avg_envelope: f64 = branches.iter().map(|b| b.envelope_r).sum::<f64>() / num_branches as f64;
    let base_orbit = if num_branches <= 2 {
        max_envelope + 450.0
    } else {
        let angle_step = std::f64::consts::TAU / num_branches as f64;
        let chord_needed = avg_envelope * 2.0 + 480.0;
        let min_d = chord_needed / (2.0 * (angle_step * 0.5).sin()).max(0.15);
        min_d.max(1050.0)
    };

    for (b_idx, branch) in branches.into_iter().enumerate() {
        let (branch_cx, branch_cy, branch_angle) = if num_branches == 1 {
            (0.0, 0.0, 0.0)
        } else {
            let angle = (b_idx as f64 * std::f64::consts::TAU / num_branches as f64) - std::f64::consts::FRAC_PI_2;
            // Étalement alterné léger pour les branches volumineuses (staggering)
            let orbit_dist = if num_branches > 6 && b_idx % 2 == 1 {
                base_orbit * 1.28
            } else {
                base_orbit
            };
            (angle.cos() * orbit_dist, angle.sin() * orbit_dist, angle)
        };

        let num_folders = branch.folders.len();
        let root_r = branch.folders[0].radius;

        for (f_idx, folder) in branch.folders.into_iter().enumerate() {
            // Placement arborescent du dossier au sein de sa branche
            let (fcx, fcy) = if f_idx == 0 {
                // Dossier primaire du module à l'ancre de la branche
                (branch_cx, branch_cy)
            } else {
                // Sous-dossiers déployés en satellites rayonnants autour du dossier parent
                let sub_offset_idx = f_idx as f64;
                let sub_angle_spread = 0.68;
                let sub_angle = branch_angle
                    + (sub_offset_idx - (num_folders as f64 * 0.5)) * sub_angle_spread;
                let sub_dist = root_r + folder.radius + 140.0 + (sub_offset_idx - 1.0) * 80.0;
                (
                    branch_cx + sub_angle.cos() * sub_dist,
                    branch_cy + sub_angle.sin() * sub_dist,
                )
            };

            let n_len = folder.indices.len();
            for (i, &n_idx) in folder.indices.iter().enumerate() {
                let (node_dist, node_angle) = if n_len <= 1 {
                    (0.0, 0.0)
                } else {
                    // Dégagement central ferme (r0 = 38px) : aucune bulle ne se superpose au barycentre
                    let t = (i as f64 + 0.6) / n_len as f64;
                    let dist = 38.0 + t.sqrt() * (folder.radius - 42.0);
                    let angle = i as f64 * GOLDEN_ANGLE;
                    (dist, angle)
                };

                nodes[n_idx].layouts.obsidian = Some(Point2D::new(
                    (fcx + node_angle.cos() * node_dist).round(),
                    (fcy + node_angle.sin() * node_dist).round(),
                ));
            }
        }
    }
}

/// 2. Z-2 : Architecture Système (Constellations équilibrées par couches hiérarchiques)
pub fn compute_system_layout(nodes: &mut [SymbolBubble]) {
    let layer_tiers: HashMap<&str, f64> = [
        ("docs", -1050.0),
        ("ui", -760.0),
        ("action", -300.0),
        ("domain", 260.0),
        ("database", 820.0),
        ("config", -530.0),
        ("utility", 540.0),
    ]
    .into_iter()
    .collect();

    let mut layer_groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, n) in nodes.iter().enumerate() {
        layer_groups.entry(n.layer.clone()).or_default().push(idx);
    }

    for (layer, indices) in layer_groups {
        let base_x = layer_tiers.get(layer.as_str()).copied().unwrap_or(0.0);
        let count = indices.len();
        let sub_cols = ((count as f64).sqrt() * 0.7).ceil().max(1.0) as usize;

        for (idx, &n_idx) in indices.iter().enumerate() {
            let col = idx % sub_cols;
            let row = idx / sub_cols;
            let total_rows = (count + sub_cols - 1) / sub_cols;

            let x = base_x + (col as f64 - (sub_cols - 1) as f64 / 2.0) * 95.0;
            let y = (row as f64 - total_rows as f64 / 2.0) * 105.0;

            nodes[n_idx].layouts.system = Some(Point2D::new(x.round(), y.round()));
        }
    }
}

/// 3. Z-3 : Flux d'Exécution DAG (Horizontal par étapes de pipeline)
pub fn compute_flow_layout(nodes: &mut [SymbolBubble]) {
    let mut stage_groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for (idx, n) in nodes.iter().enumerate() {
        stage_groups.entry(n.stage_idx).or_default().push(idx);
    }

    for stage_idx in 0..4 {
        if let Some(indices) = stage_groups.get(&stage_idx) {
            let stage_x = (stage_idx as f64 - 1.5) * 560.0;
            let count = indices.len();
            let sub_cols = ((count as f64).sqrt() * 0.6).ceil().max(1.0) as usize;

            for (idx, &n_idx) in indices.iter().enumerate() {
                let col = idx % sub_cols;
                let row = idx / sub_cols;
                let total_rows = (count + sub_cols - 1) / sub_cols;

                let x = stage_x + (col as f64 - (sub_cols - 1) as f64 / 2.0) * 90.0;
                let y = (row as f64 - total_rows as f64 / 2.0) * 100.0;

                nodes[n_idx].layouts.flow = Some(Point2D::new(x.round(), y.round()));
            }
        }
    }
}

/// 4. Z-4 : Classes & Composants UML (Grille planétaire matricielle)
pub fn compute_classes_layout(nodes: &mut [SymbolBubble]) {
    let total_nodes = nodes.len();
    if total_nodes == 0 {
        return;
    }
    let cols = ((total_nodes as f64 * 1.4).sqrt().ceil() as usize).max(2);
    let spacing_x = 340.0;
    let spacing_y = 160.0;

    for idx in 0..total_nodes {
        let r = idx / cols;
        let c = idx % cols;
        let x = (c as f64 - cols as f64 / 2.0) * spacing_x;
        let y = (r as f64 - (total_nodes / cols) as f64 / 2.0) * spacing_y;

        nodes[idx].layouts.classes = Some(Point2D::new(x.round(), y.round()));
    }
}
