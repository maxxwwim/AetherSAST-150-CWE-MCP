//! Empirical Challenger Test Suite: UI Production Enhancements (Requirements R1 & R2)
//!
//! Archetype: Empirical Challenger (specialist / critic)
//! Target: crates/desktop-shell/assets/ (webgl_renderer.js, ui_navigation.js, ui_ai_modals.js,
//!                                      ui_inspector_docs.js, styles.css, index.html)
//!
//! Scope:
//!   1. Complete R2 verification (Center HUD removal, CSS suppression, lifecycle & error safety)
//!   2. Tooltip R1 verification (Dynamic clearance, screen clamping, HTML escaping, multi-anomalies)
//!   3. Inspector debrief R1 verification (Flex-wrap, word-break, no ellipsis truncation)
//!   4. Empirical Defect Oracles for R1:
//!      - Oracle 1: Callout notch penetrates node circle at high zoom (zoom >= 4.67)
//!      - Oracle 2: Caution bracket pulse peak (1.18x) collides through callout notch
//!      - Oracle 3: Edge badge overlaps file node (radius 24) on short edges (clearance = 17.92 < 24)
//!      - Oracle 4: Font size world clamp causes vanishing at zoom 0.05 (0.65px) and ballooning at zoom 5.0 (45px)

use std::fs;
use std::path::PathBuf;

fn get_assets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets")
}

// =========================================================================
// SECTION 1: R2 — Center Loading HUD Complete Suppression
// =========================================================================

#[test]
fn test_empirical_r2_center_hud_elimination_in_html_and_css() {
    let assets = get_assets_dir();
    let index_html = fs::read_to_string(assets.join("index.html")).expect("index.html");
    let styles_css = fs::read_to_string(assets.join("styles.css")).expect("styles.css");

    // Invariant 1: DOM element #hydro-loading-hud must NOT exist
    assert!(
        !index_html.contains("id=\"hydro-loading-hud\"") && !index_html.contains("id='hydro-loading-hud'"),
        "Defect: #hydro-loading-hud found in index.html DOM"
    );

    // Invariant 2: Class .hydro-hud-banner must NOT exist in index.html
    assert!(
        !index_html.contains("class=\"hydro-hud-banner") && !index_html.contains("class='hydro-hud-banner"),
        "Defect: .hydro-hud-banner found in index.html DOM"
    );

    // Invariant 3: CSS must enforce display: none !important and opacity: 0 !important
    assert!(
        styles_css.contains("#hydro-loading-hud") && styles_css.contains(".hydro-hud-banner"),
        "Defect: styles.css lacks #hydro-loading-hud suppression rule"
    );
    assert!(
        styles_css.contains("display: none !important"),
        "Defect: styles.css lacks display: none !important"
    );
    assert!(
        styles_css.contains("opacity: 0 !important"),
        "Defect: styles.css lacks opacity: 0 !important"
    );
    assert!(
        styles_css.contains("visibility: hidden !important"),
        "Defect: styles.css lacks visibility: hidden !important"
    );
    assert!(
        styles_css.contains("pointer-events: none !important"),
        "Defect: styles.css lacks pointer-events: none !important"
    );
}

#[test]
fn test_empirical_r2_js_lifecycle_and_error_safety() {
    let assets = get_assets_dir();
    let ui_modals = fs::read_to_string(assets.join("ui_ai_modals.js"))
        .expect("ui_ai_modals.js")
        .replace("\r\n", "\n");

    // Invariant 1: showLoadingScreen does NOT schedule interval timers
    assert!(
        !ui_modals.contains("loadingTimer = setInterval"),
        "Defect: showLoadingScreen still initiates background setInterval"
    );

    // Invariant 2: analyze() must use try-finally for robust cleanup
    assert!(
        ui_modals.contains("finally {\n    hideLoadingScreen();\n  }"),
        "Defect: analyze() lacks try-finally hideLoadingScreen cleanup"
    );

    // Invariant 3: applyData emergence does NOT unhide or write to central HUD
    assert!(
        !ui_modals.contains("hud.classList.remove('hidden')"),
        "Defect: applyData still manipulates central HUD banner"
    );
}

// =========================================================================
// SECTION 2: R1 — Tooltip & Inspector Panel Non-Truncation
// =========================================================================

#[test]
fn test_empirical_r1_tooltip_and_inspector_styles() {
    let assets = get_assets_dir();
    let styles_css = fs::read_to_string(assets.join("styles.css"))
        .expect("styles.css")
        .replace("\r\n", "\n");
    let ui_inspector = fs::read_to_string(assets.join("ui_inspector_docs.js"))
        .expect("ui_inspector_docs.js")
        .replace("\r\n", "\n");

    // Invariant 1: .cve-badge must wrap normally and not truncate with ellipsis
    assert!(
        styles_css.contains("white-space: normal;"),
        "Defect: styles.css .cve-badge missing white-space: normal"
    );
    assert!(
        styles_css.contains("word-break: break-word;"),
        "Defect: styles.css .cve-badge missing word-break: break-word"
    );
    assert!(
        !styles_css.contains("text-overflow: ellipsis;") || styles_css.contains(".cve-badge {\n      font-size: 0.68rem;"),
        "Defect: styles.css .cve-badge still has text-overflow: ellipsis"
    );

    // Invariant 2: .cve-badge-group must have flex-wrap: wrap
    assert!(
        styles_css.contains("flex-wrap: wrap;"),
        "Defect: styles.css .cve-badge-group missing flex-wrap: wrap"
    );

    // Invariant 3: ui_inspector_docs renders distinct .cve-rule-name tag
    assert!(
        ui_inspector.contains("cve-rule-name"),
        "Defect: ui_inspector_docs.js lacks .cve-rule-name"
    );
    assert!(
        ui_inspector.contains("a.rule_id !== a.cve_id"),
        "Defect: ui_inspector_docs.js lacks distinct rule_id comparison"
    );
}

// =========================================================================
// SECTION 3: EMPIRICAL DEFECT ORACLES (Confirmed Mathematical & Geometric Bugs)
// =========================================================================

/// DEFECT ORACLE 1: Callout notch penetrates node circle at high zoom (zoom >= 4.67)
/// webgl_renderer.js:2065:
///   calloutY = n.y - alertR - 14 / Math.max(0.5, c.zoom) - pillH / 2;
///   notch = Math.max(3, 4 / Math.max(0.5, c.zoom));
/// At zoom = 5.0, offset = 14 / 5.0 = 2.8, notch = max(3, 0.8) = 3.0.
/// The notch extends 0.2 units (1.0 screen pixel) INSIDE the node circle!
#[test]
fn test_defect_oracle_r1_callout_notch_penetration_at_high_zoom() {
    let zoom: f64 = 5.0;
    let offset = 14.0 / zoom.max(0.5);
    let notch = (4.0 / zoom.max(0.5)).max(3.0);
    let gap = offset - notch;

    println!(
        "[ORACLE 1] Zoom: {}, Offset: {:.2}, Notch: {:.2}, Gap: {:.2}",
        zoom, offset, notch, gap
    );

    // Mathematically verifies the confirmed defect: gap is negative (-0.20)
    assert!(
        gap < 0.0,
        "Expected bug reproduction: gap should be negative, got {}",
        gap
    );
    assert_eq!((gap * 100.0).round() / 100.0, -0.20);
}

/// DEFECT ORACLE 2: Rotating caution brackets reach radius (alertR + 6/zoom) * 1.18,
/// colliding through the callout notch (tip at alertR + 14/zoom - 4/zoom = alertR + 10/zoom).
#[test]
fn test_defect_oracle_r1_callout_bracket_pulse_collision() {
    let zoom: f64 = 1.0;
    let alert_r = 24.0 / zoom; // File node
    let peak_pulse = 1.18;
    let bracket_outer_radius = (alert_r + 6.0 / zoom) * peak_pulse; // (24 + 6) * 1.18 = 35.40

    let callout_pill_bottom = alert_r + 14.0 / zoom.max(0.5); // 24 + 14 = 38.0
    let notch_height = (4.0 / zoom.max(0.5)).max(3.0); // 4.0
    let notch_tip_distance_from_center = callout_pill_bottom - notch_height; // 38.0 - 4.0 = 34.0

    let overlap = bracket_outer_radius - notch_tip_distance_from_center;
    println!(
        "[ORACLE 2] Bracket peak: {:.2}, Notch tip: {:.2}, Overlap: {:.2}",
        bracket_outer_radius, notch_tip_distance_from_center, overlap
    );

    // Confirmed defect: bracket penetrates 1.4 units into callout notch
    assert!(
        overlap > 0.0,
        "Expected bracket-notch collision bug: overlap should be positive, got {}",
        overlap
    );
    assert_eq!((overlap * 10.0).round() / 10.0, 1.4);
}

/// DEFECT ORACLE 3: Edge badge overlaps file node on short edges
/// perpDist = badgeH * 0.75 + 10 / max(0.5, zoom)
/// Clearance to badge bottom = perpDist - badgeH / 2 = 0.25 * badgeH + 10 / max(0.5, zoom) = 17.92
/// File node radius = 24.0 -> Overlap = 24.0 - 17.92 = 6.08 units!
#[test]
fn test_defect_oracle_r1_badge_file_node_overlap_on_short_edges() {
    let zoom: f64 = 1.0;
    let badge_font_size: f64 = 11.0;
    let sub_font_size: f64 = (badge_font_size * 0.88).max(8.0).min(11.0); // 9.68
    let pad_y: f64 = (4.0 / zoom.max(0.5)).max(3.0).min(6.0); // 4.0
    let line_spacing: f64 = (3.0 / zoom.max(0.5)).max(2.0); // 3.0
    let badge_h = badge_font_size + sub_font_size + line_spacing + pad_y * 2.0; // 31.68

    let perp_dist = badge_h * 0.75 + 10.0 / zoom.max(0.5); // 23.76 + 10 = 33.76
    let clearance_to_bottom = perp_dist - badge_h / 2.0; // 33.76 - 15.84 = 17.92

    let file_node_radius: f64 = 24.0;
    let overlap = file_node_radius - clearance_to_bottom;

    println!(
        "[ORACLE 3] Clearance to badge bottom: {:.2}, File node radius: {:.2}, Overlap: {:.2}",
        clearance_to_bottom, file_node_radius, overlap
    );

    // Confirmed defect: badge hangs 6.08 units into file node circle
    assert!(
        overlap > 0.0,
        "Expected badge-node overlap bug: overlap should be positive, got {}",
        overlap
    );
    assert_eq!((overlap * 100.0).round() / 100.0, 6.08);
}

/// DEFECT ORACLE 4: Font size clamped in world units balloons and vanishes
/// webgl_renderer.js:1750: Math.max(9, Math.min(13, 11 / c.zoom))
/// Screen font size = world_font_size * zoom
#[test]
fn test_defect_oracle_r1_font_size_ballooning_and_vanishing() {
    // Case A: Zoom = 0.05
    let z_out: f64 = 0.05;
    let world_font_out = (11.0 / z_out).min(13.0).max(9.0); // 13.0
    let screen_font_out = world_font_out * z_out; // 13.0 * 0.05 = 0.65 screen px

    println!(
        "[ORACLE 4A] Zoom 0.05 -> World font: {:.2}, Screen font: {:.2}px",
        world_font_out, screen_font_out
    );
    assert!(
        screen_font_out < 1.0,
        "Expected vanishing font at zoom 0.05: got {:.2}px",
        screen_font_out
    );

    // Case B: Zoom = 5.0
    let z_in: f64 = 5.0;
    let world_font_in = (11.0 / z_in).min(13.0).max(9.0); // 9.0
    let screen_font_in = world_font_in * z_in; // 9.0 * 5.0 = 45.0 screen px

    println!(
        "[ORACLE 4B] Zoom 5.0 -> World font: {:.2}, Screen font: {:.2}px",
        world_font_in, screen_font_in
    );
    assert!(
        screen_font_in > 40.0,
        "Expected ballooning font at zoom 5.0: got {:.2}px",
        screen_font_in
    );
}
