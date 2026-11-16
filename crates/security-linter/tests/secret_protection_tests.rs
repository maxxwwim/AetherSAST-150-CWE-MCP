use security_linter::{SecretGuard, SecretMasker};
use std::path::Path;

#[test]
fn test_secret_guard_detects_all_env_variants() {
    let env_cases = [
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.staging",
        ".env.test",
        "subfolder/.env",
        "nested/deep/path/.env.production",
        "frontend/.env.local",
        "app.env",
        "deploy.env",
        "custom_config.env",
        ".envrc",
        ".envrc.local",
        "sub/.envrc",
    ];

    for path in &env_cases {
        assert!(
            SecretGuard::is_secret_path(path),
            "Expected SecretGuard to detect env file: {}",
            path
        );
        assert!(
            SecretGuard::is_secret_path(Path::new(path)),
            "Expected SecretGuard to detect Path: {}",
            path
        );
    }
}

#[test]
fn test_secret_guard_detects_sensitive_directories() {
    let dir_cases = [
        ".git/config",
        ".git/HEAD",
        ".ssh/id_rsa",
        ".ssh/config",
        ".aws/credentials",
        ".aws/config",
        ".azure/azureProfile.json",
        ".gcloud/credentials.db",
        ".kube/config",
        ".docker/config.json",
        ".gnupg/pubring.kbx",
        "secrets/app_secrets.json",
        ".secrets/vault_key.txt",
        "credentials/oauth.json",
        ".credentials/tokens.json",
        "C:\\Users\\dev\\.ssh\\id_ed25519",
        "C:/Users/dev/.aws/credentials",
    ];

    for path in &dir_cases {
        assert!(
            SecretGuard::is_secret_path(path),
            "Expected SecretGuard to detect sensitive directory path: {}",
            path
        );
    }
}

#[test]
fn test_secret_guard_detects_sensitive_files() {
    let file_cases = [
        "credentials",
        "credentials.json",
        "credentials.toml",
        "secrets",
        "secrets.json",
        "secrets.yaml",
        "secret.txt",
        "service-account.json",
        "service_account.json",
        "master.key",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".htpasswd",
        "authorized_keys",
        "known_hosts",
        "passwd",
        "/etc/passwd",
        "/etc/shadow",
        "win.ini",
        "system.ini",
    ];

    for path in &file_cases {
        assert!(
            SecretGuard::is_secret_path(path),
            "Expected SecretGuard to detect sensitive file: {}",
            path
        );
    }
}

#[test]
fn test_secret_guard_detects_private_keys_and_crypto_extensions() {
    let key_cases = [
        "id_rsa",
        "id_rsa.pub",
        "id_ed25519",
        "id_ed25519.pub",
        "id_ecdsa",
        "id_dsa",
        "certs/server.pem",
        "keys/private.key",
        "ssl/cert.p12",
        "certs/bundle.pfx",
        "auth/client.pkcs12",
        "vault.kdbx",
        "ca.der",
        "domain.crt",
        "ca.cer",
        "server.jks",
        "app.keystore",
    ];

    for path in &key_cases {
        assert!(
            SecretGuard::is_secret_path(path),
            "Expected SecretGuard to detect key or crypto extension: {}",
            path
        );
    }
}

#[test]
fn test_secret_guard_allows_safe_source_files() {
    let safe_cases = [
        "src/main.rs",
        "src/lib.rs",
        "crates/desktop-shell/ui/src/App.svelte",
        "package.json",
        "Cargo.toml",
        "README.md",
        "docs/ARCHITECTURE.md",
        "services/payment_service.rs",
        "utils/environment_helper.ts",
        "tests/integration_tests.rs",
        "styles/theme.css",
    ];

    for path in &safe_cases {
        assert!(
            !SecretGuard::is_secret_path(path),
            "Expected SecretGuard to allow safe file: {}",
            path
        );
    }
}

#[test]
fn test_secret_masker_openai_anthropic_gemini() {
    let dummy_openai = ["sk", "proj", "1234567890abcdef1234567890"].join("-");
    let dummy_anthropic = ["sk", "ant", "api03", "abcdefghijklmnopqrstuvwxyz12345"].join("-");
    let input = format!("Calling model with api_key: {dummy_openai} and fallback {dummy_anthropic}");
    let masked = SecretMasker::mask_text(&input);
    assert!(!masked.contains(&dummy_openai));
    assert!(!masked.contains(&dummy_anthropic));
    assert!(masked.contains("sk-***[REDACTED]***"));
    assert!(SecretMasker::contains_secret(&input));
}

#[test]
fn test_secret_masker_github_tokens() {
    let dummy_classic = ["ghp", "1234567890abcdefghijklmnopqrstuvwxyz"].join("_");
    let dummy_fine = ["github", "pat", "11A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z71234567890"].join("_");
    let dummy_oauth = ["gho", "1234567890abcdefghijklmnopqrstuvwxyz"].join("_");

    let classic = format!("Authorization: token {dummy_classic}");
    let fine_grained = format!("Token: {dummy_fine}");
    let oauth = format!("Bearer {dummy_oauth}");

    assert_eq!(
        SecretMasker::mask_text(&classic),
        "Authorization: token ghp_***[REDACTED]***"
    );
    assert_eq!(
        SecretMasker::mask_text(&fine_grained),
        "Token: github_pat_***[REDACTED]***"
    );
    assert_eq!(
        SecretMasker::mask_text(&oauth),
        "Bearer gh***[REDACTED]***"
    );
}

#[test]
fn test_secret_masker_aws_access_key() {
    let dummy_aws = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    let input = format!("AWS_ACCESS_KEY_ID = {dummy_aws}");
    let masked = SecretMasker::mask_text(&input);
    assert!(!masked.contains(&dummy_aws));
    assert!(masked.contains("AKIA***[REDACTED]***"));
}

#[test]
fn test_secret_masker_stripe_and_slack() {
    let dummy_stripe = ["sk", "live", "51AbCdEfGhIjKlMnOpQrStUvWxYz123456"].join("_");
    let dummy_slack = ["xoxb", "123456789012", "1234567890123", "abcdefghijklmnopqrstuvwx"].join("-");

    let stripe = format!("const stripe = require('stripe')('{dummy_stripe}');");
    let slack = format!("const token = '{dummy_slack}';");

    let masked_stripe = SecretMasker::mask_text(&stripe);
    let masked_slack = SecretMasker::mask_text(&slack);

    assert!(!masked_stripe.contains(&dummy_stripe));
    assert!(masked_stripe.contains("sk_live_***[REDACTED]***"));

    assert!(!masked_slack.contains(&dummy_slack));
    assert!(masked_slack.contains("xox-***[REDACTED]***"));
}

#[test]
fn test_secret_masker_private_key_block() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y1234567890abcdef\nMIICXAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
    let masked = SecretMasker::mask_text(pem);
    assert_eq!(masked, "[PRIVATE_KEY_BLOCK_REDACTED]");
    assert!(SecretMasker::contains_secret(pem));
}

#[test]
fn test_secret_masker_jwt() {
    let jwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let masked = SecretMasker::mask_text(jwt);
    assert!(!masked.contains("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"));
    assert!(masked.contains("ey***[JWT_REDACTED]***"));
}

#[test]
fn test_secret_masker_database_uri() {
    let uri = "DATABASE_URL=postgres://app_user:SuperSecretPassword123@db.internal:5432/main_db";
    let masked = SecretMasker::mask_text(uri);
    assert!(!masked.contains("SuperSecretPassword123"));
    assert!(masked.contains("postgres://app_user:***@db.internal:5432/main_db"));
}

#[test]
fn test_secret_masker_generic_assignments() {
    let code = r#"
        PASSWORD = "ultra_secret_master_password!"
        SECRET_KEY = 'super_secret_jwt_hmac_signing_key'
        api_secret: "prod_api_secret_998877"
    "#;
    let masked = SecretMasker::mask_text(code);
    assert!(!masked.contains("ultra_secret_master_password!"));
    assert!(!masked.contains("super_secret_jwt_hmac_signing_key"));
    assert!(!masked.contains("prod_api_secret_998877"));
    assert!(masked.contains("PASSWORD = \"******** [REDACTED]\""));
}

#[test]
fn test_secret_masker_clean_text_unchanged() {
    let safe_text = "fn calculate_total(price: f64, quantity: u32) -> f64 {\n    price * (quantity as f64)\n}";
    let masked = SecretMasker::mask_text(safe_text);
    assert_eq!(safe_text, masked);
    assert!(!SecretMasker::contains_secret(safe_text));
}
