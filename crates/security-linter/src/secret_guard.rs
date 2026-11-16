use std::path::Path;

/// Guardian against sensitive files, environment configs, credentials, and private keys.
///
/// Prevents AI agents, MCP endpoints, and file analyzers from accessing or exfiltrating
/// sensitive project configurations and secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecretGuard;

impl SecretGuard {
    /// Comprehensive check for sensitive files, credentials, secrets, and private keys.
    ///
    /// Detects:
    /// - `.env`, `.env.*`, `*.env`, `.envrc`, `.envrc.*`
    /// - Sensitive directories: `.git`, `.ssh`, `.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.gnupg`, `secrets`, `.secrets`, `credentials`, `.credentials`
    /// - Sensitive files: `credentials`, `secrets`, `service-account.json`, `master.key`, `.npmrc`, `.pypirc`, `.netrc`, `.htpasswd`, `authorized_keys`, `known_hosts`, `passwd`, `shadow`, `sudoers`, `win.ini`, `system.ini`, `sam`
    /// - Private keys / identities: `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`
    /// - Secret / crypto extensions: `.pem`, `.key`, `.p12`, `.pfx`, `.pkcs12`, `.kdbx`, `.der`, `.crt`, `.cer`, `.jks`, `.keystore`
    pub fn is_secret_path<P: AsRef<Path>>(path: P) -> bool {
        let p = path.as_ref();
        let full_str = p.to_string_lossy().to_lowercase().replace('\\', "/");
        let trimmed_full = full_str.trim_start_matches("./");

        // 1. Root & System sensitive paths
        if trimmed_full.contains("etc/passwd")
            || trimmed_full.contains("etc/shadow")
            || trimmed_full.contains("etc/sudoers")
            || trimmed_full.contains("windows/system32")
            || trimmed_full.contains("system32/config")
            || trimmed_full == "win.ini"
            || trimmed_full.ends_with("/win.ini")
            || trimmed_full == "system.ini"
            || trimmed_full.ends_with("/system.ini")
        {
            return true;
        }

        // 2. Component inspection
        for comp in p.components() {
            let s = comp.as_os_str().to_string_lossy().to_lowercase();
            let c = s.trim();

            // Environment variations (.env, .env.*, *.env, .envrc, .envrc.*)
            if c == ".env"
                || c.starts_with(".env.")
                || c.ends_with(".env")
                || c == ".envrc"
                || c.starts_with(".envrc.")
            {
                return true;
            }

            // Sensitive directories
            if matches!(
                c,
                ".git"
                    | ".ssh"
                    | ".aws"
                    | ".azure"
                    | ".gcloud"
                    | ".kube"
                    | ".docker"
                    | ".gnupg"
                    | "secrets"
                    | ".secrets"
                    | "credentials"
                    | ".credentials"
            ) {
                return true;
            }

            // Sensitive filenames (exact or stemmed)
            if matches!(
                c,
                "credentials"
                    | "secrets"
                    | "secret"
                    | "service-account.json"
                    | "service_account.json"
                    | "master.key"
                    | ".npmrc"
                    | ".pypirc"
                    | ".netrc"
                    | ".htpasswd"
                    | "authorized_keys"
                    | "known_hosts"
                    | "passwd"
                    | "shadow"
                    | "sudoers"
                    | "sam"
                    | "system"
            ) {
                return true;
            }

            // Filename prefix checks (e.g. credentials.json, secrets.yaml, secret.txt)
            if c.starts_with("credentials.")
                || c.starts_with("secrets.")
                || c.starts_with("secret.")
                || c.starts_with("service-account.")
                || c.starts_with("service_account.")
            {
                return true;
            }

            // Private keys & SSH identities
            if c.starts_with("id_rsa")
                || c.starts_with("id_ed25519")
                || c.starts_with("id_ecdsa")
                || c.starts_with("id_dsa")
            {
                return true;
            }
        }

        // 3. Cryptographic Key & Certificate Extensions
        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            let el = ext.to_lowercase();
            if matches!(
                el.as_str(),
                "pem"
                    | "key"
                    | "p12"
                    | "pfx"
                    | "pkcs12"
                    | "kdbx"
                    | "der"
                    | "crt"
                    | "cer"
                    | "jks"
                    | "keystore"
            ) {
                return true;
            }
        }

        false
    }
}
