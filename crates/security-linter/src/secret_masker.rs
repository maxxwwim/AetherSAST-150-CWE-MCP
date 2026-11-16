use regex::Regex;
use std::sync::OnceLock;

/// Text redaction and masking engine to prevent confidential secrets from leaking
/// into AI prompts, active target documentation, or markdown audit logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecretMasker;

struct MaskingRules {
    private_key_block: Regex,
    openai_anthropic_gemini: Regex,
    github_pat: Regex,
    github_fine_grained: Regex,
    github_other: Regex,
    aws_access_key: Regex,
    stripe_key: Regex,
    slack_token: Regex,
    jwt_token: Regex,
    db_uri_password: Regex,
    quoted_secret_assignment: Regex,
    unquoted_secret_assignment: Regex,
}

static RULES: OnceLock<MaskingRules> = OnceLock::new();

fn get_rules() -> &'static MaskingRules {
    RULES.get_or_init(|| MaskingRules {
        // 1. Private Key Blocks (RSA, EC, OPENSSH, etc.)
        private_key_block: Regex::new(
            r"(?s)-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----.*?-----END[ A-Z0-9_-]*PRIVATE KEY-----",
        )
        .expect("valid regex for private_key_block"),

        // 2. OpenAI / Anthropic / Gemini API keys (sk-...)
        openai_anthropic_gemini: Regex::new(r"\bsk-[a-zA-Z0-9_-]{20,}\b")
            .expect("valid regex for openai_anthropic_gemini"),

        // 3. GitHub Classic Personal Access Tokens (ghp_...)
        github_pat: Regex::new(r"\bghp_[a-zA-Z0-9]{36}\b").expect("valid regex for github_pat"),

        // 4. GitHub Fine-Grained Personal Access Tokens (github_pat_...)
        github_fine_grained: Regex::new(r"\bgithub_pat_[a-zA-Z0-9_]{50,}\b")
            .expect("valid regex for github_fine_grained"),

        // 5. GitHub OAuth/Server/Refresh Tokens (gho_, ghu_, ghs_, ghr_)
        github_other: Regex::new(r"\bgh[ousr]_[a-zA-Z0-9]{36}\b")
            .expect("valid regex for github_other"),

        // 6. AWS Access Key IDs (AKIA...)
        aws_access_key: Regex::new(r"\bAKIA[0-9A-Z]{16}\b")
            .expect("valid regex for aws_access_key"),

        // 7. Stripe live secret keys (sk_live_..., rk_live_...)
        stripe_key: Regex::new(r"\b(sk_live|rk_live)_[0-9a-zA-Z]{24,}\b")
            .expect("valid regex for stripe_key"),

        // 8. Slack tokens (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-)
        slack_token: Regex::new(r"\bxox[baprs]-[0-9a-zA-Z-]{10,72}\b")
            .expect("valid regex for slack_token"),

        // 9. JSON Web Tokens (JWT: three base64 segments starting with ey...)
        jwt_token: Regex::new(r"\bey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
            .expect("valid regex for jwt_token"),

        // 10. Database Connection URIs with credentials (postgres://user:password@host...)
        db_uri_password: Regex::new(r"([a-zA-Z0-9+]+://[^:/\s@]+):([^@\s/]+)@")
            .expect("valid regex for db_uri_password"),

        // 11. Quoted generic password / secret assignments
        quoted_secret_assignment: Regex::new(
            r#"(?i)\b((?:api_key|api_secret|secret_key|secret|password|passwd|auth_token|access_token|private_key)\s*[:=]\s*["'])([^"'\r\n]{4,})(["'])"#,
        )
        .expect("valid regex for quoted_secret_assignment"),

        // 12. Unquoted generic secret assignments (e.g. in env or config lines)
        unquoted_secret_assignment: Regex::new(
            r#"(?i)\b((?:api_key|api_secret|secret_key|secret|password|passwd|auth_token|access_token)\s*=\s*)([^\s"';]{4,})"#,
        )
        .expect("valid regex for unquoted_secret_assignment"),
    })
}

impl SecretMasker {
    /// Redacts all detected sensitive tokens, keys, passwords, and private blocks from `text`.
    pub fn mask_text(input: &str) -> String {
        let rules = get_rules();

        // 1. Private key blocks
        let step1 = rules
            .private_key_block
            .replace_all(input, "[PRIVATE_KEY_BLOCK_REDACTED]");

        // 2. OpenAI / Anthropic / Gemini
        let step2 = rules
            .openai_anthropic_gemini
            .replace_all(&step1, "sk-***[REDACTED]***");

        // 3. GitHub Classic PAT
        let step3 = rules
            .github_pat
            .replace_all(&step2, "ghp_***[REDACTED]***");

        // 4. GitHub Fine-Grained PAT
        let step4 = rules
            .github_fine_grained
            .replace_all(&step3, "github_pat_***[REDACTED]***");

        // 5. GitHub other tokens
        let step5 = rules
            .github_other
            .replace_all(&step4, "gh***[REDACTED]***");

        // 6. AWS Access Key
        let step6 = rules
            .aws_access_key
            .replace_all(&step5, "AKIA***[REDACTED]***");

        // 7. Stripe keys
        let step7 = rules
            .stripe_key
            .replace_all(&step6, "${1}_***[REDACTED]***");

        // 8. Slack tokens
        let step8 = rules
            .slack_token
            .replace_all(&step7, "xox-***[REDACTED]***");

        // 9. JWT tokens
        let step9 = rules
            .jwt_token
            .replace_all(&step8, "ey***[JWT_REDACTED]***");

        // 10. Database URI passwords
        let step10 = rules
            .db_uri_password
            .replace_all(&step9, "${1}:***@");

        // 11. Quoted secret assignments
        let step11 = rules
            .quoted_secret_assignment
            .replace_all(&step10, "${1}******** [REDACTED]${3}");

        // 12. Unquoted secret assignments
        let step12 = rules
            .unquoted_secret_assignment
            .replace_all(&step11, "${1}******** [REDACTED]");

        step12.into_owned()
    }

    /// Checks whether `input` contains any identifiable sensitive token or credential.
    pub fn contains_secret(input: &str) -> bool {
        let rules = get_rules();
        rules.private_key_block.is_match(input)
            || rules.openai_anthropic_gemini.is_match(input)
            || rules.github_pat.is_match(input)
            || rules.github_fine_grained.is_match(input)
            || rules.github_other.is_match(input)
            || rules.aws_access_key.is_match(input)
            || rules.stripe_key.is_match(input)
            || rules.slack_token.is_match(input)
            || rules.jwt_token.is_match(input)
            || rules.db_uri_password.is_match(input)
            || rules.quoted_secret_assignment.is_match(input)
            || rules.unquoted_secret_assignment.is_match(input)
    }
}
