use crate::policy::tiers::TierName;
use crate::policy::{Effect, Rule};
use serde::Deserialize;

/// Default command execution timeout, in seconds, when the config file
/// does not specify one. 30s suits interactive diagnostics; operators
/// running the `standard` tier (where `dnf install` is permitted, and
/// routinely takes longer than 30s on a slow mirror) will usually want
/// to raise this via `timeout_secs`.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default safety-net ceiling, in seconds, for a call using streaming or
/// indefinite execution (e.g. `journalctl_tail` with `follow: true`, or
/// `ping` with no `count`). Applies regardless of whether the caller ever
/// cancels; a client that disconnects without cancelling must not be able
/// to keep a process running forever.
pub const DEFAULT_MAX_STREAM_DURATION_SECS: u64 = 1800;

// NOTE (post-review fix): `deny_unknown_fields` on both raw structs.
// Without it, a typo such as `custom_rule` (singular) parses "fine" and
// silently drops every rule the operator wrote, i.e. a security control
// quietly disappears with no diagnostic. A hard load error is strictly
// better than silent data loss for a file that governs what an AI agent
// is allowed to run.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    command: String,
    arg_pattern: Option<String>,
    effect: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    bind_address: String,
    bearer_token: String,
    tier: TierName,
    #[serde(default)]
    custom_rules: Vec<RawRule>,
    /// Command execution timeout in seconds. Optional; defaults to
    /// [`DEFAULT_TIMEOUT_SECS`].
    #[serde(default)]
    timeout_secs: Option<u64>,
    /// Safety-net maximum duration, in seconds, for streaming/indefinite
    /// calls. Optional; defaults to [`DEFAULT_MAX_STREAM_DURATION_SECS`].
    #[serde(default)]
    max_stream_duration_secs: Option<u64>,
}

#[derive(Debug)]
pub struct Config {
    pub bind_address: String,
    pub bearer_token: String,
    pub tier: TierName,
    pub custom_rules: Vec<Rule>,
    /// Resolved command execution timeout in seconds, already defaulted.
    pub timeout_secs: u64,
    /// Resolved safety-net duration in seconds, already defaulted.
    pub max_stream_duration_secs: u64,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let raw: RawConfig = toml::from_str(&contents)?;
        let custom_rules = raw
            .custom_rules
            .into_iter()
            .map(|r| {
                if r.command.trim().is_empty() {
                    anyhow::bail!(
                        "custom rule has an empty command, which is not permitted (rules for '{}' tier already cover blanket wildcards)",
                        match raw.tier {
                            TierName::Safe => "safe",
                            TierName::Standard => "standard",
                            TierName::Unrestricted => "unrestricted",
                        }
                    );
                }
                if let Some(ref pattern) = r.arg_pattern {
                    if pattern.trim().is_empty() {
                        anyhow::bail!(
                            "custom rule for '{}' has an empty arg_pattern; omit the field instead of setting it to an empty string",
                            r.command
                        );
                    }
                }
                Ok(Rule {
                    command: r.command,
                    arg_pattern: r.arg_pattern.map(|p| regex::Regex::new(&p)).transpose()?,
                    effect: match r.effect.as_str() {
                        "allow" => Effect::Allow,
                        "deny" => Effect::Deny,
                        other => anyhow::bail!("unknown effect '{other}', expected 'allow' or 'deny'"),
                    },
                })
            })
            .collect::<anyhow::Result<Vec<Rule>>>()?;
        Ok(Config {
            bind_address: raw.bind_address,
            bearer_token: raw.bearer_token,
            tier: raw.tier,
            custom_rules,
            timeout_secs: raw.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
            max_stream_duration_secs: raw
                .max_stream_duration_secs
                .unwrap_or(DEFAULT_MAX_STREAM_DURATION_SECS),
        })
    }

    /// Builds the ordered rule list the policy engine evaluates.
    ///
    /// NOTE (post-review Critical fix): custom rules come **first**, tier
    /// rules second. `PolicyEngine::evaluate` is first-match-wins, so the
    /// previous order (tier rules first, custom appended after) made every
    /// custom deny rule silently inert whenever the active tier already
    /// allowed the command: a real security control that accepted config
    /// and did nothing. The spec promises operators can "layer custom
    /// allow/deny rules on top of whichever tier is active", which only
    /// means anything if the user-authored rule wins the race. Custom
    /// allows for commands no tier covers still work under this order,
    /// since a non-matching custom rule simply falls through to the tier
    /// rules behind it.
    pub fn effective_rules(&self) -> Vec<Rule> {
        let mut rules = self.custom_rules.clone();
        rules.extend(crate::policy::tiers::rules_for_tier(&self.tier));
        rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_config(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    #[test]
    fn loads_a_minimal_config() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.bind_address, "100.64.0.1:8443");
        assert_eq!(config.bearer_token, "test-token");
        assert_eq!(config.tier, crate::policy::tiers::TierName::Safe);
        assert!(config.custom_rules.is_empty());
    }

    #[test]
    fn effective_rules_prepends_custom_rules_before_tier_defaults() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"

            [[custom_rules]]
            command = "curl"
            effect = "allow"
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        let rules = config.effective_rules();
        let tier_only_len =
            crate::policy::tiers::rules_for_tier(&crate::policy::tiers::TierName::Safe).len();
        assert_eq!(rules.len(), tier_only_len + 1);
        // Custom rules must be evaluated first, since the engine is
        // first-match-wins. If this ever flips back to `.last()`, custom
        // deny rules become silently inert again.
        assert_eq!(rules.first().unwrap().command, "curl");
    }

    #[test]
    fn a_custom_deny_rule_overrides_a_tier_allow_for_the_same_command() {
        // The `safe` tier allows journalctl reads. A custom deny rule for
        // journalctl must win, otherwise custom deny rules are dead config.
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"

            [[custom_rules]]
            command = "journalctl"
            effect = "deny"
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        let engine = crate::policy::PolicyEngine::new(config.effective_rules());
        assert!(matches!(
            engine.evaluate("journalctl", &["-u".into(), "sshd".into()]),
            crate::policy::Decision::Denied(_)
        ));
        // Sanity check: the tier's other allowances are untouched.
        assert!(matches!(
            engine.evaluate("systemctl", &["status".into(), "sshd".into()]),
            crate::policy::Decision::Allowed
        ));
    }

    #[test]
    fn a_custom_allow_rule_grants_a_command_no_tier_rule_covers() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"

            [[custom_rules]]
            command = "curl"
            effect = "allow"
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        let engine = crate::policy::PolicyEngine::new(config.effective_rules());
        assert!(matches!(
            engine.evaluate("curl", &["https://example.com".into()]),
            crate::policy::Decision::Allowed
        ));
        // A command with neither a custom nor a tier rule is still denied.
        assert!(matches!(
            engine.evaluate("rm", &["-rf".into(), "/".into()]),
            crate::policy::Decision::Denied(_)
        ));
    }

    #[test]
    fn timeout_secs_defaults_to_30_when_absent() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn timeout_secs_is_read_from_the_config_when_present() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "standard"
            timeout_secs = 300
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.timeout_secs, 300);
    }

    #[test]
    fn an_unknown_config_field_is_a_hard_load_error() {
        // A typo'd `custom_rule` (singular) previously parsed silently and
        // dropped every rule the operator wrote. It must now fail loudly.
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"

            [[custom_rule]]
            command = "curl"
            effect = "allow"
            "#,
        );
        let result = Config::load(file.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("custom_rule"));
    }

    #[test]
    fn an_unknown_field_inside_a_custom_rule_is_a_hard_load_error() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"

            [[custom_rules]]
            command = "curl"
            effect = "allow"
            argument_pattern = "^https"
            "#,
        );
        assert!(Config::load(file.path()).is_err());
    }

    #[test]
    fn missing_file_returns_an_error() {
        let result = Config::load(std::path::Path::new("/nonexistent/redwrench.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn empty_command_in_custom_rule_is_rejected() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"

            [[custom_rules]]
            command = ""
            effect = "allow"
            "#,
        );
        let result = Config::load(file.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty command"));
    }

    #[test]
    fn empty_arg_pattern_in_custom_rule_is_rejected() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"

            [[custom_rules]]
            command = "curl"
            arg_pattern = ""
            effect = "allow"
            "#,
        );
        let result = Config::load(file.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("empty arg_pattern"));
    }

    #[test]
    fn max_stream_duration_secs_defaults_to_1800_when_absent() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.max_stream_duration_secs, DEFAULT_MAX_STREAM_DURATION_SECS);
        assert_eq!(config.max_stream_duration_secs, 1800);
    }

    #[test]
    fn max_stream_duration_secs_is_read_from_the_config_when_present() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"
            max_stream_duration_secs = 300
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.max_stream_duration_secs, 300);
    }
}
