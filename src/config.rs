use crate::policy::tiers::TierName;
use crate::policy::{Effect, Rule};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RawRule {
    command: String,
    arg_pattern: Option<String>,
    effect: String,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    bind_address: String,
    bearer_token: String,
    tier: TierName,
    #[serde(default)]
    custom_rules: Vec<RawRule>,
}

#[derive(Debug)]
pub struct Config {
    pub bind_address: String,
    pub bearer_token: String,
    pub tier: TierName,
    pub custom_rules: Vec<Rule>,
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
        })
    }

    pub fn effective_rules(&self) -> Vec<Rule> {
        let mut rules = crate::policy::tiers::rules_for_tier(&self.tier);
        rules.extend(self.custom_rules.iter().cloned());
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
    fn effective_rules_appends_custom_rules_after_tier_defaults() {
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
        assert_eq!(rules.last().unwrap().command, "curl");
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
}
