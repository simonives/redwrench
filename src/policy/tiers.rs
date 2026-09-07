use super::{Effect, Rule};
use regex::Regex;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TierName {
    Safe,
    Standard,
    Unrestricted,
}

fn allow(command: &str, arg_pattern: Option<&str>) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: arg_pattern.map(|p| Regex::new(p).unwrap()),
        effect: Effect::Allow,
    }
}

fn safe_rules() -> Vec<Rule> {
    vec![
        allow("systemctl", Some("^status")),
        allow("systemctl", Some("^is-active")),
        allow("systemctl", Some("^is-enabled")),
        allow("journalctl", None),
        allow("ping", None),
        allow("ip", Some("^(addr|route|link)")),
    ]
}

fn standard_rules() -> Vec<Rule> {
    let mut rules = safe_rules();
    rules.extend(vec![
        allow("systemctl", Some("^(start|stop|restart|enable|disable)")),
        allow("dnf", Some("^(install|remove|upgrade)")),
        allow("rpm-ostree", Some("^(install|upgrade|status)")),
    ]);
    rules
}

pub fn rules_for_tier(tier: &TierName) -> Vec<Rule> {
    match tier {
        TierName::Safe => safe_rules(),
        TierName::Standard => standard_rules(),
        TierName::Unrestricted => vec![Rule {
            command: String::new(),
            arg_pattern: None,
            effect: Effect::Allow,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Decision, PolicyEngine};

    #[test]
    fn safe_tier_allows_systemctl_status_but_denies_stop() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("systemctl", &["status".into(), "sshd".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate("systemctl", &["stop".into(), "sshd".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn safe_tier_denies_dnf_and_raw_run_command_entirely() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("dnf", &["install".into(), "-y".into(), "htop".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn standard_tier_allows_systemctl_stop_and_dnf_install() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        assert!(matches!(
            engine.evaluate("systemctl", &["stop".into(), "sshd".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate("dnf", &["install".into(), "-y".into(), "htop".into()]),
            Decision::Allowed
        ));
    }

    #[test]
    fn standard_tier_still_denies_arbitrary_raw_commands() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        assert!(matches!(
            engine.evaluate("rm", &["-rf".into(), "/".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn unrestricted_tier_allows_anything() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Unrestricted));
        assert!(matches!(
            engine.evaluate("rm", &["-rf".into(), "/".into()]),
            Decision::Allowed
        ));
    }
}
