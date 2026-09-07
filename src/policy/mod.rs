use regex::Regex;

#[derive(Debug, Clone)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub command: String,
    pub arg_pattern: Option<Regex>,
    pub effect: Effect,
}

#[derive(Debug, PartialEq)]
#[must_use]
pub enum Decision {
    Allowed,
    Denied(String),
}

pub struct PolicyEngine {
    rules: Vec<Rule>,
}

impl PolicyEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn evaluate(&self, command: &str, args: &[String]) -> Decision {
        let joined_args = args.join(" ");
        for rule in &self.rules {
            if rule.command != command {
                continue;
            }
            let arg_matches = match &rule.arg_pattern {
                Some(pattern) => pattern.is_match(&joined_args),
                None => true,
            };
            if !arg_matches {
                continue;
            }
            return match rule.effect {
                Effect::Allow => Decision::Allowed,
                Effect::Deny => Decision::Denied(format!(
                    "'{command} {joined_args}' is denied by policy"
                )),
            };
        }
        Decision::Denied(format!(
            "'{command} {joined_args}' has no matching allow rule"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(command: &str, arg_pattern: Option<&str>, effect: Effect) -> Rule {
        Rule {
            command: command.to_string(),
            arg_pattern: arg_pattern.map(|p| Regex::new(p).unwrap()),
            effect,
        }
    }

    #[test]
    fn allows_a_command_matching_an_allow_rule() {
        let engine = PolicyEngine::new(vec![rule("systemctl", Some("^status"), Effect::Allow)]);
        let decision = engine.evaluate("systemctl", &["status".into(), "sshd".into()]);
        assert!(matches!(decision, Decision::Allowed));
    }

    #[test]
    fn denies_a_command_with_no_matching_rule() {
        let engine = PolicyEngine::new(vec![rule("systemctl", Some("^status"), Effect::Allow)]);
        let decision = engine.evaluate("systemctl", &["stop".into(), "sshd".into()]);
        assert!(matches!(decision, Decision::Denied(_)));
    }

    #[test]
    fn first_matching_rule_wins() {
        let engine = PolicyEngine::new(vec![
            rule("systemctl", Some("^stop"), Effect::Deny),
            rule("systemctl", None, Effect::Allow),
        ]);
        let decision = engine.evaluate("systemctl", &["stop".into(), "sshd".into()]);
        assert!(matches!(decision, Decision::Denied(_)));
    }

    #[test]
    fn a_rule_with_no_arg_pattern_matches_any_arguments() {
        let engine = PolicyEngine::new(vec![rule("journalctl", None, Effect::Allow)]);
        let decision = engine.evaluate("journalctl", &["-u".into(), "sshd".into()]);
        assert!(matches!(decision, Decision::Allowed));
    }
}
