use regex::Regex;

pub mod tiers;

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
            if !rule.command.is_empty() && rule.command != command {
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

    #[test]
    fn a_trailing_shell_metacharacter_in_an_argument_does_not_bypass_a_deny_rule() {
        let engine = PolicyEngine::new(vec![
            rule("systemctl", Some("stop"), Effect::Deny),
            rule("systemctl", None, Effect::Allow),
        ]);
        // Simulates an agent trying to smuggle a second command past the
        // "stop" deny by appending it to the same argument.
        let decision = engine.evaluate("systemctl", &["status".into(), "sshd; systemctl stop sshd".into()]);
        // This must be Denied, because the joined-args string still
        // contains "stop", and the deny rule for "stop" is checked before
        // the allow rule. If this ever becomes Allowed, the rule
        // ordering or matching logic has regressed.
        assert!(matches!(decision, Decision::Denied(_)));
    }

    #[test]
    fn args_are_never_shell_interpreted_by_the_engine_itself() {
        // The policy engine only does regex matching on a joined string,
        // it never invokes a shell. This test proves that a payload
        // containing shell metacharacters (`;`, backticks, `$()`) reaches
        // the matcher completely unmodified, no escaping, no substitution,
        // no shell expansion happens anywhere in this code path. The real
        // defence against shell interpretation lives in executor.rs
        // (Task 6), which must invoke commands via tokio::process::Command
        // with separate argv entries, never via a shell (`sh -c`).
        let engine = PolicyEngine::new(vec![
            rule("echo", Some("rm -rf"), Effect::Deny),
        ]);
        let decision = engine.evaluate("echo", &["hello `rm -rf /`".into()]);
        match decision {
            Decision::Denied(msg) => assert!(msg.contains("hello `rm -rf /`")),
            other => panic!("expected Denied, got {other:?}"),
        }
    }
}
