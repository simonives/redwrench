use super::RedWrenchServer;
use rmcp::model::CallToolResult;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SystemctlStatusParams {
    /// The unit name to check, e.g. "sshd" or "sshd.service".
    pub unit: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SystemctlControlParams {
    /// One of: start, stop, restart, enable, disable.
    pub action: String,
    /// The unit name to act on, e.g. "sshd" or "sshd.service".
    pub unit: String,
}

/// The complete set of actions `systemctl_control` documents and accepts.
///
/// NOTE (post-review fix): `action` was previously unvalidated at this
/// layer and only protected incidentally, by the policy tier's anchored
/// `^(start|stop|restart|enable|disable)` regex. That made the tool's own
/// documented contract accidentally true rather than enforced, and it would
/// silently stop being true if a tier's regex were ever loosened. Validate
/// here so the contract holds regardless of policy configuration.
const ALLOWED_ACTIONS: [&str; 5] = ["start", "stop", "restart", "enable", "disable"];

// NOTE (post-review fix, argument-injection hardening, same class of bug
// Task 11 fixed in dnf.rs and network.rs): `unit` is free text that ends up
// as systemctl's trailing *positional* argument, structurally identical to
// dnf's `package` and ping's `host`. systemctl's own option parser
// recognises flags anywhere in argv, so a `unit` value such as
// `--host=attacker@evil.example` would make `systemctl_status`, documented
// as read-only and allowed under every tier, open an outbound SSH
// connection using this machine's identity. `unit` is reachable by anything
// that controls the MCP tool call, including a prompt-injected agent, which
// is exactly this project's threat model.
//
// The fix is the standard `--` end-of-options separator, which systemctl
// honours: everything after it is a positional argument, never an option.
// This does not affect policy matching, the joined args become
// "status -- sshd" / "start -- sshd", which still match the anchored
// `^status` and `^(start|stop|restart|enable|disable)` tier patterns.
//
// These free functions build the argv vectors so `--` placement can be
// unit-tested directly without needing a real `systemctl` binary.
fn status_argv(unit: String) -> Vec<String> {
    vec!["status".into(), "--".into(), unit]
}

fn control_argv(action: String, unit: String) -> Vec<String> {
    vec![action, "--".into(), unit]
}

fn is_allowed_action(action: &str) -> bool {
    ALLOWED_ACTIONS.contains(&action)
}

#[tool_router(router = systemctl_router, vis = "pub(crate)")]
impl RedWrenchServer {
    #[tool(
        description = "Check the status of a systemd unit (read-only, allowed under every tier)."
    )]
    pub async fn systemctl_status(
        &self,
        Parameters(SystemctlStatusParams { unit }): Parameters<SystemctlStatusParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        self.dispatch(
            "systemctl_status",
            "systemctl",
            status_argv(unit),
            ctx,
            None,
        )
        .await
    }

    #[tool(
        description = "Start, stop, restart, enable, or disable a systemd unit. \
        Requires at least the 'standard' policy tier."
    )]
    pub async fn systemctl_control(
        &self,
        Parameters(SystemctlControlParams { action, unit }): Parameters<SystemctlControlParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        if !is_allowed_action(&action) {
            return CallToolResult::error(vec![rmcp::model::ContentBlock::text(format!(
                "Invalid action '{action}'. Must be one of: {}.",
                ALLOWED_ACTIONS.join(", ")
            ))]);
        }
        self.dispatch(
            "systemctl_control",
            "systemctl",
            control_argv(action, unit),
            ctx,
            None,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_argv_places_a_literal_double_dash_separator_before_the_unit() {
        let args = status_argv("--host=attacker@evil.example".to_string());
        assert_eq!(args, vec!["status", "--", "--host=attacker@evil.example"]);

        let dash_pos = args
            .iter()
            .position(|a| a == "--")
            .expect("-- separator missing");
        assert_eq!(dash_pos, args.len() - 2);
    }

    #[test]
    fn control_argv_places_a_literal_double_dash_separator_before_the_unit() {
        let args = control_argv("start".to_string(), "--host=evil.example".to_string());
        assert_eq!(args, vec!["start", "--", "--host=evil.example"]);

        let dash_pos = args
            .iter()
            .position(|a| a == "--")
            .expect("-- separator missing");
        assert_eq!(dash_pos, args.len() - 2);
    }

    #[test]
    fn ordinary_unit_names_are_unaffected() {
        assert_eq!(
            status_argv("sshd".to_string()),
            vec!["status", "--", "sshd"]
        );
        assert_eq!(
            control_argv("restart".to_string(), "sshd.service".to_string()),
            vec!["restart", "--", "sshd.service"]
        );
    }

    #[test]
    fn the_double_dash_form_still_matches_the_tier_policy_patterns() {
        // Guards the claim in the note above: adding `--` must not
        // accidentally make previously-allowed calls fail policy matching.
        use crate::policy::{tiers, Decision, PolicyEngine};
        let engine = PolicyEngine::new(tiers::rules_for_tier(&tiers::TierName::Standard));
        assert!(matches!(
            engine.evaluate("systemctl", &status_argv("sshd".to_string())),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate(
                "systemctl",
                &control_argv("restart".to_string(), "sshd".to_string())
            ),
            Decision::Allowed
        ));
    }

    #[test]
    fn every_documented_action_is_accepted() {
        for action in ["start", "stop", "restart", "enable", "disable"] {
            assert!(is_allowed_action(action), "{action} should be allowed");
        }
    }

    #[test]
    fn an_undocumented_action_is_rejected() {
        // `reboot` and `mask` are real systemctl verbs the tool does not
        // document; `--force` is a flag-shaped injection attempt.
        assert!(!is_allowed_action("reboot"));
        assert!(!is_allowed_action("mask"));
        assert!(!is_allowed_action("--force"));
        assert!(!is_allowed_action("isolate"));
        assert!(!is_allowed_action(""));
        // Case matters: systemctl verbs are lowercase, and accepting
        // "START" would only widen the surface for no benefit.
        assert!(!is_allowed_action("START"));
    }

    #[tokio::test]
    async fn systemctl_control_rejects_an_invalid_action_before_dispatch() {
        use crate::policy::{Effect, PolicyEngine, Rule};
        use std::time::Duration;

        // Deliberately an allow-everything policy: if the tool layer did
        // not validate, this call would sail straight through to execution.
        let server = RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(vec![Rule {
                command: String::new(),
                arg_pattern: None,
                effect: Effect::Allow,
                description: "allow everything".to_string(),
            }])),
            Duration::from_secs(5),
            "unrestricted".to_string(),
            Duration::from_secs(1800),
            crate::policy::tiers::TierName::Unrestricted,
            vec![],
        );
        let (ctx, _guard) = crate::tools::tests::test_request_context(&server);

        let result = server
            .systemctl_control(
                Parameters(SystemctlControlParams {
                    action: "reboot".to_string(),
                    unit: "sshd".to_string(),
                }),
                ctx,
            )
            .await;

        assert_eq!(result.is_error, Some(true));
        let text = result
            .content
            .iter()
            .filter_map(|b| b.as_text())
            .map(|t| t.text.clone())
            .collect::<Vec<_>>()
            .join("");
        assert!(text.contains("Invalid action"), "unexpected text: {text}");
    }
}
