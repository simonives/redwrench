use super::RedWrenchServer;
use crate::policy::introspection::{
    additional_rules, describe_rules, effective_rules_for, lowest_tier_that_would_allow,
    tier_order, RuleDescription,
};
use crate::policy::tiers::tier_display_name;
use crate::policy::Decision;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct TierUnlock {
    tier: String,
    additional_capabilities: Vec<RuleDescription>,
}

#[derive(Debug, Serialize)]
struct CapabilitiesResponse {
    active_tier: String,
    current_capabilities: Vec<RuleDescription>,
    unlocked_by_higher_tiers: Vec<TierUnlock>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CheckCommandParams {
    /// The command binary to evaluate, e.g. "journalctl" or "dnf".
    pub command: String,
    /// The arguments that would be passed to `command`, in order.
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CheckCommandResponse {
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    would_be_allowed_at: Option<String>,
}

#[tool_router(router = introspection_router, vis = "pub(crate)")]
impl RedWrenchServer {
    #[tool(
        description = "Describe what this RedWrench instance can do right now: the \
        active policy tier, every command/argument rule it currently evaluates \
        (allow or deny, in plain language), and what each higher tier would \
        additionally unlock. Safe to call at every tier, including 'safe': this \
        only inspects the policy engine's own rule list, it never executes anything."
    )]
    pub async fn list_capabilities(&self) -> CallToolResult {
        let current_rules = effective_rules_for(&self.tier, &self.custom_rules);
        let current_capabilities = describe_rules(&current_rules);

        let from_index = tier_order()
            .iter()
            .position(|t| t == &self.tier)
            .unwrap_or(0);
        let unlocked_by_higher_tiers = tier_order()[from_index + 1..]
            .iter()
            .map(|tier| {
                let higher_rules = effective_rules_for(tier, &self.custom_rules);
                TierUnlock {
                    tier: tier_display_name(tier),
                    additional_capabilities: additional_rules(&current_rules, &higher_rules),
                }
            })
            .collect();

        let response = CapabilitiesResponse {
            active_tier: tier_display_name(&self.tier),
            current_capabilities,
            unlocked_by_higher_tiers,
        };
        CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&response)
                .expect("CapabilitiesResponse is always serializable"),
        )])
    }

    #[tool(
        description = "Check whether a specific command and arguments would be \
        allowed right now, without running it. Returns the decision, the reason, \
        and (if denied) the lowest tier that would allow it, if any. Safe to call \
        at every tier, including 'safe': this only evaluates the policy engine, \
        it never executes anything."
    )]
    pub async fn check_command(
        &self,
        Parameters(CheckCommandParams { command, args }): Parameters<CheckCommandParams>,
    ) -> CallToolResult {
        let response = match self.policy.evaluate(&command, &args) {
            Decision::Allowed => CheckCommandResponse {
                decision: "allowed".to_string(),
                reason: None,
                would_be_allowed_at: None,
            },
            Decision::Denied(reason) => CheckCommandResponse {
                decision: "denied".to_string(),
                would_be_allowed_at: lowest_tier_that_would_allow(
                    &command,
                    &args,
                    &self.custom_rules,
                    &self.tier,
                )
                .map(|t| tier_display_name(&t)),
                reason: Some(reason),
            },
        };
        CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&response)
                .expect("CheckCommandResponse is always serializable"),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::tiers::{rules_for_tier, TierName};
    use crate::policy::PolicyEngine;
    use std::time::Duration;

    fn server_at(tier: TierName, tier_name: &str) -> RedWrenchServer {
        RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(rules_for_tier(&tier))),
            Duration::from_secs(5),
            tier_name.to_string(),
            Duration::from_secs(1800),
            tier,
            vec![],
        )
    }

    #[tokio::test]
    async fn list_capabilities_reports_the_active_tier_and_a_nonempty_rule_list() {
        let server = server_at(TierName::Safe, "safe");
        let result = server.list_capabilities().await;
        let text = super::super::tests::text_of(&result);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["active_tier"], "safe");
        assert!(!parsed["current_capabilities"]
            .as_array()
            .unwrap()
            .is_empty());
        // Safe is not the highest tier, so it must report at least one
        // tier above it (standard, unrestricted) that would unlock more.
        assert!(parsed["unlocked_by_higher_tiers"].as_array().unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn list_capabilities_reports_no_higher_tiers_when_already_unrestricted() {
        let server = server_at(TierName::Unrestricted, "unrestricted");
        let result = server.list_capabilities().await;
        let text = super::super::tests::text_of(&result);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            parsed["unlocked_by_higher_tiers"].as_array().unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn check_command_reports_allowed_with_no_reason_or_suggestion() {
        // (issue #26) A bare, unscoped journalctl call is no longer
        // allowed under `safe`, so this "genuinely allowed" fixture uses a
        // real unit scope instead.
        let server = server_at(TierName::Safe, "safe");
        let result = server
            .check_command(Parameters(CheckCommandParams {
                command: "journalctl".to_string(),
                args: vec!["-u".to_string(), "sshd".to_string()],
            }))
            .await;
        let text = super::super::tests::text_of(&result);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["decision"], "allowed");
        assert!(parsed.get("reason").is_none());
        assert!(parsed.get("would_be_allowed_at").is_none());
    }

    #[tokio::test]
    async fn check_command_reports_denied_with_a_tier_suggestion() {
        let server = server_at(TierName::Safe, "safe");
        let result = server
            .check_command(Parameters(CheckCommandParams {
                command: "dnf".to_string(),
                args: vec!["install".to_string(), "htop".to_string()],
            }))
            .await;
        let text = super::super::tests::text_of(&result);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["decision"], "denied");
        assert!(!parsed["reason"].as_str().unwrap().is_empty());
        assert_eq!(parsed["would_be_allowed_at"], "standard");
    }
}
