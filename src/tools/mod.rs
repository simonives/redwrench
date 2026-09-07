use crate::policy::{Decision, PolicyEngine};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool_handler, ServerHandler};
use std::time::Duration;

pub mod dnf;
pub mod journalctl;
pub mod network;
pub mod run_command;
pub mod systemctl;

#[derive(Clone)]
pub struct RedWrenchServer {
    pub policy: std::sync::Arc<PolicyEngine>,
    pub timeout: Duration,
    pub tier_name: String,
    pub tool_router: ToolRouter<Self>,
}

// NOTE (Task 9 rmcp API adaptation): the task brief's plan assumed a
// version of rmcp where `#[tool_router(server_handler)]` alone was
// sufficient to make `RedWrenchServer` usable as an MCP `ServerHandler`.
// The pinned rmcp 3.2.0 requires an explicit `tool_router: ToolRouter<Self>`
// field on the struct (populated via the generated `Self::<name>_router()`
// associated function) plus an explicit `#[tool_handler(router = self.tool_router)]
// impl ServerHandler for RedWrenchServer {}` block. This mirrors the
// multi-router pattern rmcp's own test suite uses
// (tests/test_tool_routers.rs), which is also what Task 10 needs when it
// adds a second `impl RedWrenchServer` block with its own `#[tool_router]`
// (merged into this field with `+`, since `ToolRouter` implements `Add`).
impl RedWrenchServer {
    pub fn new(policy: std::sync::Arc<PolicyEngine>, timeout: Duration, tier_name: String) -> Self {
        Self {
            policy,
            timeout,
            tier_name,
            tool_router: Self::run_command_router()
                + Self::systemctl_router()
                + Self::dnf_router()
                + Self::journalctl_router()
                + Self::network_router(),
        }
    }

    // NOTE (post-review fix): `dispatch` returns `rmcp::model::CallToolResult`
    // rather than a bare `String`, so a policy denial is a structurally
    // distinct, protocol-level result (`is_error: Some(true)`) rather than a
    // successful result whose text merely happens to say "Denied: ...". This
    // is `CallToolResult::error(...)`, not `Err(rmcp::ErrorData)`: rmcp's own
    // docs on `CallToolResult::error` draw the line as "the tool ran and
    // didn't work" (caller's client renders the content, message reaches the
    // user) versus a protocol-level `ErrorData` ("the server cannot route
    // the request at all", rendered opaquely, message does NOT reach the
    // user). A policy denial is squarely the former: the tool executed, the
    // policy check is part of its normal operation, and the reason string
    // must reach the calling agent verbatim. `CallToolResult` itself
    // implements `IntoCallToolResult`, so `run_command` can return this
    // directly.
    //
    // A command timeout is treated the same way (also `CallToolResult::error`),
    // not folded into the "success" shape: the spec's error-handling section
    // groups a timeout with an internal server fault under "the agent
    // receives a generic failure", drawing the success/failure line at the
    // calling agent's perspective (did the call produce a usable result)
    // rather than at policy-allowed vs policy-denied. A timed-out command has
    // no real stdout/exit code to hand back, so it belongs on the same
    // `is_error: true` side as a denial, not lumped in with an actually
    // completed command's real output.
    pub async fn dispatch(&self, tool: &str, command: &str, args: Vec<String>) -> CallToolResult {
        match self.policy.evaluate(command, &args) {
            Decision::Denied(reason) => {
                crate::audit::record_invocation(
                    tool,
                    command,
                    &args,
                    &self.tier_name,
                    "denied",
                    None,
                );
                CallToolResult::error(vec![ContentBlock::text(format!(
                    "Denied: {reason} (active tier: {})",
                    self.tier_name
                ))])
            }
            Decision::Allowed => {
                let result = crate::executor::execute(command, &args, self.timeout).await;
                crate::audit::record_invocation(
                    tool,
                    command,
                    &args,
                    &self.tier_name,
                    "allowed",
                    result.exit_code,
                );
                if result.timed_out {
                    CallToolResult::error(vec![ContentBlock::text(format!(
                        "Command timed out after {:?}",
                        self.timeout
                    ))])
                } else {
                    CallToolResult::success(vec![ContentBlock::text(format!(
                        "exit code: {:?}\nstdout:\n{}\nstderr:\n{}",
                        result.exit_code, result.stdout, result.stderr
                    ))])
                }
            }
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for RedWrenchServer {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Effect, Rule};

    fn allow_all_server(timeout: Duration) -> RedWrenchServer {
        RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(vec![Rule {
                command: String::new(),
                arg_pattern: None,
                effect: Effect::Allow,
            }])),
            timeout,
            "unrestricted".to_string(),
        )
    }

    fn deny_all_server(timeout: Duration) -> RedWrenchServer {
        RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(vec![])),
            timeout,
            "safe".to_string(),
        )
    }

    fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|block| block.as_text())
            .map(|t| t.text.clone())
            .collect::<Vec<_>>()
            .join("")
    }

    #[tokio::test]
    async fn dispatch_returns_a_structured_error_result_when_the_policy_denies() {
        let server = deny_all_server(Duration::from_secs(5));
        let result = server
            .dispatch(
                "run_command",
                "rm",
                vec!["-rf".to_string(), "/".to_string()],
            )
            .await;

        assert_eq!(result.is_error, Some(true));
        let text = text_of(&result);
        assert!(text.starts_with("Denied:"), "unexpected text: {text}");
        assert!(
            text.contains("active tier: safe"),
            "unexpected text: {text}"
        );
    }

    #[tokio::test]
    async fn dispatch_returns_a_successful_result_with_real_output_when_the_policy_allows() {
        let server = allow_all_server(Duration::from_secs(5));
        let result = server
            .dispatch("run_command", "echo", vec!["hello".to_string()])
            .await;

        assert_eq!(result.is_error, Some(false));
        let text = text_of(&result);
        assert!(
            text.contains("exit code: Some(0)"),
            "unexpected text: {text}"
        );
        assert!(text.contains("hello"), "unexpected text: {text}");
    }

    #[tokio::test]
    async fn dispatch_reports_a_timeout_as_a_structured_error_result() {
        let server = allow_all_server(Duration::from_millis(100));
        let result = server
            .dispatch("run_command", "sleep", vec!["5".to_string()])
            .await;

        // A timeout produced no real output, so from the calling agent's
        // perspective it is a failed call, same `is_error: true` shape as a
        // policy denial, not the same shape as a command that actually
        // completed with real stdout.
        assert_eq!(result.is_error, Some(true));
        let text = text_of(&result);
        assert!(text.contains("timed out"), "unexpected text: {text}");
    }
}
