use crate::policy::{Decision, PolicyEngine};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::{tool_handler, ServerHandler};
use std::time::Duration;

pub mod run_command;

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
            tool_router: Self::run_command_router(),
        }
    }

    pub async fn dispatch(&self, tool: &str, command: &str, args: Vec<String>) -> String {
        match self.policy.evaluate(command, &args) {
            Decision::Denied(reason) => {
                crate::audit::record_invocation(tool, command, &self.tier_name, "denied", None);
                format!("Denied: {reason} (active tier: {})", self.tier_name)
            }
            Decision::Allowed => {
                let result = crate::executor::execute(command, &args, self.timeout).await;
                crate::audit::record_invocation(
                    tool,
                    command,
                    &self.tier_name,
                    "allowed",
                    result.exit_code,
                );
                if result.timed_out {
                    format!("Command timed out after {:?}", self.timeout)
                } else {
                    format!(
                        "exit code: {:?}\nstdout:\n{}\nstderr:\n{}",
                        result.exit_code, result.stdout, result.stderr
                    )
                }
            }
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for RedWrenchServer {}
