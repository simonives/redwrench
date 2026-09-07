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

#[tool_router(router = systemctl_router, vis = "pub(crate)")]
impl RedWrenchServer {
    #[tool(
        description = "Check the status of a systemd unit (read-only, allowed under every tier)."
    )]
    pub async fn systemctl_status(
        &self,
        Parameters(SystemctlStatusParams { unit }): Parameters<SystemctlStatusParams>,
    ) -> CallToolResult {
        self.dispatch("systemctl_status", "systemctl", vec!["status".into(), unit])
            .await
    }

    #[tool(
        description = "Start, stop, restart, enable, or disable a systemd unit. \
        Requires at least the 'standard' policy tier."
    )]
    pub async fn systemctl_control(
        &self,
        Parameters(SystemctlControlParams { action, unit }): Parameters<SystemctlControlParams>,
    ) -> CallToolResult {
        self.dispatch("systemctl_control", "systemctl", vec![action, unit])
            .await
    }
}
