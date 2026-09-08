use super::RedWrenchServer;
use rmcp::model::CallToolResult;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunCommandParams {
    /// The executable to run, e.g. "systemctl". Never a full shell string.
    pub command: String,
    /// Arguments to pass, as separate argv entries, e.g. ["status", "sshd"].
    #[serde(default)]
    pub args: Vec<String>,
}

#[tool_router(router = run_command_router, vis = "pub(crate)")]
impl RedWrenchServer {
    #[tool(
        description = "Run an arbitrary command on the Fedora host, subject to the \
        active policy tier. Denied commands return an explanation of why, including \
        the active tier name, rather than a generic failure."
    )]
    pub async fn run_command(
        &self,
        Parameters(RunCommandParams { command, args }): Parameters<RunCommandParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        self.dispatch("run_command", &command, args, ctx, None)
            .await
    }
}
