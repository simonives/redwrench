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
    // (issue #75) Dedicated tool routers (dnf.rs, systemctl.rs,
    // network.rs) inject a literal "--" separator before user-controlled
    // tail arguments, hardening those handlers specifically against
    // argument injection (e.g. a "unit" value like "--host=attacker"
    // being parsed as a flag instead of a positional argument).
    // run_command has no such guard, it passes raw MCP-call arguments
    // straight to dispatch. PolicyEngine::evaluate makes no distinction
    // between "came through a dedicated router" and "came through
    // run_command", both hit the identical rule set, so today's
    // protection against argument injection genuinely rests entirely on
    // tiers.rs's regex denials, not on any argv-shape guarantee this
    // handler provides. This is not a bug today (every existing tool's
    // tiers.rs denies are believed comprehensive), but any future tool
    // added with a "--" guard in its own dedicated router and without an
    // equally comprehensive tiers.rs deny would be exposed via
    // run_command, since run_command bypasses the router-level guard
    // entirely. Treat tiers.rs's deny rules as the actual security
    // boundary for any new tool, never the router's own "--" injection.
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
