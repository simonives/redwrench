use super::RedWrenchServer;
use rmcp::model::CallToolResult;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DnfPackageParams {
    /// The package name, e.g. "htop". Only a single package per call.
    pub package: String,
}

#[tool_router(router = dnf_router, vis = "pub(crate)")]
impl RedWrenchServer {
    #[tool(
        description = "Install a package via dnf. On immutable Fedora variants, \
        prefer rpm-ostree via run_command instead, dnf itself may not persist \
        changes across a reboot on those systems. Requires the 'standard' tier."
    )]
    pub async fn dnf_install(
        &self,
        Parameters(DnfPackageParams { package }): Parameters<DnfPackageParams>,
    ) -> CallToolResult {
        self.dispatch(
            "dnf_install",
            "dnf",
            vec!["install".into(), "-y".into(), package],
        )
        .await
    }

    #[tool(description = "Remove a package via dnf. Requires the 'standard' tier.")]
    pub async fn dnf_remove(
        &self,
        Parameters(DnfPackageParams { package }): Parameters<DnfPackageParams>,
    ) -> CallToolResult {
        self.dispatch(
            "dnf_remove",
            "dnf",
            vec!["remove".into(), "-y".into(), package],
        )
        .await
    }
}
