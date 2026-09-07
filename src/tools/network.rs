// src/tools/network.rs
use super::RedWrenchServer;
use rmcp::model::CallToolResult;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PingParams {
    /// Hostname or IP address to ping.
    pub host: String,
    /// Number of echo requests to send. Defaults to 4.
    #[serde(default = "default_count")]
    pub count: u32,
}

fn default_count() -> u32 {
    4
}

// NOTE (argument-injection hardening, same class of bug Task 11 fixed in
// dnf.rs): `host` is free text that ends up as ping's trailing *positional*
// argument, exactly the same shape as dnf's `package` (not journalctl's `-u
// <value>` case from Task 12, where the value is a required argument of a
// short flag rather than a trailing positional, and therefore not
// vulnerable to this class of attack). A `host` value such as `-f` (flood
// ping), `-i 0.01` (interval flooding, denial-of-service potential), or
// `-s <size>` (oversized packets) could be reinterpreted by ping's own
// getopt-style parser as a flag rather than a hostname, since the parser
// continues scanning trailing positional-looking arguments for more flags
// unless something stops it. `host` is reachable by anything that controls
// the MCP tool call, including a prompt-injected agent, which is exactly
// this project's threat model.
//
// The fix is the same as dnf's: a literal `--` separator before the
// trailing positional value. Standard Linux/iputils `ping` supports `--` as
// end-of-options like most GNU-convention tools, so everything after it is
// treated as positional, never as an option, regardless of what it starts
// with.
fn ping_argv(host: String, count: u32) -> Vec<String> {
    vec!["-c".into(), count.to_string(), "--".into(), host]
}

#[tool_router(router = network_router, vis = "pub(crate)")]
impl RedWrenchServer {
    #[tool(description = "Ping a host to check basic network reachability. Allowed under every tier.")]
    pub async fn ping(
        &self,
        Parameters(PingParams { host, count }): Parameters<PingParams>,
    ) -> CallToolResult {
        self.dispatch("ping", "ping", ping_argv(host, count)).await
    }

    #[tool(description = "Show network interface addresses. Allowed under every tier.")]
    pub async fn ip_addr(&self) -> CallToolResult {
        self.dispatch("ip_addr", "ip", vec!["addr".into()]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_argv_places_a_literal_double_dash_separator_before_the_host() {
        let args = ping_argv("-f".to_string(), 4);
        assert_eq!(args, vec!["-c", "4", "--", "-f"]);

        let dash_pos = args.iter().position(|a| a == "--").expect("-- separator missing");
        assert_eq!(dash_pos, args.len() - 2);
        assert_eq!(args.last().unwrap(), "-f");
    }

    #[test]
    fn a_flood_flag_like_host_value_is_safely_treated_as_positional() {
        let args = ping_argv("--flood".to_string(), 4);
        assert_eq!(args, vec!["-c", "4", "--", "--flood"]);
    }

    #[test]
    fn an_interval_flooding_host_value_is_safely_treated_as_positional() {
        let args = ping_argv("-i0.01".to_string(), 4);
        assert_eq!(args, vec!["-c", "4", "--", "-i0.01"]);
    }

    #[test]
    fn ordinary_host_values_are_unaffected() {
        assert_eq!(
            ping_argv("127.0.0.1".to_string(), 4),
            vec!["-c", "4", "--", "127.0.0.1"]
        );
        assert_eq!(
            ping_argv("example.com".to_string(), 10),
            vec!["-c", "10", "--", "example.com"]
        );
    }
}
