// src/tools/network.rs
use super::RedWrenchServer;
use rmcp::model::CallToolResult;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PingParams {
    /// Hostname or IP address to ping.
    pub host: String,
    /// Number of echo requests to send. Omit to ping indefinitely (no
    /// packet count) until the caller cancels the call or the server's
    /// safety-net duration elapses.
    #[serde(default)]
    pub count: Option<u32>,
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
fn ping_argv(host: String, count: Option<u32>) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(count) = count {
        args.push("-c".to_string());
        args.push(count.to_string());
    }
    args.push("--".to_string());
    args.push(host);
    args
}

#[tool_router(router = network_router, vis = "pub(crate)")]
impl RedWrenchServer {
    #[tool(
        description = "Ping a host to check basic network reachability. Omit \
        'count' to ping indefinitely (bounded by the server's safety-net \
        duration or cancellation). Allowed under every tier."
    )]
    pub async fn ping(
        &self,
        Parameters(PingParams { host, count }): Parameters<PingParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        // An indefinite ping (no count) is exactly the case this whole
        // feature exists for: something that never exits on its own,
        // bounded only by the safety-net duration or a caller cancelling
        // it. A bounded ping (count given) keeps the ordinary timeout.
        let max_duration_override = if count.is_none() {
            Some(self.max_stream_duration)
        } else {
            None
        };
        self.dispatch(
            "ping",
            "ping",
            ping_argv(host, count),
            ctx,
            max_duration_override,
        )
        .await
    }

    #[tool(description = "Show network interface addresses. Allowed under every tier.")]
    pub async fn ip_addr(
        &self,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        self.dispatch("ip_addr", "ip", vec!["addr".into()], ctx, None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_argv_places_a_literal_double_dash_separator_before_the_host() {
        let args = ping_argv("-f".to_string(), Some(4));
        assert_eq!(args, vec!["-c", "4", "--", "-f"]);

        let dash_pos = args
            .iter()
            .position(|a| a == "--")
            .expect("-- separator missing");
        assert_eq!(dash_pos, args.len() - 2);
        assert_eq!(args.last().unwrap(), "-f");
    }

    #[test]
    fn a_flood_flag_like_host_value_is_safely_treated_as_positional() {
        let args = ping_argv("--flood".to_string(), Some(4));
        assert_eq!(args, vec!["-c", "4", "--", "--flood"]);
    }

    #[test]
    fn an_interval_flooding_host_value_is_safely_treated_as_positional() {
        let args = ping_argv("-i0.01".to_string(), Some(4));
        assert_eq!(args, vec!["-c", "4", "--", "-i0.01"]);
    }

    #[test]
    fn ordinary_host_values_are_unaffected() {
        assert_eq!(
            ping_argv("127.0.0.1".to_string(), Some(4)),
            vec!["-c", "4", "--", "127.0.0.1"]
        );
        assert_eq!(
            ping_argv("example.com".to_string(), Some(10)),
            vec!["-c", "10", "--", "example.com"]
        );
    }

    #[test]
    fn omitting_count_produces_an_indefinite_ping_with_no_dash_c_flag() {
        let args = ping_argv("8.8.8.8".to_string(), None);
        assert_eq!(args, vec!["--", "8.8.8.8"]);
        assert!(
            !args.iter().any(|a| a == "-c"),
            "an indefinite ping must never include -c: {args:?}"
        );
    }

    #[test]
    fn a_present_count_still_produces_a_bounded_ping() {
        let args = ping_argv("8.8.8.8".to_string(), Some(4));
        assert_eq!(args, vec!["-c", "4", "--", "8.8.8.8"]);
    }
}
