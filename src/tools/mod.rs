use crate::policy::tiers::TierName;
use crate::policy::{Decision, PolicyEngine, Rule};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool_handler, ServerHandler};
use std::time::Duration;

pub mod dnf;
pub mod introspection;
pub mod journalctl;
pub mod network;
pub mod run_command;
pub mod systemctl;

#[derive(Clone)]
pub struct RedWrenchServer {
    pub policy: std::sync::Arc<PolicyEngine>,
    pub timeout: Duration,
    pub max_stream_duration: Duration,
    pub tier_name: String,
    pub tier: TierName,
    pub custom_rules: std::sync::Arc<Vec<Rule>>,
    /// `Some(identity)` only when the active tier is `developer` and its
    /// `developer_user` precondition resolved successfully at startup;
    /// `None` under every other tier, including `unrestricted` (the
    /// privilege drop is not inherited upward, see the design spec's
    /// non-goals). `dispatch()` consults this to decide whether a given
    /// call to a developer-tier tool should run under this identity
    /// instead of root.
    pub developer_identity: Option<crate::executor::DeveloperIdentity>,
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
    pub fn new(
        policy: std::sync::Arc<PolicyEngine>,
        timeout: Duration,
        tier_name: String,
        max_stream_duration: Duration,
        tier: TierName,
        custom_rules: Vec<Rule>,
        developer_identity: Option<crate::executor::DeveloperIdentity>,
    ) -> Self {
        Self {
            policy,
            timeout,
            max_stream_duration,
            tier_name,
            tier,
            custom_rules: std::sync::Arc::new(custom_rules),
            developer_identity,
            tool_router: Self::run_command_router()
                + Self::systemctl_router()
                + Self::dnf_router()
                + Self::journalctl_router()
                + Self::network_router()
                + Self::introspection_router(),
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
    pub async fn dispatch(
        &self,
        tool: &str,
        command: &str,
        args: Vec<String>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
        max_duration_override: Option<Duration>,
    ) -> CallToolResult {
        // The MCP request id, carried on every audit entry this call writes.
        // It is what lets an operator pair a "started" line with its
        // completion line when several long-running calls to the same tool
        // are in flight at once.
        let request_id = ctx.id.to_string();

        match self.policy.evaluate(command, &args) {
            Decision::Denied(reason) => {
                crate::audit::record_invocation(
                    tool,
                    command,
                    &args,
                    &self.tier_name,
                    "denied",
                    None,
                    &request_id,
                );
                let suggestion = crate::policy::introspection::lowest_tier_that_would_allow(
                    command,
                    &args,
                    &self.custom_rules,
                    &self.tier,
                )
                .map(|t| {
                    format!(
                        "; would be allowed at: {}",
                        crate::policy::tiers::tier_display_name(&t)
                    )
                })
                .unwrap_or_default();
                CallToolResult::error(vec![ContentBlock::text(format!(
                    "Denied: {reason} (active tier: {}{suggestion})",
                    self.tier_name
                ))])
            }
            Decision::Allowed => {
                // NOTE (rmcp API adaptation): the chunk sink only exists when
                // the caller supplied a progress token in the request's
                // `_meta`. Without one there is nothing to address a
                // `notifications/progress` message to, so streaming is simply
                // off and `execute()` buffers as before.
                let progress_token = ctx.meta.get_progress_token();

                // An explicit override always wins. Failing that, a caller
                // that attached a progress token has declared it can consume
                // a long-running stream, so the ceiling escalates to the
                // safety net rather than the ordinary timeout. Without this,
                // `run_command vmstat 1` (or `top -b`, or `ping` driven
                // through `run_command`) could never actually stream: it
                // passes no override, so it was permanently capped at
                // `self.timeout` no matter what the caller asked for. A
                // caller that sent no progress token still gets `self.timeout`
                // exactly as before.
                let effective_timeout = max_duration_override.unwrap_or_else(|| {
                    if progress_token.is_some() {
                        self.max_stream_duration
                    } else {
                        self.timeout
                    }
                });

                // A "started" audit entry is owed for two independent
                // reasons, so the gate tests for both. A call carrying a
                // duration override may run far past the ordinary timeout
                // before `record_invocation` ever logs its completion, and a
                // call carrying a progress token is streaming live output to
                // the caller right now. Gating on the override alone would
                // leave a bounded-but-streaming call with no record it was
                // ever in flight, which is exactly the gap `record_start`
                // exists to close.
                if max_duration_override.is_some() || progress_token.is_some() {
                    crate::audit::record_start(
                        tool,
                        command,
                        &args,
                        &self.tier_name,
                        crate::audit::start_reason(
                            progress_token.is_some(),
                            max_duration_override.is_some(),
                        ),
                        effective_timeout,
                        &request_id,
                    );
                }

                let chunk_sink = progress_token.map(|token| {
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
                    let peer = ctx.peer.clone();
                    let mut progress_count: f64 = 0.0;
                    tokio::spawn(async move {
                        while let Some(chunk) = rx.recv().await {
                            progress_count += 1.0;
                            let param = rmcp::model::ProgressNotificationParam::new(
                                token.clone(),
                                progress_count,
                            )
                            .with_message(chunk);
                            let _ = peer.notify_progress(param).await;
                        }
                    });
                    tx
                });

                // The privilege drop applies only to a developer-tier tool call, and
                // only when this server actually has a resolved developer_identity
                // (i.e. the active tier is exactly `developer`, see the field's own
                // doc comment on RedWrenchServer, it is never Some under any other
                // tier including unrestricted, so this check alone is sufficient,
                // no separate tier-name comparison needed here).
                let run_as = self
                    .developer_identity
                    .clone()
                    .filter(|_| crate::policy::tiers::DEVELOPER_TOOLS.contains(&command));

                let result = crate::executor::execute(
                    command,
                    &args,
                    effective_timeout,
                    Some(ctx.ct.clone()),
                    chunk_sink,
                    run_as,
                )
                .await;

                // The spec puts the audit log, not the MCP response, in
                // charge of preserving the difference between a call that
                // timed out and one the caller cancelled. Both surface an
                // `exit_code` of `None`, so a fixed "allowed" decision string
                // would collapse them into one indistinguishable audit event.
                // The decision field carries the real outcome instead.
                let decision = if result.cancelled {
                    "cancelled"
                } else if result.timed_out {
                    "timed_out"
                } else {
                    "allowed"
                };
                crate::audit::record_invocation(
                    tool,
                    command,
                    &args,
                    &self.tier_name,
                    decision,
                    result.exit_code,
                    &request_id,
                );
                if result.cancelled {
                    CallToolResult::error(vec![ContentBlock::text(
                        "Command cancelled by caller".to_string(),
                    )])
                } else if result.timed_out {
                    CallToolResult::error(vec![ContentBlock::text(format!(
                        "Command timed out after {effective_timeout:?}"
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

const README: &str = include_str!("../../README.md");
const ARCHITECTURE: &str = include_str!("../../ARCHITECTURE.md");

const README_URI: &str = "redwrench://docs/readme";
const ARCHITECTURE_URI: &str = "redwrench://docs/architecture";

#[tool_handler(router = self.tool_router)]
impl ServerHandler for RedWrenchServer {
    // NOTE (rmcp API adaptation): the task brief's plan assumed a version of
    // `rmcp::model::ServerInfo` (an alias for `InitializeResult`) that could
    // be built with `ServerInfo { capabilities: ..., ..Default::default() }`.
    // The pinned rmcp 3.2.0 marks `InitializeResult` `#[non_exhaustive]`, so
    // that struct-update syntax no longer compiles from outside the crate;
    // its own `InitializeResult::new(capabilities)` constructor is the
    // supported route to the same result.
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, rmcp::ErrorData> {
        Ok(rmcp::model::ListResourcesResult::with_all_items(vec![
            rmcp::model::Resource::new(README_URI, "readme")
                .with_description(
                    "RedWrench's README: what it is, how to install and configure it, \
                     and its tool catalogue.",
                )
                .with_mime_type("text/markdown"),
            rmcp::model::Resource::new(ARCHITECTURE_URI, "architecture")
                .with_description(
                    "RedWrench's architecture document: the policy engine, executor, \
                     and tier model.",
                )
                .with_mime_type("text/markdown"),
        ]))
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, rmcp::ErrorData> {
        let contents = match request.uri.as_str() {
            README_URI => rmcp::model::ResourceContents::text(README, &request.uri)
                .with_mime_type("text/markdown"),
            ARCHITECTURE_URI => rmcp::model::ResourceContents::text(ARCHITECTURE, &request.uri)
                .with_mime_type("text/markdown"),
            other => {
                return Err(rmcp::ErrorData::resource_not_found(
                    format!("no such resource: {other}"),
                    None,
                ))
            }
        };
        Ok(rmcp::model::ReadResourceResponse::Complete(
            rmcp::model::ReadResourceResult::new(vec![contents]),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::policy::{Effect, Rule};

    use rmcp::service::{serve_directly, RequestContext, RunningService};
    use rmcp::RoleServer;

    fn allow_all_server(timeout: Duration) -> RedWrenchServer {
        RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(vec![Rule {
                command: String::new(),
                arg_pattern: None,
                effect: Effect::Allow,
                description: "allow everything".to_string(),
            }])),
            timeout,
            "unrestricted".to_string(),
            Duration::from_secs(1800),
            crate::policy::tiers::TierName::Unrestricted,
            vec![],
            None,
        )
    }

    fn deny_all_server(timeout: Duration) -> RedWrenchServer {
        RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(vec![])),
            timeout,
            "safe".to_string(),
            Duration::from_secs(1800),
            crate::policy::tiers::TierName::Safe,
            vec![],
            None,
        )
    }

    fn developer_identity_for(username: &str) -> crate::executor::DeveloperIdentity {
        let user = nix::unistd::User::from_name(username)
            .unwrap()
            .unwrap_or_else(|| {
                panic!(
                    "'{username}' must exist on the Fedora test environment this project requires"
                )
            });
        crate::executor::DeveloperIdentity {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            name: user.name,
            home: user.dir,
        }
    }

    fn developer_tier_server(
        timeout: Duration,
        developer_identity: crate::executor::DeveloperIdentity,
    ) -> RedWrenchServer {
        RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(crate::policy::tiers::rules_for_tier(
                &crate::policy::tiers::TierName::Developer,
            ))),
            timeout,
            "developer".to_string(),
            Duration::from_secs(1800),
            crate::policy::tiers::TierName::Developer,
            vec![],
            Some(developer_identity),
        )
    }

    /// Builds a real `RequestContext<RoleServer>` for `dispatch()`'s tests.
    ///
    /// NOTE (rmcp API adaptation): `RequestContext::new` is public, but
    /// `Peer::new` is `pub(crate)` in rmcp 3.2.0, so a peer cannot be
    /// conjured directly from outside the crate. The public route to one is
    /// `serve_directly`, which skips the initialize handshake and hands back
    /// a `RunningService` whose `.peer()` is the `Peer<RoleServer>` we need.
    /// The returned `RunningService` is the guard that keeps that peer's
    /// channel alive, so callers must bind it for the duration of the test.
    pub(crate) fn test_request_context(
        server: &RedWrenchServer,
    ) -> (
        RequestContext<RoleServer>,
        RunningService<RoleServer, RedWrenchServer>,
    ) {
        let (server_transport, _client_transport) = tokio::io::duplex(4096);
        let running =
            serve_directly::<RoleServer, _, _, _, _>(server.clone(), server_transport, None);
        let ctx = RequestContext::new(
            rmcp::model::NumberOrString::Number(1),
            running.peer().clone(),
        );
        (ctx, running)
    }

    pub(crate) fn text_of(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|block| block.as_text())
            .map(|t| t.text.clone())
            .collect::<Vec<_>>()
            .join("")
    }

    #[tokio::test]
    async fn readme_resource_matches_the_real_file_on_disk() {
        let server = allow_all_server(Duration::from_secs(5));
        let real = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"),
        )
        .unwrap();
        let (ctx, _guard) = test_request_context(&server);
        let response = server
            .read_resource(
                rmcp::model::ReadResourceRequestParams::new(super::README_URI),
                ctx,
            )
            .await
            .unwrap();
        let result = match response {
            rmcp::model::ReadResourceResponse::Complete(r) => r,
            other => panic!("expected a complete response, got {other:?}"),
        };
        match &result.contents[0] {
            rmcp::model::ResourceContents::TextResourceContents { text, .. } => {
                assert_eq!(text, &real)
            }
            other => panic!("expected text contents, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_resource_rejects_an_unknown_uri() {
        let server = allow_all_server(Duration::from_secs(5));
        let (ctx, _guard) = test_request_context(&server);
        let response = server
            .read_resource(
                rmcp::model::ReadResourceRequestParams::new("redwrench://docs/nonexistent"),
                ctx,
            )
            .await;
        assert!(response.is_err());
    }

    #[tokio::test]
    async fn dispatch_drops_privilege_for_a_developer_tool_call() {
        let identity = developer_identity_for("nobody");
        let uid = identity.uid;

        let server = developer_tier_server(Duration::from_secs(5), identity);
        let (ctx, _guard) = test_request_context(&server);
        let result = server
            .dispatch(
                "run_command",
                "sh",
                vec!["-c".to_string(), "id -u".to_string()],
                ctx,
                None,
            )
            .await;

        assert_eq!(result.is_error, Some(false));
        // dispatch() formats a successful result as "exit code: ...\nstdout:\n<output>\nstderr:\n",
        // so asserting the dropped uid appears right after "stdout:\n" confirms
        // it's the command's own reported identity, not a coincidental match
        // elsewhere in the formatted text.
        assert!(
            text_of(&result).contains(&format!("stdout:\n{uid}")),
            "expected the dropped uid ({uid}) in the command output, got: {}",
            text_of(&result)
        );
    }

    #[tokio::test]
    async fn dispatch_does_not_drop_privilege_for_a_non_developer_tool_call() {
        // systemctl under the developer tier must behave exactly as it does
        // under standard: root, unaffected by developer_identity being set.
        // `systemctl status` is allowed under developer (inherited from
        // standard/safe) but `systemctl` is not in DEVELOPER_TOOLS, so this
        // call must not have privilege dropped. This test confirms the call
        // reaches the executor at all (is not denied by policy), it cannot
        // itself observe "ran as root" without a real systemctl target on the
        // test machine, that is what the run_as_drops_privilege tests in
        // executor.rs already cover for the mechanism itself.
        let server =
            developer_tier_server(Duration::from_secs(5), developer_identity_for("nobody"));
        let (ctx, _guard) = test_request_context(&server);
        let result = server
            .dispatch(
                "systemctl_status",
                "systemctl",
                vec!["status".to_string(), "sshd".to_string()],
                ctx,
                None,
            )
            .await;
        assert!(
            !text_of(&result).starts_with("Denied:"),
            "systemctl status must still be allowed under developer tier, got: {}",
            text_of(&result)
        );
    }

    #[tokio::test]
    async fn dispatch_returns_a_structured_error_result_when_the_policy_denies() {
        let server = deny_all_server(Duration::from_secs(5));
        let (ctx, _guard) = test_request_context(&server);
        let result = server
            .dispatch(
                "run_command",
                "rm",
                vec!["-rf".to_string(), "/".to_string()],
                ctx,
                None,
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
    async fn dispatch_denial_message_names_the_tier_that_would_allow_it() {
        let server = RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(crate::policy::tiers::rules_for_tier(
                &crate::policy::tiers::TierName::Safe,
            ))),
            Duration::from_secs(5),
            "safe".to_string(),
            Duration::from_secs(1800),
            crate::policy::tiers::TierName::Safe,
            vec![],
            None,
        );
        let (ctx, _guard) = test_request_context(&server);
        // dnf is not in safe_rules() at all, but standard_rules() adds it.
        let result = server
            .dispatch(
                "dnf_install",
                "dnf",
                vec!["install".to_string(), "htop".to_string()],
                ctx,
                None,
            )
            .await;
        let text = text_of(&result);
        assert!(
            text.contains("would be allowed at: standard"),
            "got: {text}"
        );
    }

    #[tokio::test]
    async fn dispatch_denial_message_has_no_suggestion_when_no_tier_would_allow_it() {
        let custom = vec![Rule {
            command: "dnf".to_string(),
            arg_pattern: None,
            effect: Effect::Deny,
            description: "custom: never allow dnf".to_string(),
        }];
        let mut rules = custom.clone();
        rules.extend(crate::policy::tiers::rules_for_tier(
            &crate::policy::tiers::TierName::Safe,
        ));
        let server = RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(rules)),
            Duration::from_secs(5),
            "safe".to_string(),
            Duration::from_secs(1800),
            crate::policy::tiers::TierName::Safe,
            custom,
            None,
        );
        let (ctx, _guard) = test_request_context(&server);
        let result = server
            .dispatch(
                "dnf_install",
                "dnf",
                vec!["install".to_string(), "htop".to_string()],
                ctx,
                None,
            )
            .await;
        let text = text_of(&result);
        assert!(!text.contains("would be allowed at"), "got: {text}");
    }

    #[tokio::test]
    async fn dispatch_returns_a_successful_result_with_real_output_when_the_policy_allows() {
        let server = allow_all_server(Duration::from_secs(5));
        let (ctx, _guard) = test_request_context(&server);
        let result = server
            .dispatch("run_command", "echo", vec!["hello".to_string()], ctx, None)
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
        let (ctx, _guard) = test_request_context(&server);
        let result = server
            .dispatch("run_command", "sleep", vec!["5".to_string()], ctx, None)
            .await;

        // A timeout produced no real output, so from the calling agent's
        // perspective it is a failed call, same `is_error: true` shape as a
        // policy denial, not the same shape as a command that actually
        // completed with real stdout.
        assert_eq!(result.is_error, Some(true));
        let text = text_of(&result);
        assert!(text.contains("timed out"), "unexpected text: {text}");
    }

    #[tokio::test]
    async fn dispatch_reports_cancellation_as_a_structured_error_result() {
        let server = allow_all_server(Duration::from_secs(60));
        let (ctx, _guard) = test_request_context(&server);
        ctx.ct.cancel();
        let result = server
            .dispatch("run_command", "sleep", vec!["30".to_string()], ctx, None)
            .await;

        assert_eq!(result.is_error, Some(true));
        let text = text_of(&result);
        assert!(text.contains("cancelled"), "unexpected text: {text}");
    }

    #[tokio::test]
    async fn a_duration_override_is_used_instead_of_the_default_timeout() {
        // A short default timeout would normally kill this in 100ms; the
        // override lets a streaming/follow call run for up to 5s instead.
        let server = allow_all_server(Duration::from_millis(100));
        let (ctx, _guard) = test_request_context(&server);
        let result = server
            .dispatch(
                "ping",
                "sleep",
                vec!["1".to_string()],
                ctx,
                Some(Duration::from_secs(5)),
            )
            .await;
        assert_eq!(result.is_error, Some(false));
        assert!(!text_of(&result).is_empty());
    }

    #[tokio::test]
    async fn an_attached_progress_token_escalates_the_ceiling_to_the_safety_net() {
        // No `max_duration_override`, so before this fix the call was capped
        // at `self.timeout` (100ms here) and `run_command` could never reach
        // indefinite execution however the caller asked. Attaching a progress
        // token is the caller declaring it can consume a long stream, so the
        // ceiling becomes `max_stream_duration` (1800s from
        // `allow_all_server`) instead, and a 300ms command completes.
        let server = allow_all_server(Duration::from_millis(100));
        let (server_transport, _client_transport) = tokio::io::duplex(64 * 1024);
        let _running =
            serve_directly::<RoleServer, _, _, _, _>(server.clone(), server_transport, None);
        let mut ctx = RequestContext::new(
            rmcp::model::NumberOrString::Number(1),
            _running.peer().clone(),
        );
        ctx.meta.set_progress_token(rmcp::model::ProgressToken(
            rmcp::model::NumberOrString::String("escalation-test".into()),
        ));

        let result = server
            .dispatch(
                "run_command",
                "sh",
                vec!["-c".to_string(), "sleep 0.3; echo done".to_string()],
                ctx,
                None,
            )
            .await;

        assert_eq!(
            result.is_error,
            Some(false),
            "expected the call to outlive self.timeout, got: {}",
            text_of(&result)
        );
        assert!(text_of(&result).contains("done"));
    }

    #[tokio::test]
    async fn without_a_progress_token_the_default_timeout_still_applies() {
        // The other half of the escalation rule: a caller that attaches
        // nothing must see byte-identical pre-streaming behaviour, so the
        // same 300ms command still times out against a 100ms timeout.
        let server = allow_all_server(Duration::from_millis(100));
        let (ctx, _guard) = test_request_context(&server);
        let result = server
            .dispatch(
                "run_command",
                "sh",
                vec!["-c".to_string(), "sleep 0.3; echo done".to_string()],
                ctx,
                None,
            )
            .await;

        assert_eq!(result.is_error, Some(true));
        assert!(text_of(&result).contains("timed out"));
    }

    #[tokio::test]
    async fn a_leaked_reader_cannot_keep_streaming_after_the_call_has_ended() {
        // The grandchild shape: `sh` exits at once, but the backgrounded
        // subshell inherits both pipe write ends and outlives it. Its `echo
        // leaked` fires at ~3s, deliberately past POST_EXIT_READ_TIMEOUT (2s),
        // so it lands after `dispatch()` has already returned its result.
        //
        // Before the fix, the elapsed post-exit drain merely dropped the
        // reader's `JoinHandle`, which detaches a Tokio task rather than
        // cancelling it. The detached reader still held a live `ChunkSink`
        // clone, so "leaked" would be forwarded to `peer.notify_progress` and
        // a `notifications/progress` frame would appear on the wire for a call
        // that was already over. The explicit `.abort()` is what stops it.
        use tokio::io::{AsyncBufReadExt, BufReader};

        let server = allow_all_server(Duration::from_secs(30));
        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let _running =
            serve_directly::<RoleServer, _, _, _, _>(server.clone(), server_transport, None);
        let mut ctx = RequestContext::new(
            rmcp::model::NumberOrString::Number(1),
            _running.peer().clone(),
        );
        ctx.meta.set_progress_token(rmcp::model::ProgressToken(
            rmcp::model::NumberOrString::String("leak-test".into()),
        ));

        let result = server
            .dispatch(
                "run_command",
                "sh",
                vec![
                    "-c".to_string(),
                    "echo one; (sleep 3; echo leaked; sleep 30) & exit 0".to_string(),
                ],
                ctx,
                None,
            )
            .await;
        assert_eq!(result.is_error, Some(false));

        // Read the wire for a bounded window that spans the grandchild's
        // 3s emission. Nothing carrying "leaked" may arrive.
        let mut reader = BufReader::new(client_transport);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(2500);
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout_at(deadline, reader.read_line(&mut line)).await;
            let Ok(Ok(n)) = read else {
                break;
            };
            if n == 0 {
                break;
            }
            let Ok(frame) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            if frame["method"] == "notifications/progress" {
                let message = frame["params"]["message"].as_str().unwrap_or_default();
                assert!(
                    !message.contains("leaked"),
                    "a detached reader kept streaming after the call ended: {frame:?}"
                );
            }
        }
    }

    /// Regression guard on the streaming path itself.
    ///
    /// Every other test here goes through `test_request_context`, whose
    /// `RequestContext::new` leaves `meta` empty, so
    /// `ctx.meta.get_progress_token()` returns `None` and the chunk sink is
    /// never built. This test is the only one that sets a real progress
    /// token, and so the only one that exercises the sink and the
    /// `peer.notify_progress(...)` call at all.
    ///
    /// It asserts at the wire level rather than through a typed struct: it
    /// keeps the *client* half of the duplex transport (the half the shared
    /// helper throws away), reads the newline-delimited JSON-RPC frames rmcp
    /// writes there, and inspects the raw JSON. That is what makes the
    /// "`total` is absent" assertion meaningful, since these calls have no
    /// known duration and the design intent is that no bogus denominator is
    /// ever put on the wire.
    #[tokio::test]
    async fn output_chunks_are_streamed_to_the_caller_as_progress_notifications() {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let server = allow_all_server(Duration::from_secs(10));
        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let _running =
            serve_directly::<RoleServer, _, _, _, _>(server.clone(), server_transport, None);

        let mut ctx = RequestContext::new(
            rmcp::model::NumberOrString::Number(1),
            _running.peer().clone(),
        );
        ctx.meta.set_progress_token(rmcp::model::ProgressToken(
            rmcp::model::NumberOrString::String("stream-test".into()),
        ));

        // Two writes separated by a pause, so the pipe genuinely yields two
        // distinct reads and therefore two distinct chunks. A single
        // `echo one; echo two` could be coalesced into one read and would
        // prove nothing about the counter advancing.
        let result = server
            .dispatch(
                "run_command",
                "sh",
                vec![
                    "-c".to_string(),
                    "echo one; sleep 0.3; echo two".to_string(),
                ],
                ctx,
                None,
            )
            .await;
        assert_eq!(result.is_error, Some(false));

        // The notifications are sent from a spawned task, so they may still
        // be in flight when `dispatch` returns. Read until two progress
        // frames have arrived, bounded so a genuine failure fails the test
        // rather than hanging it.
        let mut reader = BufReader::new(client_transport);
        let mut progress_frames: Vec<serde_json::Value> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while progress_frames.len() < 2 {
            let mut line = String::new();
            let read = tokio::time::timeout_at(deadline, reader.read_line(&mut line)).await;
            let Ok(Ok(n)) = read else {
                break;
            };
            if n == 0 {
                break;
            }
            let Ok(frame) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            if frame["method"] == "notifications/progress" {
                progress_frames.push(frame);
            }
        }

        assert!(
            progress_frames.len() >= 2,
            "expected at least two progress notifications, got {}: {progress_frames:?}",
            progress_frames.len()
        );

        let mut last_progress = 0.0_f64;
        let mut streamed = String::new();
        for frame in &progress_frames {
            let params = &frame["params"];

            assert_eq!(
                params["progressToken"], "stream-test",
                "notification addressed to the wrong token: {frame:?}"
            );

            let progress = params["progress"]
                .as_f64()
                .unwrap_or_else(|| panic!("progress was not a number: {frame:?}"));
            assert!(
                progress > last_progress,
                "progress counter did not increase: {last_progress} then {progress}"
            );
            last_progress = progress;

            // Duration is unknown for a streaming call, so no denominator is
            // claimed. Absent from the JSON, not merely null.
            assert!(
                params.get("total").is_none(),
                "total must not appear on the wire: {frame:?}"
            );

            streamed.push_str(
                params["message"]
                    .as_str()
                    .unwrap_or_else(|| panic!("message was missing or not a string: {frame:?}")),
            );
        }

        assert!(
            streamed.contains("one") && streamed.contains("two"),
            "streamed chunks did not carry the command's output: {streamed:?}"
        );
    }
}
