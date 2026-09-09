use tracing_subscriber::prelude::*;

/// Installs the process-wide tracing subscriber that carries the audit
/// trail.
///
/// Prefers journald, matching the spec's "writes a structured entry to the
/// systemd journal". If journald is unreachable (a container without
/// `/run/systemd/journal/socket`, a non-systemd host, a restricted
/// sandbox), this falls back to a plain stderr subscriber rather than
/// leaving the process with **no** subscriber at all.
///
/// That fallback is the whole point of this function: `tracing` macros are
/// silent no-ops when nothing is subscribed, so a failed journald init used
/// to mean every subsequent `record_invocation` and every auth-failure
/// warning vanished for the lifetime of the process, after a single
/// easily-missed line on stderr. A security tool's audit trail must not
/// fail open and quiet. Under systemd, a unit with `StandardError=journal`
/// still routes the fallback output into the journal anyway.
///
/// Returns `Err` only if *neither* subscriber could be installed, which in
/// practice means a subscriber was already set by someone else.
///
/// NOTE (post-review fix, full command output was leaking into the
/// persistent journal): every deliberate log line RedWrench itself emits
/// targets `"redwrench::audit"` (see [`record_invocation`], [`record_start`],
/// and the auth-rejection warnings in `src/auth.rs`), and each one is a
/// narrow, structured line by design, tool, command, tier, decision,
/// nothing else. Without a filter, that restraint was cosmetic: `rmcp`'s own
/// internal instrumentation (a `tracing::info!` per request/response inside
/// its `serve_inner` span) was reaching the same subscriber unfiltered, and
/// that instrumentation `Debug`-prints the full `CallToolResult`, meaning
/// every command's complete stdout/stderr (a `systemctl status` dump
/// including live SSH session details, in the case that surfaced this) was
/// being written to the persistent systemd journal a second time, outside
/// the one audit channel the design intends. Found live, via manual UAT
/// against a real deployment, not in any test, since none of the existing
/// tests read the journal's actual contents; they only assert the presence
/// of `record_invocation`'s own fields. Restricting both layers to the
/// `redwrench::audit` target at `INFO` and above closes this without
/// touching a single call site, RedWrench's own logging was already
/// correctly scoped, only the absence of a filter let something else's
/// logging ride along.
pub fn init_logging() -> anyhow::Result<()> {
    let audit_only = audit_only_filter();

    match tracing_journald::layer() {
        Ok(journald_layer) => {
            tracing_subscriber::registry()
                .with(journald_layer.with_filter(audit_only))
                .try_init()?;
            Ok(())
        }
        Err(err) => {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_filter(audit_only),
                )
                .try_init()?;
            tracing::warn!(
                target: "redwrench::audit",
                error = %err,
                "journald unavailable, audit trail is being written to stderr instead"
            );
            Ok(())
        }
    }
}

/// Writes one structured audit entry for a tool invocation.
///
/// `args` is included because the binary name alone cannot answer the
/// questions an audit trail exists to answer: which package was installed,
/// which unit was stopped, what a denied `run_command` actually tried to
/// run. The spec calls for the *resolved command*, not just the executable.
///
/// `request_id` is the MCP request id, carried on both this entry and the
/// matching [`record_start`] entry. Without it the two lines for one call
/// cannot be paired: two concurrent `journalctl_tail` calls with `follow`
/// set against the same unit produce two indistinguishable "started" lines
/// and, minutes later, two indistinguishable completion lines.
pub fn record_invocation(
    tool: &str,
    command: &str,
    args: &[String],
    tier: &str,
    decision: &str,
    exit_code: Option<i32>,
    request_id: &str,
) {
    tracing::info!(
        target: "redwrench::audit",
        request_id,
        tool,
        command,
        args = %args.join(" "),
        tier,
        decision,
        exit_code,
        "tool invocation"
    );
}

/// Writes an audit entry when a streaming or indefinite call begins.
///
/// A call using streaming or the safety-net duration (rather than the
/// ordinary default timeout) may run for a long time before
/// `record_invocation` ever logs its completion. Without a "started"
/// entry, an operator has no record such a call was even in flight until
/// it eventually ends, possibly tens of minutes later.
///
/// `reason` says *why* this call qualifies (see [`start_reason`]): the
/// message used to read "streaming invocation started" even for a call that
/// was merely indefinite with no progress token attached, which is the one
/// distinction an operator reading this line most wants. `duration` records
/// the ceiling that actually applies, so the started entry says how long
/// this call may legitimately run, not just that it began. `request_id`
/// pairs this entry with its [`record_invocation`] completion line.
pub fn record_start(
    tool: &str,
    command: &str,
    args: &[String],
    tier: &str,
    reason: &str,
    duration: std::time::Duration,
    request_id: &str,
) {
    tracing::info!(
        target: "redwrench::audit",
        request_id,
        tool,
        command,
        args = %args.join(" "),
        tier,
        reason,
        duration = %format!("{duration:?}"),
        "long-running invocation started"
    );
}

/// Classifies why a call earned a [`record_start`] entry.
///
/// The two triggers are independent: a call may stream (progress token
/// attached), run past the ordinary timeout (duration override), or both.
pub fn start_reason(streaming: bool, indefinite: bool) -> &'static str {
    match (streaming, indefinite) {
        (true, true) => "streaming+indefinite",
        (true, false) => "streaming",
        (false, true) => "indefinite",
        (false, false) => "none",
    }
}

/// The filter `init_logging` applies to both the journald and stderr-fallback
/// layers. Extracted to a plain function, rather than inlined twice, so it
/// can also be exercised directly in tests without standing up a real
/// subscriber (there is no journald socket in CI, and asserting against a
/// live journal's contents would be a slow, environment-dependent test for
/// what is really a pure "does this filter admit this target/level" check).
fn audit_only_filter() -> tracing_subscriber::filter::Targets {
    use tracing_subscriber::filter::LevelFilter;
    tracing_subscriber::filter::Targets::new()
        .with_target("redwrench::audit", LevelFilter::INFO)
        .with_default(LevelFilter::OFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn the_audit_filter_admits_only_the_redwrench_audit_target() {
        let filter = audit_only_filter();
        assert!(
            filter.would_enable("redwrench::audit", &Level::INFO),
            "the one deliberate audit channel must not be silenced"
        );
        assert!(
            filter.would_enable("redwrench::audit", &Level::WARN),
            "the auth-rejection warnings in src/auth.rs also target \
             redwrench::audit at WARN, and must still get through"
        );
    }

    #[test]
    fn the_audit_filter_rejects_everything_else_including_at_info_level() {
        // This is the regression the fix exists for: rmcp's own internal
        // instrumentation targets its own module paths, at INFO, and
        // Debug-prints the full request/response (including a command's
        // complete stdout/stderr) on every call. A filter that only checked
        // level, not target, would let this straight through, since it is
        // logged at the same level RedWrench's own audit lines use.
        let filter = audit_only_filter();
        assert!(!filter.would_enable("rmcp::service", &Level::INFO));
        assert!(!filter.would_enable(
            "rmcp::transport::streamable_http_server::tower",
            &Level::INFO
        ));
        // Not even at a level above what the audit target requires: this
        // must be a target allowlist, not merely a level floor that happens
        // to exclude DEBUG/TRACE noise.
        assert!(!filter.would_enable("some_other_crate", &Level::ERROR));
    }

    #[test]
    fn the_start_reason_names_which_trigger_fired() {
        // The old fixed message claimed "streaming" for a call that was
        // merely indefinite. Each combination now gets its own answer.
        assert_eq!(start_reason(true, false), "streaming");
        assert_eq!(start_reason(false, true), "indefinite");
        assert_eq!(start_reason(true, true), "streaming+indefinite");
        assert_eq!(start_reason(false, false), "none");
    }
}
