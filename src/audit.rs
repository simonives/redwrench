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
pub fn init_logging() -> anyhow::Result<()> {
    match tracing_journald::layer() {
        Ok(journald_layer) => {
            tracing_subscriber::registry()
                .with(journald_layer)
                .try_init()?;
            Ok(())
        }
        Err(err) => {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
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

#[cfg(test)]
mod tests {
    use super::*;

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
