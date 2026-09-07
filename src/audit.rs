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
pub fn record_invocation(
    tool: &str,
    command: &str,
    args: &[String],
    tier: &str,
    decision: &str,
    exit_code: Option<i32>,
) {
    tracing::info!(
        target: "redwrench::audit",
        tool,
        command,
        args = %args.join(" "),
        tier,
        decision,
        exit_code,
        "tool invocation"
    );
}
