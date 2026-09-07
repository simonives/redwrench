use tracing_subscriber::prelude::*;

pub fn init_journal_logging() -> anyhow::Result<()> {
    let journald_layer = tracing_journald::layer()?;
    tracing_subscriber::registry().with(journald_layer).init();
    Ok(())
}

pub fn record_invocation(
    tool: &str,
    command: &str,
    tier: &str,
    decision: &str,
    exit_code: Option<i32>,
) {
    tracing::info!(
        target: "redwrench::audit",
        tool,
        command,
        tier,
        decision,
        exit_code,
        "tool invocation"
    );
}
