mod cli;

use clap::Parser;
use redwrench::{audit, auth, config, policy, tools};
use std::sync::Arc;
use std::time::Duration;
use tools::RedWrenchServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    if let Err(err) = audit::init_journal_logging() {
        eprintln!("warning: could not initialise journal logging: {err}");
    }

    let config = config::Config::load(&cli.config)?;
    auth::validate_bind_address(&config.bind_address, cli.allow_public_bind)?;

    // Post-review fix: the 'unrestricted' tier must not be reachable via a
    // bare config file edit alone (spec's global constraint). Task 14 gates
    // *writing* 'unrestricted' into config via a CLI subcommand, but that
    // can't close the hole in this read/start path: anyone can hand-edit
    // config.toml directly, so the gate has to live here too, at the point
    // the tier is actually loaded and turned into a running policy.
    if config.tier == policy::tiers::TierName::Unrestricted {
        if !cli.i_understand_the_risk {
            anyhow::bail!(
                "config specifies the 'unrestricted' policy tier, which allows \
                 arbitrary command execution with no policy restrictions. \
                 Refusing to start without --i-understand-the-risk. This \
                 cannot be enabled by a config file edit alone."
            );
        }
        eprintln!(
            "WARNING: starting with the 'unrestricted' policy tier active. \
             All commands will be allowed with no policy restrictions."
        );
    }

    let tier_name = format!("{:?}", config.tier).to_lowercase();
    let server = RedWrenchServer::new(
        Arc::new(policy::PolicyEngine::new(config.effective_rules())),
        Duration::from_secs(30),
        tier_name,
    );

    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    let http_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        http_config,
    );

    let bearer_token = config.bearer_token.clone();
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn(move |req, next| {
            let token = bearer_token.clone();
            async move { auth::require_bearer_token(token, req, next).await }
        }),
    );

    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    tracing::info!(target: "redwrench::audit", bind_address = %config.bind_address, "redwrench starting");
    axum::serve(listener, router).await?;
    Ok(())
}
