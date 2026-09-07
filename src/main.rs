mod cli;

use clap::Parser;
use redwrench::{audit, auth, config, policy, tools};
use std::sync::Arc;
use std::time::Duration;
use tools::RedWrenchServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        Some(cli::Command::Config {
            command: cli::ConfigCommand::SetTier { tier, i_understand_the_risk },
        }) => {
            let tier = match tier {
                cli::TierName::Safe => policy::tiers::TierName::Safe,
                cli::TierName::Standard => policy::tiers::TierName::Standard,
                cli::TierName::Unrestricted => policy::tiers::TierName::Unrestricted,
            };
            if matches!(tier, policy::tiers::TierName::Unrestricted) && !i_understand_the_risk {
                eprintln!(
                    "WARNING: the 'unrestricted' tier allows every command with no \
                     filtering, including destructive ones. This is not reversible \
                     by redwrench itself once a destructive command has run. \
                     If you understand this, re-run with --i-understand-the-risk."
                );
                return Err(anyhow::anyhow!(
                    "refusing to set the 'unrestricted' tier without --i-understand-the-risk"
                ));
            }
            update_tier_in_config(&cli.config, &tier)?;
            println!("Active tier set to {tier:?}.");
            Ok(())
        }
        None => run_server(&cli).await,
    }
}

fn update_tier_in_config(
    path: &std::path::Path,
    tier: &policy::tiers::TierName,
) -> anyhow::Result<()> {
    // Minimal implementation: read the existing file as a TOML table,
    // replace the `tier` key, write it back. Using toml::Value here
    // rather than the strict Config/RawConfig structs from Task 5,
    // since this needs to preserve unrelated keys (bearer_token,
    // bind_address, custom_rules) without needing to know their shape.
    let contents = std::fs::read_to_string(path)?;
    let mut value: toml::Value = contents.parse()?;
    let tier_str = match tier {
        policy::tiers::TierName::Safe => "safe",
        policy::tiers::TierName::Standard => "standard",
        policy::tiers::TierName::Unrestricted => "unrestricted",
    };
    value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config file is not a TOML table"))?
        .insert("tier".to_string(), toml::Value::String(tier_str.to_string()));
    std::fs::write(path, toml::to_string_pretty(&value)?)?;
    Ok(())
}

async fn run_server(cli: &cli::Cli) -> anyhow::Result<()> {
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
