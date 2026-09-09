mod cli;

use clap::Parser;
use redwrench::executor::DeveloperIdentity;
use redwrench::{audit, auth, config, policy, tools};
use std::sync::Arc;
use std::time::Duration;
use tools::RedWrenchServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        Some(cli::Command::Config {
            command:
                cli::ConfigCommand::SetTier {
                    tier,
                    i_understand_the_risk,
                },
        }) => {
            let tier = match tier {
                cli::TierName::Safe => policy::tiers::TierName::Safe,
                cli::TierName::Standard => policy::tiers::TierName::Standard,
                cli::TierName::Developer => policy::tiers::TierName::Developer,
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
        policy::tiers::TierName::Developer => "developer",
        policy::tiers::TierName::Unrestricted => "unrestricted",
    };
    value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config file is not a TOML table"))?
        .insert(
            "tier".to_string(),
            toml::Value::String(tier_str.to_string()),
        );
    std::fs::write(path, toml::to_string_pretty(&value)?)?;
    Ok(())
}

/// Resolves a username to the identity developer-tier commands run
/// under: numeric uid/gid, plus the account's own name and home
/// directory (the child process's `HOME`/`USER`/`LOGNAME` and working
/// directory, see `executor::DeveloperIdentity`). `Ok(None)` is never
/// returned: `nix::unistd::User::from_name` returning `Ok(None)`
/// (username not found) is turned into a proper error here, since every
/// caller of this function needs a resolved identity or a reason it
/// failed, not a third "maybe" state to handle separately.
fn resolve_user(username: &str) -> anyhow::Result<DeveloperIdentity> {
    let user = nix::unistd::User::from_name(username)
        .map_err(|err| anyhow::anyhow!("failed to look up user '{username}': {err}"))?
        .ok_or_else(|| anyhow::anyhow!("no such user '{username}' on this system"))?;
    Ok(DeveloperIdentity {
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
        name: user.name,
        home: user.dir,
    })
}

/// Checks the `developer` tier's precondition (a valid `developer_user`)
/// and resolves it if the tier needs it. Returns the resolved identity
/// so the caller doesn't have to resolve the same username twice.
///
/// Designed as a standalone function from the start, rather than inline
/// logic in `run_server`, so it can be unit-tested directly: that
/// function binds a real TCP listener and calls `axum::serve`, which
/// never returns under normal operation, so it cannot itself be exercised
/// by a `#[test]` the way this pure validation step can.
fn validate_developer_tier_precondition(
    tier: &policy::tiers::TierName,
    developer_user: &Option<String>,
) -> anyhow::Result<Option<DeveloperIdentity>> {
    if !matches!(tier, policy::tiers::TierName::Developer) {
        return Ok(None);
    }
    let username = developer_user.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "config specifies the 'developer' policy tier, which requires \
             'developer_user' to be set (the account developer-tier tool \
             execution runs as instead of root). Refusing to start without it."
        )
    })?;
    let identity = resolve_user(username).map_err(|err| {
        anyhow::anyhow!(
            "config specifies the 'developer' policy tier with \
             developer_user = \"{username}\", but that account could not be \
             resolved: {err}"
        )
    })?;
    // A developer_user that resolves to uid 0 is the one value that makes
    // this tier a silent no-op: every precondition passes, the tier reports
    // itself as 'developer', and every developer-tier command still runs as
    // root, which is the exact outcome the tier exists to prevent. Refuse it
    // at startup, the same posture as every other precondition failure on
    // this path, rather than warning and starting anyway.
    if identity.uid == 0 {
        anyhow::bail!(
            "config specifies the 'developer' policy tier with \
             developer_user = \"{username}\", but that account resolves to \
             uid 0 (root). The entire safety mechanism of this tier is \
             running developer-tier commands as a non-root account, so \
             dropping privilege to root would make it a no-op. Refusing to \
             start. Set 'developer_user' to a regular, unprivileged account."
        );
    }
    Ok(Some(identity))
}

async fn run_server(cli: &cli::Cli) -> anyhow::Result<()> {
    // NOTE (post-review fix, audit must not fail silently): if journald is
    // unavailable (containers, non-systemd hosts), `audit::init_logging`
    // previously left NO tracing subscriber installed, which turns every
    // subsequent audit record and auth-failure warning into a permanent
    // no-op after one easily-missed startup line. The spec's audit
    // requirement is unconditional, so we fall back to a stderr subscriber
    // instead (a systemd unit with `StandardError=journal` still lands
    // those entries in the journal). We deliberately do not fail hard here:
    // refusing to start when journald is absent would add a new
    // denial-of-service surface without making the audit trail any better.
    if let Err(err) = audit::init_logging() {
        eprintln!("warning: could not initialise any logging subscriber: {err}");
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

    let developer_identity =
        validate_developer_tier_precondition(&config.tier, &config.developer_user)?;

    let tier_name = format!("{:?}", config.tier).to_lowercase();
    let server = RedWrenchServer::new(
        Arc::new(policy::PolicyEngine::new(config.effective_rules())),
        Duration::from_secs(config.timeout_secs),
        tier_name,
        Duration::from_secs(config.max_stream_duration_secs),
        developer_identity,
    );

    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    let http_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(allowed_hosts_for(&config.bind_address));

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        http_config,
    );

    let bearer_token = config.bearer_token.clone();
    let router =
        axum::Router::new()
            .nest_service("/mcp", service)
            .layer(axum::middleware::from_fn(move |req, next| {
                let token = bearer_token.clone();
                async move { auth::require_bearer_token(token, req, next).await }
            }));

    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    tracing::info!(target: "redwrench::audit", bind_address = %config.bind_address, "redwrench starting");
    axum::serve(listener, router).await?;
    Ok(())
}

/// The Host headers `StreamableHttpServerConfig` accepts, as a DNS-rebinding
/// defence: any request whose Host header doesn't match one of these is
/// rejected with a 403, regardless of a valid bearer token.
///
/// NOTE (post-review fix, DNS-rebinding allowlist blocked every real
/// client): rmcp's `StreamableHttpServerConfig::default()` only allows
/// `localhost`/`127.0.0.1`/`::1`. RedWrench is designed to be bound to and
/// reached over a non-loopback address (a Tailscale IP, typically), so the
/// unmodified default silently made the server unreachable by the one
/// client it actually exists to serve. This was never caught because every
/// prior test and manual check happened over loopback. `bind_address` has
/// already been proven to parse as a real `SocketAddr` by
/// `auth::validate_bind_address` before this function is ever called, so its
/// IP (host only, no port, matching any port on that host, see
/// `host_is_allowed`'s port-matching rule) is added to the allowlist
/// alongside the loopback defaults, keeping the defence-in-depth intact for
/// any Host header that isn't either loopback or the server's own
/// configured address.
fn allowed_hosts_for(bind_address: &str) -> Vec<String> {
    let bind_host = bind_address
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();

    ["localhost", "127.0.0.1", "::1", bind_host.as_str()]
        .into_iter()
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_hosts_includes_loopback_and_the_configured_bind_address() {
        let hosts = allowed_hosts_for("100.64.0.1:8443");
        assert!(hosts.contains(&"localhost".to_string()));
        assert!(hosts.contains(&"127.0.0.1".to_string()));
        assert!(hosts.contains(&"::1".to_string()));
        assert!(
            hosts.contains(&"100.64.0.1".to_string()),
            "the server's own bind address must be an allowed Host, or every \
             real remote client is rejected with a 403 before ever reaching \
             the bearer-token check: {hosts:?}"
        );
    }

    #[test]
    fn allowed_hosts_for_an_ipv6_bind_address_does_not_include_the_port() {
        // A port left attached to the host entry would never match, since
        // rmcp's own default entries ("localhost", "127.0.0.1", "::1") are
        // bare hosts too, and host_is_allowed compares host and port
        // separately. This guards against a regression that re-adds the
        // port (e.g. accidentally pushing `bind_address` itself, unparsed).
        let hosts = allowed_hosts_for("[::1]:8443");
        assert!(hosts.contains(&"::1".to_string()));
        assert!(
            !hosts.iter().any(|h| h.contains(':') && h.contains("8443")),
            "the bind host entry must not carry the port: {hosts:?}"
        );
    }

    #[test]
    fn resolves_a_real_username_to_its_numeric_uid_gid_name_and_home() {
        // "root" (uid 0, gid 0) exists on every Linux system, including CI,
        // which is why it's used here purely to exercise the resolution
        // mechanism itself. It is not a legal `developer_user` value,
        // `validate_developer_tier_precondition` rejects uid 0 outright
        // (dropping privilege *to* root would defeat the entire point of
        // this tier), which is a separate test below. This one asserts only
        // that resolution reports what the passwd database holds.
        let identity = resolve_user("root").unwrap();
        assert_eq!(identity.uid, 0);
        assert_eq!(identity.gid, 0);
        assert_eq!(identity.name, "root");
        assert_eq!(identity.home, std::path::PathBuf::from("/root"));
    }

    #[test]
    fn returns_a_clear_error_for_a_nonexistent_username() {
        let result = resolve_user("this-user-should-not-exist-anywhere-12345");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("this-user-should-not-exist-anywhere-12345"));
    }

    #[test]
    fn developer_tier_without_a_developer_user_is_rejected() {
        let result =
            validate_developer_tier_precondition(&policy::tiers::TierName::Developer, &None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("developer_user"));
    }

    #[test]
    fn developer_tier_with_a_nonexistent_developer_user_is_rejected() {
        let result = validate_developer_tier_precondition(
            &policy::tiers::TierName::Developer,
            &Some("this-user-should-not-exist-anywhere-12345".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn developer_tier_with_a_real_developer_user_succeeds() {
        // "nobody" is the portable non-root fixture this project's Fedora
        // test environment guarantees (see CONTRIBUTING.md), used here
        // rather than "root" because a root developer_user is now rejected
        // outright, see the test below.
        let expected = nix::unistd::User::from_name("nobody")
            .unwrap()
            .expect("'nobody' must exist on the Fedora test environment this project requires");
        let result = validate_developer_tier_precondition(
            &policy::tiers::TierName::Developer,
            &Some("nobody".to_string()),
        );
        assert_eq!(
            result.unwrap(),
            Some(DeveloperIdentity {
                uid: expected.uid.as_raw(),
                gid: expected.gid.as_raw(),
                name: "nobody".to_string(),
                home: expected.dir,
            })
        );
    }

    #[test]
    fn developer_tier_with_root_as_the_developer_user_is_rejected() {
        // The failure this guards is silent, not loud: "root" resolves
        // perfectly well, so without an explicit uid 0 check the server
        // starts, reports tier 'developer', and runs every developer-tier
        // command as root anyway, with the safety mechanism a no-op and
        // nothing anywhere saying so.
        let result = validate_developer_tier_precondition(
            &policy::tiers::TierName::Developer,
            &Some("root".to_string()),
        );
        let err = result.expect_err("a developer_user resolving to uid 0 must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("uid 0") && message.contains("root"),
            "the error must say plainly that the account resolves to root: {message}"
        );
    }

    #[test]
    fn non_developer_tiers_ignore_a_missing_developer_user() {
        for tier in [
            policy::tiers::TierName::Safe,
            policy::tiers::TierName::Standard,
            policy::tiers::TierName::Unrestricted,
        ] {
            let result = validate_developer_tier_precondition(&tier, &None);
            assert_eq!(result.unwrap(), None);
        }
    }
}
