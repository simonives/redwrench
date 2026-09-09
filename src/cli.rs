use clap::{Parser, Subcommand};

// The build script (build.rs) includes this file directly and can't
// see the redwrench library crate, so TierName is redeclared locally
// as a build-time-only mirror for the purposes of man page generation.
// The real TierName (src/policy/tiers.rs) still owns Deserialize and
// the actual policy logic; this local copy exists purely so build.rs
// can construct a clap Command without a circular crate dependency.
#[derive(Debug, Clone, PartialEq, clap::ValueEnum)]
pub enum TierName {
    Safe,
    Standard,
    Developer,
    Unrestricted,
}

#[derive(Parser, Debug)]
#[command(
    name = "redwrench",
    about = "MCP server for Fedora hardware and OS control"
)]
pub struct Cli {
    /// Path to the config file.
    #[arg(long, default_value = "/etc/redwrench/config.toml", global = true)]
    pub config: std::path::PathBuf,

    /// Allow binding to a blanket-public address (0.0.0.0 or ::). Dangerous.
    #[arg(long, default_value_t = false)]
    pub allow_public_bind: bool,

    /// Acknowledge the risk of running with the 'unrestricted' policy tier
    /// active (arbitrary command execution, no policy restrictions).
    /// Required if the config file's tier is set to 'unrestricted'.
    #[arg(long, default_value_t = false)]
    pub i_understand_the_risk: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Manage the active policy configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Set the active policy tier.
    SetTier {
        tier: TierName,
        /// Required to set the 'unrestricted' tier. Read the warning first.
        #[arg(long, default_value_t = false)]
        i_understand_the_risk: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_tier_unrestricted_requires_the_risk_flag() {
        let cli = Cli::try_parse_from(["redwrench", "config", "set-tier", "unrestricted"]).unwrap();
        match cli.command {
            Some(Command::Config {
                command:
                    ConfigCommand::SetTier {
                        tier,
                        i_understand_the_risk,
                    },
            }) => {
                assert_eq!(tier, TierName::Unrestricted); // cli::TierName, not policy::tiers::TierName
                assert!(!i_understand_the_risk);
            }
            _ => panic!("expected Config(SetTier) command"),
        }
    }

    #[test]
    fn set_tier_developer_parses_without_requiring_the_risk_flag() {
        let cli = Cli::try_parse_from(["redwrench", "config", "set-tier", "developer"]).unwrap();
        match cli.command {
            Some(Command::Config {
                command:
                    ConfigCommand::SetTier {
                        tier,
                        i_understand_the_risk,
                    },
            }) => {
                assert_eq!(tier, TierName::Developer);
                assert!(!i_understand_the_risk);
            }
            _ => panic!("expected Config(SetTier) command"),
        }
    }
}
