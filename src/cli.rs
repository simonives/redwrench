use clap::{Parser, Subcommand};
use redwrench::policy::tiers::TierName;

#[derive(Parser, Debug)]
#[command(name = "redwrench", about = "MCP server for Fedora hardware and OS control")]
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
            Some(Command::Config { command: ConfigCommand::SetTier { tier, i_understand_the_risk } }) => {
                assert_eq!(tier, crate::policy::tiers::TierName::Unrestricted);
                assert!(!i_understand_the_risk);
            }
            _ => panic!("expected Config(SetTier) command"),
        }
    }
}
