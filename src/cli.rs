use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "redwrench", about = "MCP server for Fedora hardware and OS control")]
pub struct Cli {
    /// Path to the config file.
    #[arg(long, default_value = "/etc/redwrench/config.toml")]
    pub config: std::path::PathBuf,

    /// Allow binding to a blanket-public address (0.0.0.0 or ::). Dangerous.
    #[arg(long, default_value_t = false)]
    pub allow_public_bind: bool,

    /// Acknowledge the risk of running with the 'unrestricted' policy tier
    /// active (arbitrary command execution, no policy restrictions).
    /// Required if the config file's tier is set to 'unrestricted'.
    #[arg(long, default_value_t = false)]
    pub i_understand_the_risk: bool,
}
