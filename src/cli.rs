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
}
