// src/tools/journalctl.rs
use super::RedWrenchServer;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JournalctlTailParams {
    /// Optional unit to filter by, e.g. "sshd.service". If omitted, tails
    /// the whole system journal.
    pub unit: Option<String>,
    /// How many of the most recent lines to return. Defaults to 50.
    #[serde(default = "default_lines")]
    pub lines: u32,
}

fn default_lines() -> u32 {
    50
}

// NOTE (argument-injection hardening, same class of bug Task 11 fixed in
// dnf.rs): `unit` is free text that ends up as the value of journalctl's
// `-u` flag, and journalctl (like dnf) has its own general-purpose argv
// parser that recognises flags wherever they appear, not just in a fixed
// position. A `unit` of e.g. "--file=/etc/shadow" or "--directory=/root"
// would let a caller redirect journalctl to read from an arbitrary path
// instead of filtering by unit name. `unit` is reachable by anything that
// controls the MCP tool call, including a prompt-injected agent, which is
// this project's threat model (same as the dnf case).
//
// dnf.rs closes the equivalent hole with a literal `--` separator before
// the free-text `package`, because `package` is dnf's trailing *positional*
// argument: GNU getopt stops interpreting anything after a standalone `--`
// as an option, so a positional argument can never be mistaken for a flag
// once `--` has been seen.
//
// That trick does not carry over to `-u`. `-u` is a short option that
// *requires* an argument, and getopt_long's rule for a required-argument
// option is unconditional: whatever the very next argv element is becomes
// that option's value, verbatim, even if it is itself the string "--". So
// `-u --` does not protect the unit value the way `--` protects a trailing
// positional; it sets the unit filter to the literal string "--" and
// leaves whatever was supposed to be the real unit value as a separate,
// unprotected positional argument (which journalctl would treat as a
// journal field match expression, not as part of the `-u` filter at all).
// `--` simply cannot disambiguate an option's own argument from a
// following flag the way it disambiguates a trailing positional.
//
// The correct equivalent protection here is validation, not separator
// placement: reject any `unit` value that starts with `--` before it ever
// reaches journalctl's argv.
//
// NOTE (post-review correction, false positive on escaped unit names):
// this was originally `unit.starts_with('-')` (single dash), which wrongly
// rejected legitimate systemd unit names. systemd's unit-name escaping
// convention produces names starting with a single `-`, e.g. `-.mount` is
// the real, standard name for the root filesystem's mount unit; someone
// diagnosing root-filesystem I/O errors with `journalctl -u -.mount` would
// have been incorrectly blocked. Per getopt_long's semantics (see above),
// `-u`'s required argument is consumed unconditionally as a single argv
// token and is never re-scanned as a flag by journalctl's own parser once
// consumed, so the two-token `-u <value>` form was likely never exploitable
// for this injection class in the first place (unlike dnf's genuinely
// vulnerable trailing positional argument). This check is therefore
// defense-in-depth, not a confirmed-necessary fix, so it should be no
// broader than the concrete risk it guards against: GNU long-option-style
// flags, which all start with `--`, not `-`. Narrowing to `--` still
// catches every concrete payload this file's tests exercise
// (`--file=/etc/shadow`, `--directory=/root`, a bare `--`), while no longer
// rejecting single-dash-escaped unit names like `-.mount`.
fn journalctl_args(unit: Option<String>, lines: u32) -> Result<Vec<String>, String> {
    let mut args = vec![
        "-n".to_string(),
        lines.to_string(),
        "--no-pager".to_string(),
    ];
    if let Some(unit) = unit {
        if unit.starts_with("--") {
            return Err(format!(
                "Invalid unit \"{unit}\": unit names cannot start with \"--\" \
                (this would be interpreted as a journalctl long-option flag \
                rather than a unit name)"
            ));
        }
        args.push("-u".to_string());
        args.push(unit);
    }
    Ok(args)
}

#[tool_router(router = journalctl_router, vis = "pub(crate)")]
impl RedWrenchServer {
    #[tool(
        description = "Return the most recent lines from the systemd journal, \
        optionally filtered to a single unit. This is a one-shot read, it does \
        not follow the log live; live-following is not supported in this \
        version. Allowed under every tier."
    )]
    pub async fn journalctl_tail(
        &self,
        Parameters(JournalctlTailParams { unit, lines }): Parameters<JournalctlTailParams>,
    ) -> CallToolResult {
        match journalctl_args(unit, lines) {
            Ok(args) => self.dispatch("journalctl_tail", "journalctl", args).await,
            Err(reason) => CallToolResult::error(vec![ContentBlock::text(reason)]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_lines_only_when_no_unit_is_given() {
        let args = journalctl_args(None, 50).unwrap();
        assert_eq!(args, vec!["-n", "50", "--no-pager"]);
    }

    #[test]
    fn ordinary_unit_names_are_unaffected() {
        let args = journalctl_args(Some("sshd.service".to_string()), 50).unwrap();
        assert_eq!(args, vec!["-n", "50", "--no-pager", "-u", "sshd.service"]);
    }

    #[test]
    fn a_unit_value_that_looks_like_a_file_redirect_flag_is_rejected() {
        let result = journalctl_args(Some("--file=/etc/shadow".to_string()), 50);
        assert!(result.is_err(), "expected rejection, got {result:?}");
    }

    #[test]
    fn a_unit_value_that_looks_like_a_directory_redirect_flag_is_rejected() {
        let result = journalctl_args(Some("--directory=/root".to_string()), 50);
        assert!(result.is_err(), "expected rejection, got {result:?}");
    }

    #[test]
    fn a_bare_double_dash_unit_value_is_rejected() {
        // A bare "--" is not a legitimate unit name either, and must not be
        // silently absorbed as -u's argument.
        let result = journalctl_args(Some("--".to_string()), 50);
        assert!(result.is_err(), "expected rejection, got {result:?}");
    }

    #[test]
    fn a_single_dash_escaped_unit_name_is_accepted() {
        // "-.mount" is the real, standard systemd-escaped unit name for the
        // root filesystem's mount unit. It starts with a single dash, not a
        // double dash, and must not be rejected by the "--" long-option
        // guard: someone diagnosing root-filesystem I/O errors with
        // `journalctl -u -.mount` needs this to work.
        let args = journalctl_args(Some("-.mount".to_string()), 50).unwrap();
        assert_eq!(args, vec!["-n", "50", "--no-pager", "-u", "-.mount"]);
    }

    #[test]
    fn other_single_dash_prefixed_unit_names_are_accepted() {
        // A couple more plausible single-dash-escaped names, to confirm the
        // guard is specifically anchored on "--" and not just "starts with
        // more than zero dashes".
        for unit in ["-.slice", "-boot.mount"] {
            let args = journalctl_args(Some(unit.to_string()), 50).unwrap();
            assert_eq!(args, vec!["-n", "50", "--no-pager", "-u", unit]);
        }
    }

    #[test]
    fn lines_is_a_plain_integer_and_is_never_treated_as_a_flag() {
        // lines is a u32, already immune to this class of injection; confirm
        // it still lands in the expected fixed position regardless.
        let args = journalctl_args(None, 9999).unwrap();
        assert_eq!(args, vec!["-n", "9999", "--no-pager"]);
    }
}
