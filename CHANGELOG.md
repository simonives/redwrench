# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/) from `1.0.0` onward.

## [1.0.1] - 2026-09-10

A security patch closing five findings from an independent tier-charter audit (`docs/superpowers/specs/2026-09-10-tier-charter-audit.md`), all affecting `v1.0.0`. Two of the five affect every tier except `unrestricted`, since every tier inherits `safe`'s rules.

### Fixed

- **#38, critical**: `journalctl`'s bare `+` disjunction operator let a query carry a real, glob-free unit scope while OR-combining it with other appended match expressions, reopening a whole-journal read at `safe` tier by a route the original `#26` fix didn't anticipate.
- **#39, high**: `top -b -c` at `safe` tier disclosed every process's full command line, system-wide, as root, the same confidentiality class as `#26`, never previously scoped.
- **#40, high**: `standard` tier could reboot, power off, or drop the host to single-user mode via `systemctl start`/`restart` against `reboot.target`/`poweroff.target`/`halt.target`/`emergency.target`/`rescue.target`, ordinary service-lifecycle syntax the tier's own allow pattern didn't distinguish from a real service.
- **#41, critical**: `dnf -c`/`--config` (and several other flags) were not covered by the package-trust-bypass deny, letting an alternate config file achieve `--nogpgcheck` and `--repofrompath` together with no denied flag involved, a full root-escalation chain under `developer` tier. Closed across three review rounds after live testing against real `dnf4`/`dnf5` binaries surfaced clustered short options (`-yc`, `-4c`), dnf's prefix-abbreviation (`--con`, `--i`, `--des`), and a digit-inclusive character class the first two fixes missed.
- **#42, critical**: a `custom_rules` entry unconditionally allowing a command (e.g. `bash`) under `safe`/`standard` tier granted unfiltered root code execution with no warning and no `--i-understand-the-risk` requirement, since those tiers have no privilege-drop mechanism. RedWrench now refuses to start on such a configuration without the flag. Closed across two rounds after review found a catch-all `arg_pattern` (`.*`, `^`, `$`) was functionally unconditional but technically distinct from the unconditional (`None`) case the first fix checked for.

## [1.0.0] - 2026-09-10

The first tagged release. RedWrench exposes Fedora hardware and OS control to AI coding agents over MCP, behind a tiered, ordered allow/deny policy engine, with every invocation recorded to the systemd journal.

### Added

- **Policy engine**: an ordered, first-match-wins allow/deny rule set with four tiers (`safe`, `standard`, `developer`, `unrestricted`), each extending the one below it, plus operator-configurable `custom_rules` layered on top via `config.toml`.
- **Developer tier**: privilege-dropped execution of a fixed set of interpreters and build tools (`bash`, `sh`, `python3`, `gcc`, `cc`, `node`, `npm`, `cargo`, `make`) under a configured non-root identity, with a real Unix privilege drop (`setgroups`→`setgid`→`setuid`) as the actual security boundary, not command filtering.
- **Structured tools**: `systemctl_status`/`systemctl_control`, `dnf_install`/`dnf_remove`, `journalctl_tail`, `ping`, `run_command` for everything else, each argument-injection-hardened against flag-abbreviation and clustered-short-option bypasses.
- **Streaming execution**: live output via `notifications/progress`, cooperative cancellation via `notifications/cancelled`, and a server-enforced safety-net duration for indefinite commands.
- **Capability and policy discovery**: `list_capabilities` and `check_command`, both allowed at every tier since they only introspect the policy engine and never execute, plus self-teaching denial messages that name a tier that would allow a denied command. README and ARCHITECTURE.md exposed as MCP resources.
- **Audit trail**: every invocation, allowed or denied, recorded to the systemd journal with the active tier, resolved command, and outcome.
- **Transport**: MCP over Streamable HTTP, bearer-token authenticated, with a DNS-rebinding host allowlist and an explicit guard against binding to a public address without an override flag.
- **UAT scenarios** (`docs/uat/v1-uat-scenarios.md`): manual verification scenarios covering every tier, the audit trail, streaming, cancellation, and the discovery tools, run against a real Fedora box over Tailscale.

### Known limitations, deliberately deferred

These were the original design spec's own v1.0 non-goals, not gaps discovered late:

- No deep Tailscale-specific integration (per-device identity in authorisation), see #6.
- No real-time interactive approval workflow (a pending-request-to-phone model), see #5.
- No `systemd-sysext` packaging for immutable Fedora variants, see #3.
- Not submitted to COPR or Fedora's official repositories, see #4.
- No GUI configuration app, see #30.
