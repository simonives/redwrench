# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/) from `1.0.0` onward.

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
