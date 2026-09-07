# RedWrench, Design Spec

**Date:** 2026-09-07
**Status:** Approved for implementation planning

## Summary

RedWrench is a native, security-conscious MCP (Model Context Protocol)
server that exposes hardware and OS control on a dedicated Fedora machine
to AI coding agents (Claude Code, Google Antigravity) running elsewhere on
the network. It lets an agent operate a physically or logically separate
Fedora box, standard or immutable, KDE or GNOME or Server, without
installing agent tooling on that box or exposing the operator's main
workstations to full-exec risk.

This is a personal hobby project, intended to be public on GitHub from
early on, and built with the expectation that it may grow contributors,
including AI agents picking up the codebase cold. Documentation and code
clarity are treated as first-class requirements throughout, not
afterthoughts.

## Goals

- Give an AI agent on another machine safe, auditable control over a
  dedicated Fedora box: command execution, service management, package
  management, log access, and network diagnostics.
- Default to a restrictive, pre-configured security posture, with an
  explicit, clearly-warned path to loosen it up to full unrestricted
  access for users who want that.
- Support Fedora broadly: Workstation (KDE and GNOME), Server, and the
  immutable variants (Silverblue, Kinoite, IoT).
- CLI-first. No GUI in v1, GUI/config-screen affordances are a possible
  future layer on top of a complete CLI, not a parallel feature to build
  now.
- Be genuinely approachable for a future contributor, human or AI agent,
  encountering the codebase for the first time.

## Non-goals (v1.0)

- Streaming/live command output (e.g. following `journalctl -f`
  interactively). See Backlog.
- Real-time interactive approval workflows (a pending-request-to-phone
  model). The v1 permission model is entirely pre-configured.
- Deep Tailscale-specific integration (device identity, ACL tags). v1
  treats the network layer as opaque; Tailscale is the recommended,
  documented, and tested setup, not a hardcoded dependency.
- `systemd-sysext` packaging for immutable variants. `rpm-ostree install`
  is the v1.0 path for immutable Fedora.
- Submission to a COPR repo or Fedora's official repos.

## Architecture

One Rust binary, `redwrench`, built on `rmcp` (Anthropic's official Rust
MCP SDK), `tokio` for async networking, and `zbus` for systemd/D-Bus
integration where structured tools need it.

Four components:

1. **MCP transport layer**: an `rmcp`-based server speaking Streamable
   HTTP. Binds to a configured address only; binding to `0.0.0.0` or
   another blanket-public interface is refused unless an explicit
   override flag is passed, since a full-exec tool has no business being
   reachable from the open internet by accident. A bearer token is
   required on every request and is checked before any other processing
   happens. The network layer itself is transport-agnostic: the config
   just names an address to bind to. Tailscale is the documented,
   recommended, and tested setup (matching the maintainer's own use), but
   nothing in the code is Tailscale-specific, a user running WireGuard,
   ZeroTier, or a trusted LAN segment just points the bind address at
   their own interface.

2. **Policy engine**: the security core. An ordered list of allow/deny
   rules, each matching a command name plus an optional argument
   pattern. Three built-in named tiers ship as presets:
   - `safe`, read-only diagnostics: status checks, `journalctl` reads,
     network diagnostics. No mutation of system state.
   - `standard`, adds service start/stop, `dnf`/`rpm-ostree`
     install/remove, and other common but reversible operations.
   - `unrestricted`, everything, including unfiltered raw command
     execution. Switching to this tier requires an explicit
     `--i-understand-the-risk` flag on the CLI command that activates
     it, and the CLI prints a clear warning about what that means, this
     cannot happen by an accidental config edit alone.

   A user can layer custom allow/deny rules on top of whichever tier is
   active, rather than needing to hand-write a tier from scratch. Every
   tool call, structured or raw, is checked against this engine before
   execution; there is no path that bypasses it.

3. **Tool handlers**: the MCP tools exposed to the agent. Structured
   tools (`systemctl_status`, `dnf_install`, `journalctl_tail`, network
   diagnostics) build a specific, template-based command from validated
   parameters. `run_command` is the general-purpose tool, taking
   arbitrary input, gated the same way as everything else by the policy
   engine, per the earlier decision to build one general-exec foundation
   with a permission layer in front of it, rather than a curated-only
   tool set. Tool descriptions (the schema an agent reads before calling
   a tool) are treated as primary documentation, not an afterthought:
   they are the first and most consequential thing an agent sees about
   this system.

4. **Executor and logger**: runs approved commands via
   `tokio::process` with a configurable timeout (a hung process must not
   be able to wedge the server). For v1.0, output is captured and
   returned as a whole (buffered), not streamed, truncated with a note
   if very large so a single noisy command can't blow out an agent's
   context. Every invocation, allowed or denied, writes a structured
   entry to the systemd journal: timestamp, tool name, resolved command,
   active tier, and outcome (allow/deny, exit code). This is the audit
   trail.

Config lives at `/etc/redwrench/config.toml` on standard Fedora. On
immutable variants, `/etc` is technically writable but does not survive a
full OS reset the way it does on standard Fedora; this is documented
explicitly (see Documentation) rather than handled as a silent code
branch.

## Data flow

1. Agent sends an MCP tool call over Streamable HTTP.
2. Bearer token is checked first. Invalid or missing leads to immediate
   rejection, logged as an auth failure. These are worth watching
   closely as the most likely sign of unauthorised probing.
3. The tool handler resolves the concrete command (template-filled for
   structured tools, as-given for `run_command`).
4. The policy engine evaluates that exact command against the active
   tier plus any custom rules, in order, first match wins.
5. **Denied**: a clear, structured MCP error naming the active tier and
   that the command isn't permitted under it. There is no security
   value in being vague here, the rules live in a config file the agent
   could read anyway, so the error is written to help the agent
   self-correct. Logged regardless of outcome.
6. **Allowed**: executed with a timeout, output captured, result
   returned: exit code, stdout/stderr (truncated if huge).
7. A structured audit entry is written to the systemd journal for every
   call, regardless of outcome.

### Error handling, three distinct cases

- **Auth failure** and **policy denial** are protocol-level rejections,
  the request itself didn't proceed.
- **A command that ran but exited non-zero** is a normal result, not an
  error. The agent asked for something to run, it ran, and it failed on
  its own terms; that's data for the agent to interpret.
- **Timeout or an internal server fault** is logged in full detail
  server-side, but the agent receives a generic failure with no internal
  detail leaked over the wire.

## Documentation and contributor experience

Treated as a non-negotiable requirement, not a v2 nice-to-have:

- **CLI built on `clap`**, with man pages generated via `clap_mangen`
  directly from the same argument definitions that drive the CLI, so
  documentation cannot drift out of sync with behaviour.
- **MCP tool descriptions as primary documentation.** These are what an
  agent reads before deciding to call a tool; a vague description on a
  full-exec-capable tool is a real risk, not just a documentation gap.
- **Rustdoc comments explaining why, not what,** especially around
  policy engine decisions, so a future contributor (human or agent)
  understands the reasoning behind a rule before changing it.
- **`CONTRIBUTING.md` and `AGENTS.md`/`CLAUDE.md`** at the repo root,
  giving any contributor, human or AI agent, the same onboarding: how the
  policy engine works, where to add a new structured tool, what testing
  is expected before a PR, including a documented minimum test bar for
  any PR touching the policy engine specifically.
- **`ARCHITECTURE.md`** as the living companion to this spec (specs
  describe a point-in-time design; a codebase needs a doc that stays
  current as it evolves).
- **UAT documentation**, v1.0 scope, not backlog: scenario-based
  walkthroughs a human or agent can follow to manually verify the system
  behaves as designed. At minimum: each named tier actually
  blocks/allows what it claims to, the bind-address guard genuinely
  refuses a blanket-public bind without the override flag, and a full
  connect-and-use walkthrough from both Claude Code and Antigravity.

## Testing strategy

Three tiers, not a flat "unit tests" plan:

1. **Policy engine unit tests**, the highest-value tests in the
   project. Every named tier gets tests asserting specific commands are
   allowed/denied as expected. Rule-ordering tests (a custom deny
   correctly overriding a tier default, and vice versa). Tests
   specifically targeting command-injection-shaped inputs disguised as
   arguments, to confirm argument-pattern matching isn't fooled by
   something like a trailing `; rm -rf /`.
2. **Tool handler integration tests** against a real, sandboxed or
   containerised Fedora environment (CI runs in a Fedora container).
   Mocking `systemctl`/`dnf` would test nothing meaningful.
3. **Transport/auth tests** for the bearer token check and the
   bind-address safety guard, cheap to write and easy to accidentally
   regress if untested.

## Packaging

1. **Standard Fedora** (any spin, Server included): plain RPM via
   `rust2rpm` generating the spec from `Cargo.toml`, `dnf install`,
   systemd service. Config at `/etc/redwrench/config.toml`.
2. **Immutable Fedora** (Silverblue, Kinoite, IoT): RPM layered via
   `rpm-ostree install` as the v1.0 path. The `/etc` persistence caveat
   on immutable variants is documented explicitly rather than solved in
   code.

## Licensing

Dual-licensed **MIT OR Apache-2.0**, matching Rust ecosystem convention
(Tokio, Serde, and `rmcp` itself). `LICENSE-MIT` and `LICENSE-APACHE`
files at the repo root, noted in `Cargo.toml`.

## Naming

**RedWrench** (crate/repo name: `redwrench`, all lowercase). Chosen over
a Fedora-prefixed name specifically to avoid the trademark ambiguity of
a third-party tool sounding like an official Fedora Project component.
"Red" is a deliberate, understated nod to Red Hat without spelling out a
protected term; "Wrench" reflects the hands-on hardware/OS control the
tool provides. Verified 7 September 2026: no conflicting crates.io
package, no conflicting GitHub repository or organisation, no
identified trademark conflict (the sole related web hit, a "Red Wrench
Club" hobby car-restoration group at a US college, is unrelated in
domain and not a registered trademark).

## Development workflow

Development happens on the maintainer's Mac (editing via Claude Code);
build, test, and run cycles happen on the target Fedora box itself,
since the Linux-specific facilities this project wraps (`systemctl`,
D-Bus, `dnf`) cannot be meaningfully exercised on macOS. The two
machines share a LAN in addition to being reachable over Tailscale; the
dev-loop tooling uses the LAN address for lower-latency iteration, while
the running MCP server itself is only ever bound to and reached via the
Tailscale interface, keeping the "convenient for development" and "the
actual production access model" paths clearly separate.

A `justfile` (or `Makefile`) ships with a `remote-test` recipe (or
equivalent) that rsyncs the working tree to the Fedora box and runs
`cargo test` there over SSH, so this cross-machine loop doesn't require
hand-typed SSH commands every session.

Target hardware for initial development: a 2011 MacBook Pro running
Fedora KDE, kept current with daily updates. Plain
`x86_64-unknown-linux-gnu`, no unusual architecture considerations.

## Backlog / roadmap (post-v1.0)

1. **Streaming/live output** for long-running or follow-mode commands
   (e.g. `journalctl -f`). Needs its own design pass on how streaming
   responses work over MCP.
2. **`systemd-sysext` packaging** for immutable variants as a
   no-reboot-required alternative to `rpm-ostree install`. Needs
   validation against current Fedora systemd support before it's a real
   design goal.
3. **COPR repo**, and possibly Fedora's official repos, once the project
   has some track record.
4. Real-time interactive approval workflow (notify-and-approve rather
   than pre-configured tiers) as an optional mode for the
   unrestricted-adjacent end of the spectrum, if the pre-configured
   model ever feels insufficient in practice.
5. Deeper Tailscale-specific integration (per-device identity used in
   authorisation decisions), if the transport-agnostic bearer-token
   model ever feels insufficient in practice.

These become GitHub issues and a project board once the repository is
pushed.
