# RedWrench

[![CI](https://github.com/simonives/redwrench/actions/workflows/ci.yml/badge.svg)](https://github.com/simonives/redwrench/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

I keep a few old machines at home running Fedora, and the hardware's
too outdated to sell but still fine as a home server or something to
tinker with. I wanted an AI coding agent to look after them for me:
simple things like restarting a service, chasing down a bad config, or
running the odd diagnostic. And some more complex things too, like
installing a package I've decided I want, or working out why a service
refuses to start after a kernel update. However I didn't want to hand
the agents a shell on these machines.

RedWrench is what I built instead. It runs on the Fedora box itself and
uses [MCP (Model Context Protocol)](https://modelcontextprotocol.io/),
the standard Claude Code, Codex, and most other coding agents already
support. Every command the agents send passes through a policy engine
first, which decides what they may run before it runs anything at all.

This is a hobby project. I built it to scratch my own itch on my own
hardware, and I'm publishing it because anyone else running similar
machines at home will hit the same problem the moment they point an
agent at them.

Any MCP-speaking agent works: Claude Code, Codex, Google Antigravity, and
whatever comes next. The Fedora box itself can be physically or
logically separate from your workstation, standard or immutable, KDE,
GNOME, or Server, and it needs no agent tooling installed on it
directly.

Every invocation passes through an ordered allow/deny policy engine and is
written to the systemd journal, whether it was permitted or refused. Four
built-in tiers (`safe`, `standard`, `developer`, `unrestricted`) set the
baseline, and custom rules layer on top without editing a line of code.

RedWrench is written in Rust. As it's a tool that spawns arbitrary processes,
reads their output as it arrives, and enforces policy decisions up-front, it needs strict guarantees on memory bounds and
concurrent state. Rust's compiler checks both at build time rather
than leaving them to runtime discipline.

Governments have started saying the same thing directly. The NSA and
the White House's National Cyber Director have both urged vendors to
move away from memory-unsafe languages like C and C++ toward
alternatives such as Rust, because so many serious vulnerabilities
trace back to memory bugs that a compiler can catch before their code is
shipped. That same guarantee's important for an AI agent talking to this
server: the compiler bounds what a single request can touch at build
time, so a malformed or adversarial instruction from the agent cannot
corrupt memory outside its own transaction.

## Contents

- [Install](#install)
- [Configure](#configure)
- [Policy tiers](#policy-tiers)
- [Security posture: no TLS, by design](#security-posture-no-tls-by-design)
- [Further reading](#further-reading)
- [License](#license)

## Install

RedWrench is not packaged yet. `packaging/redwrench.spec` is a
work-in-progress RPM spec (see its own header for the `rust2rpm`
regeneration it still needs), so for now build from source on the Fedora
machine RedWrench will control:

```sh
sudo dnf install -y cargo rust systemd-devel gcc pkgconf-pkg-config
git clone https://github.com/simonives/redwrench
cd redwrench
cargo build --release
sudo install -m 0755 target/release/redwrench /usr/local/bin/redwrench
```

The build script generates a man page at
`target/release/build/redwrench-*/out/redwrench.1`; install it with
`sudo install -m 0644 <that path> /usr/share/man/man1/` if you want
`man redwrench`.

## Configure

RedWrench reads `/etc/redwrench/config.toml` by default (override with
`--config`). Create it root-owned and mode `0600`, since it holds the
bearer token in plaintext:

```sh
sudo mkdir -p /etc/redwrench
sudo install -m 0600 /dev/null /etc/redwrench/config.toml
```

A minimal config:

```toml
# The address to bind to. Point this at the interface your agent reaches
# you on, typically a Tailscale address. Binding to 0.0.0.0 or [::] is
# refused unless you also pass --allow-public-bind.
bind_address = "100.64.0.1:8443"

# Required on every request as `Authorization: Bearer <token>`. Generate a
# real one, e.g. `openssl rand -hex 32`. Never commit this file.
bearer_token = "replace-me-with-a-long-random-string"

# One of: safe, standard, developer, unrestricted.
tier = "standard"

# Required only when tier = "developer". The OS username developer-tier
# tool execution (bash, python3, gcc, npm, cargo, etc.) runs as, instead
# of root. The server refuses to start under the developer tier without
# this set to a real account on the machine.
developer_user = "your-username-here"

# How long any single command may run before it is killed. Optional;
# defaults to 30. Raise it if you run `dnf install` over a slow mirror.
timeout_secs = 120

# The safety net for genuinely indefinite calls (e.g. `ping` with no
# count, `journalctl_tail` with follow enabled, `vmstat 1` under a
# progress-token-attached call). Such a call is not bounded by
# timeout_secs above; it runs until cancelled or until this many
# seconds have passed. Optional; defaults to 1800 (30 minutes).
max_stream_duration_secs = 1800

# Custom rules layer on top of the tier and are evaluated FIRST, so a
# custom deny overrides a tier allow. Matching is first-match-wins.
# `arg_pattern` is a regex tested against the joined arguments; omit it to
# match the command regardless of arguments.
[[custom_rules]]
command = "dnf"
arg_pattern = "^remove"
effect = "deny"
```

Generate the token, then start the server:

```sh
redwrench --config /etc/redwrench/config.toml
```

## Policy tiers

The tier sets the baseline rule list. Your `custom_rules` sit in front of
it, so you narrow or widen any tier without editing the binary.

| Tier | What it permits |
| --- | --- |
| `safe` | Read-only diagnostics: `systemctl status`/`is-active`/`is-enabled`, `journalctl` reads, `ping`, `ip` show/list/get. No mutation of system state. Journal-writing flags, flood/abuse ping flags (`-f`, `-A`, `-l`, `-s`, zero intervals), and systemctl flags that redirect the operation off this machine (`--host`/`-H`, `--machine`/`-M`, `--root`) are explicitly denied. |
| `standard` | Everything in `safe`, plus service start/stop/restart/enable/disable and `dnf`/`rpm-ostree` install/remove/upgrade. Flags that defeat package signature checking (`--nogpgcheck`, `--repofrompath`, `--setopt`) are explicitly denied, including the abbreviated forms dnf's argparse CLI accepts. |
| `developer` | Everything in `standard`, plus `bash`, `sh`, `python3`, `gcc`, `cc`, `node`, `npm`, `cargo`, and `make`, unconditionally (no argument restriction). These run under a configured `developer_user` account instead of root, not RedWrench's own filtering, that account's own Unix permissions are what bound the risk. Requires `developer_user` to be set in `config.toml`; the server refuses to start under this tier without it. |
| `unrestricted` | Everything, including unfiltered raw command execution. No policy restrictions at all. |

Switch tiers with `redwrench config set-tier <tier>`.

`developer` hands the agent a real shell and a compiler toolchain, but
never as root: every developer-tier call drops privilege to the
`developer_user` account before it runs, so whatever damage a bad or
adversarial command can do is bounded by that account's own file
permissions, not by anything RedWrench filters. Pick an account with no
more access than you're comfortable an agent using unsupervised.

`unrestricted` is arbitrary remote code execution as whatever user
RedWrench runs as. It is refused unless you pass
`--i-understand-the-risk`, both when setting the tier and when starting
the server with it active. That flag exists so choosing this posture is a
deliberate act rather than a config typo. Do not run `unrestricted` on a
machine you care about, or on any network you do not fully control.

## Security posture: no TLS, by design

RedWrench speaks plaintext HTTP. It does not terminate TLS and has no
plans to. Confidentiality and network-level authentication come from
binding it to a private network, not from anything RedWrench does itself.
The recommended and tested setup is Tailscale: give the machine a
Tailscale address, put that address in `bind_address`, and the traffic is
WireGuard-encrypted between the agent and the box before RedWrench sees
it. WireGuard directly, ZeroTier, or a genuinely trusted LAN segment work
the same way; nothing in the code is Tailscale-specific.

The bearer token is checked on every request before any other processing,
and compared in constant time. Treat it as a second factor behind the
network boundary, not as the boundary itself. Binding to a blanket-public
address is refused unless you explicitly override it, because a full-exec
tool has no business being reachable from the open internet by accident.

## Further reading

- `ARCHITECTURE.md`, how the transport, policy engine, executor, and audit
  layers fit together, and the contracts between them.
- `CONTRIBUTING.md`, development workflow, the two-machine setup, and what
  a change is expected to come with.
- `AGENTS.md`, orientation for an AI agent picking up this codebase cold.
- `docs/superpowers/specs/2026-09-07-redwrench-design.md`, the original
  design spec.

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and
`LICENSE-APACHE`.
