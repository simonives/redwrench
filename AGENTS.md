# Agent Onboarding

This file is for AI coding agents (Claude Code, Codex, or others)
picking up this codebase. It's the same onboarding a human contributor
gets via `CONTRIBUTING.md` and `ARCHITECTURE.md`, restated with the
specific things an agent is likely to get wrong if it skips straight to
editing code.

## Read first

1. `ARCHITECTURE.md`, the four-layer structure and where new code goes.
2. `docs/superpowers/specs/2026-09-07-redwrench-design.md`, the full
   design rationale, especially the security design principles.

## The one rule that matters most

**Every tool, without exception, calls `RedWrenchServer::dispatch`
(`src/tools/mod.rs`) to actually run a command.** Do not call
`crate::executor::execute` directly from a tool file, and do not add a
tool that constructs and runs a command without going through
`dispatch`. `dispatch` is what applies the policy check and writes the
audit log; a tool that bypasses it is a security hole, not a shortcut.

## The second rule

**Commands are always argv (a command string plus a `Vec<String>` of
arguments), never a single shell string passed to `sh -c`.** This is
enforced structurally in `src/executor.rs` via `tokio::process::Command`.
If you find yourself wanting to build a shell string with `&&` or `;`
to chain operations, that's a sign the task needs two separate tool
calls, not a shell escape hatch inside one.

## The third rule

Argv-only closes shell injection, but it does not close **flag
injection**: a free-text tool parameter that ends up in an underlying
CLI tool's own argv can still be reinterpreted by that tool's own
option parser as a flag rather than a literal value. This has been
found and fixed three separate times in this codebase (dnf's
`package`, journalctl's `unit`, ping's `host`), so treat every new
free-text parameter that reaches a spawned command as a suspect until
proven otherwise.

The fix depends on where the value lands, and the two shapes are not
interchangeable:

- **Trailing positional argument** (dnf's `package`, ping's `host`):
  prefix the value with a literal `--` argv separator. Everything after
  `--` is positional, never a flag, regardless of what it starts with.
  See `install_argv`/`remove_argv` in `src/tools/dnf.rs` and
  `ping_argv` in `src/tools/network.rs`.
- **A short option's required argument** (journalctl's `-u <value>`):
  `--` does not help here. A getopt-style parser unconditionally
  consumes the very next argv token as that option's value, so `-u --`
  just sets the value to the literal string `"--"` and leaves the real
  value as a separate, unprotected positional. The correct fix is to
  validate the value directly, rejecting anything that looks like a
  flag before it reaches argv. See `journalctl_args` in
  `src/tools/journalctl.rs`.

When adding a new tool, work out which shape your free-text parameter
occupies before picking a fix, applying the wrong one gives a false
sense of safety.

## The fourth rule

**A tool wanting to stream output or run indefinitely does not build its
own timeout or streaming logic.** `dispatch()` already does this for
every tool, uniformly: pass an `Option<Duration>` override when a call
should use the safety-net `max_stream_duration` instead of the ordinary
default (see `ping`'s optional `count` or `journalctl_tail`'s `follow`),
and `dispatch()` handles cancellation and progress-token-triggered
streaming the same way for every tool, whether or not it opted into a
duration override. Reimplementing any part of this in a tool file is the
same class of mistake the first rule warns against for policy checks:
`dispatch` is the one place that gets this right, a tool that bypasses it
will get subtly wrong behaviour, not a shortcut.

## Before submitting a change

Run `cargo test`. If you changed `src/policy/`, make sure you added a
test, per `CONTRIBUTING.md`'s testing expectations, this is checked in
review, not just suggested.
