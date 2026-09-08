# RedWrench Streaming Execution, Design Spec

**Date:** 2026-09-08
**Status:** Approved for implementation planning
**Supersedes:** the "Streaming/live output" backlog item in
`docs/superpowers/specs/2026-09-07-redwrench-design.md`'s "Backlog / roadmap"
section (item 1), which named this exact capability as v1.0 non-goal
pending its own design pass. This is that pass.

## Summary

RedWrench v1.0 buffers a command's entire output and returns it once, when
the command finishes. This spec adds live streaming of output as a command
runs, cooperative cancellation of an in-flight command, and support for
commands with no natural end (a `ping` with no packet count, `journalctl
-f`), bounded by a server-enforced safety-net duration rather than relying
on the caller to eventually stop it.

This is built entirely on MCP's existing standard mechanisms
(`notifications/progress` and `notifications/cancelled`), already present
in the pinned `rmcp` 3.2.0 SDK. No bespoke protocol, polling endpoint, or
job abstraction is introduced.

## Motivating use cases

1. **Long-command progress** (the more frequent case in practice): a
   `dnf install` that takes 90 seconds currently looks identical to a
   hung process until it finishes. Seeing its output live, and being able
   to interrupt it if it's clearly going wrong, avoids waiting out a
   command that's already failed.
2. **Live log following**: `journalctl -f`, watching a service's log in
   real time rather than a one-shot tail.
3. **Indefinite monitoring alongside other work**: running something like
   `vmstat 1` continuously while subsequent, unrelated tool calls happen,
   stopped only when the operator decides they're done watching.

## Goals

- Stream a running command's output to the calling agent as it's
  produced, for both naturally-terminating and indefinite commands.
- Let the caller cancel a running command, ending it immediately via the
  same kill path the timeout already uses.
- Support commands with no natural exit condition, under a server-enforced
  maximum duration that applies regardless of whether the caller ever
  cancels.
- Preserve today's behaviour exactly for any caller that doesn't opt into
  streaming: a buffered result, once, at the end.

## Non-goals

- **A job/polling abstraction** (`start_job`/`poll_job`/`cancel_job`
  tools). Rejected during design in favour of MCP's native progress and
  cancellation notifications, which the pinned SDK already implements.
  Revisit only if real-world client support for progress/cancellation
  proves too unreliable in practice.
- **A dedicated resource-monitoring tool.** Every existing structured tool
  (`systemctl`, `dnf`, `journalctl`, network diagnostics) earned its own
  file because it needed real security-relevant argument handling
  (action allowlists, flag-injection hardening, trust-bypass patterns).
  Resource monitoring has no comparable hardening need; `run_command`
  plus new tier allow-rules for known-safe monitoring binaries covers it
  without an unjustified new abstraction.
- **Tier-gating indefinite execution.** The tier system answers "is this
  command safe to run at all," which is orthogonal to "for how long."
  Duration is bounded by the safety-net ceiling described below, not by
  tier. If real usage later shows indefinite processes being abused for
  resource exhaustion despite the safety net, that is the signal to
  revisit this, not a default assumption to build in now.
- **The separate "real-time interactive approval" backlog item.** That is
  a human-in-the-loop approval gate for the unrestricted-adjacent end of
  the policy spectrum, a fundamentally different mechanism (a pending
  request waiting on a human's yes/no) from a caller cancelling a command
  it already started. This spec does not address it, despite both
  involving mid-flight control over a running action.
- **Per-client customisation of progress message format, or streaming
  stdout and stderr as separate progress channels.** One interleaved
  text stream, same as the buffered result's `stdout`/`stderr` framing
  today, is sufficient for v1.

## Architecture

### The core shift

`executor::execute()` changes from "run, wait, return one buffered result"
to "run, streaming each output chunk to an optional sink as it arrives,
until the process exits, a safety-net duration elapses, or the caller
cancels, whichever comes first." This single change serves both the
long-command-progress case and the indefinite-execution case; the only
difference between them is whether the command would have exited on its
own before the safety net or a cancellation intervened.

`timeout_secs` (the existing per-call config value, default 30s) keeps its
current meaning and default for ordinary bounded commands. A new
**`max_stream_duration_secs`** config value (proposed default: 30 minutes)
is the absolute ceiling for calls using streaming/indefinite execution,
enforced by the server regardless of what a caller requests or whether it
ever cancels.

### Streaming

`dispatch()` (`src/tools/mod.rs`) extracts the incoming request's
`RequestContext<RoleServer>` (via whatever extractor `rmcp`'s `#[tool]`
macro provides for it, alongside the existing `Parameters<T>` extraction).
If the request carried a progress token (the client's opt-in signal per
the MCP spec), `dispatch()` passes the context's `Peer` handle into
`execute()` as a chunk sink. Each time the executor's stdout/stderr reader
tasks read a chunk, if a sink is present, it sends a
`notifications/progress` message via `peer.send_notification(...)`
(message = the chunk's text, progress = a running counter, no fixed
`total` since duration isn't known in advance for indefinite commands).

If no progress token is present, `dispatch()` passes no sink, and
`execute()`'s behaviour is unchanged from today: buffer everything,
return once. No tool file needs to know or care whether a given caller
wants streaming, that decision is made once, centrally, in `dispatch()`.

### Cancellation

The same `RequestContext` carries a `CancellationToken`
(`request_context.ct`) that `rmcp` cancels automatically when the client
sends `notifications/cancelled` for that request, no bookkeeping of
request IDs needed on RedWrench's side. `execute()`'s `tokio::select!`
gains this token as a third branch alongside "process exited" and
"safety-net duration elapsed." Cancellation kills the child via the exact
same `kill_on_drop`/explicit `.kill()` path the timeout branch already
uses (`src/executor.rs`), and the returned result is a structured error
(consistent with how a timeout is already reported), not a success.

### Tool-level changes

- **`ping`** (`src/tools/network.rs`): `count: u32` (default 4) becomes
  `count: Option<u32>`. When absent, the `-c` flag is omitted entirely,
  the correct way to invoke a genuinely indefinite ping. No change to the
  existing flood-flag hardening (`PING_ABUSE_FLAGS`), which governs
  content, not duration.
- **`journalctl_tail`** (`src/tools/journalctl.rs`): gains a `follow:
  bool` parameter (default `false`). When `true`, appends `-f` to the
  argv and the call becomes indefinite, governed by the same safety-net
  ceiling as any other streaming call. The existing `-n`/`lines` bound
  still sets the initial backlog shown before following begins.
- **`run_command`**: no interface change. Once `execute()` supports
  indefinite execution generically, `run_command` inherits it (an agent
  can already pass argv that never exits, e.g. `vmstat 1` with no count,
  the executor rewrite is what makes that safe rather than a bug).
- **`src/policy/tiers.rs`**: add allow-rules to `safe_rules()` for a
  small, named set of known-safe, read-only monitoring binaries (`vmstat`,
  `top -b` or similar batch-mode invocations, `sar`) so monitoring via
  `run_command` doesn't require `unrestricted` tier. The exact command
  list is an implementation-time decision, constrained to genuinely
  read-only tools consistent with `safe`'s existing "no mutation of
  system state" definition.

### Audit logging

A streaming/indefinite call now has a lifecycle, not a single atomic
allowed/denied-plus-result event. `src/audit.rs` gains a second audit
point: a "started" entry logged when a streaming/follow call begins,
in addition to today's completion entry logged when it ends (naturally,
by timeout, or by cancellation). Without this, an operator would have no
record that a long-running call was even in flight until it eventually
concluded, possibly tens of minutes later.

## Data flow (streaming case)

1. Agent sends a `tools/call` request with a progress token attached
   (client opt-in) and, for an indefinite command, no natural bound
   (e.g. `ping` with no `count`).
2. `dispatch()` runs the existing policy check unchanged. Denied calls
   behave exactly as today, no streaming applies to a denial.
3. On allow, `dispatch()` extracts the `RequestContext`, passes its
   `CancellationToken` and (if a progress token was present) its `Peer`
   into `executor::execute()`.
4. `execute()` spawns the process as today, but each chunk read from
   stdout/stderr is both accumulated (for the eventual buffered result,
   still truncated at `MAX_OUTPUT_BYTES` as today) and, if a sink is
   present, sent immediately as a `notifications/progress` message.
5. The call ends via exactly one of: the process exits naturally: return
   the buffered result as a success, same shape as today; the
   `max_stream_duration_secs` ceiling elapses: kill the process, return a
   structured error (same treatment as today's ordinary timeout);
   the client sends `notifications/cancelled`: kill the process, return a
   structured error distinct in its message from a timeout (so an agent
   or operator reading the audit log can tell the difference).
6. A completion audit entry is written in all three cases, in addition to
   the "started" entry from step 3.

## Error handling

Consistent with the existing three-way distinction in the original design
spec (auth/policy rejection vs. a command that ran and exited non-zero vs.
timeout/internal fault): cancellation joins timeout on the "generic
failure, no internal detail leaked" side, both are the calling agent not
getting a usable result, for different reasons the agent doesn't need
protocol-level detail on. The audit log, not the MCP response, is where
the distinction between "timed out" and "cancelled" is preserved.

## Testing strategy

- **Streaming emission**: a test asserting `execute()` sends progress
  messages via a mock/test sink when one is provided, and asserts nothing
  is sent (identical to today's `ExecutionResult` shape) when it isn't.
  This is the regression guard for "callers who don't opt in see no
  behavioural change."
- **Cancellation**: start an indefinite command (e.g. `sleep` with a long
  duration, or a real indefinite `ping` if network access allows in CI),
  cancel via the token, assert prompt termination well inside the
  safety-net ceiling.
- **Safety-net ceiling**: assert a command that never exits and is never
  cancelled is still killed once `max_stream_duration_secs` elapses.
- **Policy**: tests for the new `safe`-tier monitoring allow-rules,
  following the existing tier-test pattern in `src/policy/tiers.rs`.
- **Real end-to-end verification** (does a real MCP client actually send
  a progress token, does it actually send `notifications/cancelled` when
  a user asks to stop something) is not achievable in the dev sandbox
  this spec was written in, same limitation as v1.0's structured tool
  handlers. This becomes new UAT scenarios in
  `docs/uat/v1-uat-scenarios.md`, not a claim proven by the automated
  suite. A client that never sends a progress token or cancellation still
  gets today's buffered behaviour, so the worst case for an
  unsupportive client is no regression, not a broken call.

## Documentation impact

- `ARCHITECTURE.md`'s "Tools" and "Execution and audit" layer
  descriptions need updating to describe the streaming/cancellation path
  alongside the existing `dispatch()`/`CallToolResult` contract
  documentation added post-v1.0-review.
- `AGENTS.md` gains a note (a "fourth rule," following the existing
  three) that a new tool wanting indefinite execution gets it for free
  through `execute()`, and must not build its own timeout/streaming
  logic, the same "don't bypass the shared path" principle the first
  rule already states for policy checks.
- New UAT scenarios per the testing strategy above.

## Open implementation-time decisions

These are appropriately resolved during plan-writing or implementation,
not blocking this spec:

- The exact `rmcp` extractor syntax for pulling `RequestContext` into a
  `#[tool]`-annotated method (confirmed available via `FromContextPart`/
  `AsRequestContext` in the pinned SDK version, exact macro usage to be
  confirmed against the SDK's own test suite, the same way prior
  multi-router and error-result questions were resolved during v1.0).
- The exact monitoring-binary allow-list for `safe_rules()` (`vmstat`,
  `top -b`, `sar`, or a different set), and their exact safe invocation
  patterns (matching the existing per-command hardening precedent, e.g.
  `top` must be forced into batch mode, not interactive mode, to behave
  sensibly as a non-interactive tool call).
- The default value of `max_stream_duration_secs` (30 minutes proposed
  here, adjustable before implementation if that's the wrong order of
  magnitude for real usage).
