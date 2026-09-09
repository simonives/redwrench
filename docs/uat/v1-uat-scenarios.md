# RedWrench v1.0 UAT Scenarios

Manual verification scenarios. These check things the automated test
suite can't: real end-to-end behaviour against a real Fedora box and
real MCP clients. Run through all of these before tagging a v1.0
release, and any time the policy engine or transport layer changes.

## Scenario 1: `safe` tier blocks a destructive command

1. Configure `/etc/redwrench/config.toml` with `tier = "safe"`.
2. Start `redwrench`.
3. From an MCP client (Claude Code or Antigravity), call `run_command`
   with `{"command": "rm", "args": ["-rf", "/tmp/test"]}`.
4. **Expected:** the call returns a denial message naming the active
   tier (`safe`), the command does not run (confirm `/tmp/test`, if it
   existed, is untouched).

## Scenario 2: `standard` tier allows service control, `safe` doesn't

1. With `tier = "safe"`, call `systemctl_control` with
   `{"action": "stop", "unit": "some-test-service"}`.
   **Expected:** denied.
2. Switch to `standard` (`redwrench config set-tier standard`), restart
   `redwrench`.
3. Repeat the same call.
   **Expected:** the service actually stops (confirm with
   `systemctl_status`).

## Scenario 3: `unrestricted` tier requires the explicit flag

1. Run `redwrench config set-tier unrestricted` (no flag).
   **Expected:** a warning is printed, the command exits non-zero, and
   the config file's `tier` value is unchanged.
2. Run `redwrench config set-tier unrestricted --i-understand-the-risk`.
   **Expected:** the config file's `tier` value changes to
   `unrestricted`.

## Scenario 4: bind-address guard refuses blanket-public binding

1. Set `bind_address = "0.0.0.0:8443"` in the config.
2. Run `redwrench` without `--allow-public-bind`.
   **Expected:** the process refuses to start, printing an explanation.
3. Run it again with `--allow-public-bind`.
   **Expected:** it starts and binds successfully.

## Scenario 5: bearer token is actually enforced

1. With `redwrench` running, send an MCP request with no
   `Authorization` header, or an incorrect one.
   **Expected:** HTTP 401, no tool executes.
2. Send the same request with the correct bearer token.
   **Expected:** the request succeeds normally.

## Scenario 6: audit trail captures both allowed and denied calls

1. Perform one allowed call (e.g. `journalctl_tail`) and one denied
   call (e.g. `run_command` with `rm` under `safe` tier).
2. Run `journalctl -t redwrench` (or filter on the `redwrench::audit`
   target, per however the journal exposes it in practice).
   **Expected:** both invocations appear, with the tool name, resolved
   command, active tier, and outcome (allowed/denied) visible.

## Scenario 7: end-to-end connectivity from both supported clients

1. Connect to a running `redwrench` instance from Claude Code
   (`claude mcp add --transport http`).
   **Expected:** tools are discoverable and callable.
2. Connect to the same instance from Google Antigravity
   (`serverUrl` in `mcp_config.json`).
   **Expected:** tools are discoverable and callable.

## Scenario 8: config persistence caveat on immutable Fedora

Run on a Silverblue or Kinoite test system, if available:

1. Confirm `/etc/redwrench/config.toml` is writable and RedWrench
   reads changes to it normally within the current boot.
2. Perform an `rpm-ostree` rollback or reset, per the immutable
   variant's normal reset procedure.
3. **Expected:** confirm whether the config survives or reverts, and
   update this scenario's expected result with the actual observed
   behaviour once tested, this is currently unverified and documented
   as a known caveat in the design spec rather than an assumption.

## Scenario 9: argument-injection hardening holds against real binaries

Tasks 11, 12, and 13 hardened `dnf_install`/`dnf_remove`, `journalctl_tail`,
and `ping` against argument injection: a flag-shaped value in a
free-text parameter (`package`, `unit`, `host`) could otherwise be
reinterpreted by the target binary's own argv parser as an option
rather than as data. The unit tests in `src/tools/dnf.rs`,
`src/tools/journalctl.rs`, and `src/tools/network.rs` already confirm
the argv vectors RedWrench *constructs* are correct. What they can't
confirm is that the real `dnf`, `journalctl`, and `ping` binaries on a
real Fedora box actually behave safely when handed those hardened
argv vectors end-to-end. Run all three:

1. Call `dnf_install` with `{"package": "--nogpgcheck"}`.
   **Expected:** the call is rejected by RedWrench's policy engine
   before dispatch, so dnf is never invoked at all. The `--` separator
   makes the value a literal package name, and the tier's dnf deny rule
   matches it. Confirm via `dnf history` (or equivalent) that no
   install occurred, and that no package named `nogpgcheck` or similar
   was installed. The `--` hardening is the second line of defence
   here; the policy deny is the first.
2. Call `journalctl_tail` with `{"unit": "--file=/etc/shadow"}`.
   **Expected:** the call is rejected by RedWrench's own validation
   before journalctl ever runs (a clear error message naming the
   invalid unit, not journalctl output). Confirm the response never
   contains any content from `/etc/shadow`.
3. Call `ping` with `{"host": "-f", "count": 1}`.
   **Expected:** ping either fails looking for a literal hostname
   `-f` (DNS resolution failure) or otherwise behaves as a single
   ordinary ping, rather than actually running a flood ping. Confirm
   no flood ping executed: a real flood ping typically also requires
   elevated privileges (`CAP_NET_RAW`/root) and would either fail on
   permission grounds or be visibly different in behaviour and output
   timing from a normal single ping. If in doubt, watch outbound ICMP
   traffic (e.g. `tcpdump icmp` or equivalent) during the call and
   confirm it shows a single echo request rather than a rapid burst.

## Scenario 10: streaming output reaches the client live

1. Connect to a running `redwrench` instance from an MCP client that
   supports progress notifications (confirm which of Claude Code or
   Antigravity actually surfaces `notifications/progress` to the user,
   this is genuinely unverified against a real client as of this
   scenario being written).
2. Call `dnf_install` (or another command that takes several seconds)
   under the `standard` tier, with the client attaching a progress
   token.
3. **Expected:** output appears incrementally as the command runs, not
   as a single block only after it finishes.
4. Repeat the same call from a client that does NOT attach a progress
   token (or via a raw request with no `_meta.progressToken`).
5. **Expected:** behaviour is identical to pre-streaming RedWrench, one
   buffered result at the end, no partial output, no regression.

## Scenario 11: cancellation actually stops a running command

1. Call `run_command` with a long-running command (e.g. `sleep 30`)
   under a tier that allows it.
2. While it's running, send a cancellation for that request (however the
   connected MCP client exposes this, e.g. a "stop" action on an
   in-progress tool call).
3. **Expected:** the call ends quickly (well under 30 seconds), and
   `ps`/`pgrep` on the Fedora host confirms the `sleep` process is
   actually gone, not orphaned.
4. **Expected:** no response is delivered for the cancelled request. This
   is correct MCP behaviour, not a bug: rmcp removes a cancelled
   request's entry from its cancellation-token pool when the
   `notifications/cancelled` arrives, so RedWrench's own
   "Command cancelled by caller" result finds no entry to send against
   and is dropped. How the client renders that is the client's business
   (some show "cancelled", some simply stop waiting), so do not assert
   anything about what appears in its UI.
5. Check the journal (`journalctl -t redwrench` or equivalent) for the
   audit entry covering this call.
   **Expected:** an entry with `decision="cancelled"`, carrying the same
   `request_id` as the `"long-running invocation started"` entry for the
   same call. The audit log, not the response, is the durable record
   that a cancellation happened.

## Scenario 12: indefinite ping runs until cancelled or the safety net trips

1. Call `ping` with `host` set but `count` omitted.
2. **Expected:** the ping runs continuously; confirm via the streamed
   output (Scenario 10) that successive replies are visible over time,
   not just a final result.
3. Cancel the call (as in Scenario 11).
4. **Expected:** ping stops immediately, confirmed via `ps`/`pgrep`. As
   in Scenario 11, no response is delivered for the cancelled request;
   the journal's `decision="cancelled"` audit entry is the observable
   record.
5. Repeat without cancelling, and instead temporarily lower
   `max_stream_duration_secs` in the config to a small value (e.g. 10)
   to make the safety net practical to observe.
6. **Expected:** the call is killed once that duration elapses even
   though nobody cancelled it, confirming the safety net is not
   optional.

## Scenario 13: journalctl follow mode streams new log lines

1. Call `journalctl_tail` with `follow: true` against a unit that's
   actively logging (or trigger some activity on a chosen unit while the
   call is in flight).
2. **Expected:** new log lines appear in the streamed output as they're
   written to the journal, not only the initial `lines` backlog.
3. Cancel the call.
4. **Expected:** the call ends and `journalctl -f` for that unit is
   confirmed via `ps`/`pgrep` to no longer be running. As in Scenario 11,
   no response is delivered for the cancelled request; the journal's
   `decision="cancelled"` audit entry is the observable record.

## Scenario 14: monitoring binaries are usable under the safe tier

1. With `tier = "safe"`, call `run_command` with `vmstat 1`.
   **Expected:** allowed, runs, produces output (streamed if a progress
   token is attached, per Scenario 10).
2. Call `run_command` with `top -b -n 1`.
   **Expected:** allowed.
3. Call `run_command` with `top` (no `-b`, interactive mode).
   **Expected:** denied by policy (interactive top would hang as a
   non-interactive call).
4. Call `run_command` with `sar 1 5`.
   **Expected:** allowed.
5. Call `run_command` with `sar -o /tmp/evil.dat 1 5`.
   **Expected:** denied, the `-o` file-output flag is blocked.

## Scenario 15: developer tier can write, compile, and run a trivial program, under a dropped identity

1. Set `tier = "developer"` and `developer_user = "<a real, non-root account on the test machine>"` in `config.toml`. Start `redwrench`.
2. From an MCP client, call `run_command` with `{"command": "bash", "args": ["-c", "cat > /home/<developer_user>/hello.c <<'EOF'\n#include <stdio.h>\nint main(void) { printf(\"hello world\\n\"); return 0; }\nEOF\ngcc /home/<developer_user>/hello.c -o /home/<developer_user>/hello && /home/<developer_user>/hello"]}`.
3. **Expected:** the call succeeds, output includes `hello world`.
4. On the target machine, while a longer-running variant of the same call is in flight (e.g. append `sleep 5` before the final run step), check `ps -o user= -p <pid>` for the `gcc`/`hello` process.
   **Expected:** the process's user is `developer_user`, not `root`.

## Scenario 16: developer tier cannot destroy the system, structurally

1. With the same `developer` tier config as Scenario 15, call `run_command` with `{"command": "bash", "args": ["-c", "rm -rf /root"]}` (or another root-owned path the `developer_user` account has no write access to; do not actually target `/` itself even though the same principle applies, to avoid needing to rebuild the test machine if something about the test setup is wrong).
2. **Expected:** the command runs (it is allowed by policy, `bash` is unconditionally allowed at this tier) but fails with a permissions error from `rm` itself (e.g. `rm: cannot remove '/root': Permission denied`), confirming the protection is the account's real Unix permissions, not a policy-level denial. Check the redwrench audit log for this call: it should show `decision="allowed"` (the policy engine permitted the call) with a nonzero exit code from `rm`, not `decision="denied"`, that distinction is what proves the guarantee is structural rather than pattern-matched.
