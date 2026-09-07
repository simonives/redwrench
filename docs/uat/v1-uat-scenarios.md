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
   **Expected:** dnf fails cleanly looking for a literal package
   named `--nogpgcheck` (which does not exist) rather than actually
   disabling GPG verification. Confirm via `dnf history` (or
   equivalent) that no install with GPG checking disabled occurred,
   and that no package named `nogpgcheck` or similar was installed.
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
