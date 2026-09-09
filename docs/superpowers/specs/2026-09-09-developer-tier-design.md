# RedWrench Developer Tier, Design Spec

**Date:** 2026-09-09
**Status:** Approved for implementation planning
**Motivated by:** UAT against a real deployment (`cia`), acting as a
DevOps engineer, found `standard` tier has zero capability to write,
compile, or run even a trivial "hello world" program, no file-write
primitive, no compiler/interpreter allowlist entries, and `run_command`'s
argv-only design means shell redirection isn't reachable even if a binary
were allowed. That gap is intentional today (`standard` administers an
already-built system, it doesn't build software), but real sysadmin work
sometimes needs exactly this: writing a simple C program, a bash script,
or a Python tool on the target machine. This spec is that capability,
scoped deliberately, not a blanket toolchain unlock.

## Summary

Adds a fourth policy tier, `developer`, sitting between `standard` and
`unrestricted`. It unlocks a short list of interpreters, compilers, and
build tools (`bash`, `sh`, `python3`, `gcc`, `cc`, `node`, `npm`, `cargo`,
`make`), each allowed unconditionally (no argument filtering), but
executed under a different identity than the rest of RedWrench: the
operator's own regular, non-root user account, rather than root.

That identity change, not command or argument filtering, is what bounds
the tier's risk. RedWrench itself keeps running as root (needed for
`systemctl`/`dnf`), but code this tier writes or runs is confined to
whatever a normal, non-root login on this machine could already do. A
`bash` script that tries `rm -rf /` fails with `Permission denied` on
nearly the entire tree, structurally, because the process attempting it
isn't root, not because RedWrench parsed the script and recognised
something dangerous in it.

## Why not command/argument filtering

Every other tier in RedWrench works by matching specific binaries and, for
the risky ones, specific argument patterns (deny-before-allow, anchored
regexes closing argument-injection classes). That approach is a poor fit
for this tier's actual content: `bash` and `python3` are general-purpose
interpreters whose entire purpose is running arbitrary script content
supplied as an argument. There is no useful subset of "safe bash scripts"
expressible as a regex the way "safe `ip` subcommands" is; trying would
produce an illusion of safety a few characters of obfuscation defeats,
the opposite of every other hardening pass this codebase has done. The
privilege drop sidesteps the problem instead of attempting to solve an
unsolvable one: it doesn't matter what the script says, only what the
account running it is permitted to touch.

## Scope decisions, made explicitly during design

Two real risk trade-offs were discussed and decided deliberately rather
than defaulted:

1. **File-write and execution scope is the operator's home directory**,
   not a dedicated empty sandbox directory. This is a real, natural
   development experience (`~/projects`, existing dotfiles, existing
   tooling config all reachable) at the cost of a materially larger
   attack surface than a clean, empty workspace would have been: the
   privilege drop protects the rest of the *system*, but it does not
   protect the *operator's own account* from a compromised or
   prompt-injected agent overwriting `~/.bashrc`, `~/.ssh/authorized_keys`,
   or any other file that account can already write. This is accepted,
   not mitigated by a path denylist in this spec (see Non-goals).
2. **Package installation (`npm install`, `pip install`, `cargo build`
   pulling new dependencies) is in scope, accepting the supply-chain
   risk.** Installing a package can execute arbitrary code automatically
   (npm `postinstall`, `setup.py`, `build.rs`) with no separate "run"
   step, a materially different and more automatic risk than compiling
   code the operator wrote themselves. This is a known, real-world
   exploited attack class. Accepted deliberately for this tier rather
   than excluded.

Both decisions raise this tier's real risk above what a purely
conservative design would choose. They stand as recorded, deliberate
choices, not oversights, should either warrant revisiting later.

## Non-goals

- **No path-based denylist inside the home directory** (excluding
  `~/.ssh`, shell rc files, etc. from writes). Per the scope decision
  above, this tier accepts that risk rather than attempting to enumerate
  every sensitive path, which is the same kind of incomplete-blocklist
  problem the rest of the codebase avoids for shell content. A future
  spec could add this; it is explicitly out of scope here.
- **No sandboxing beyond the UID/GID drop** (no bubblewrap, no
  namespaces, no `systemd-run` isolation, no resource limits). Named as
  Approach C during design and deferred as a future hardening pass once
  this tier has real-world track record, not a blocker for v1.
- **No content or flag validation on the developer-tier binaries.** No
  attempt to restrict `bash` script content, compiler flags, or
  `npm`/`pip`/`cargo` package names. The privilege drop is the entire
  safety mechanism for this tier.
- **`unrestricted` tier is unaffected.** It continues running everything
  as root, as today; the privilege drop applies specifically to
  developer-tier binary calls, not tier-wide, and is not inherited
  upward.

## Design

### Tier and config

A new `TierName::Developer` variant, inserted between `Standard` and
`Unrestricted` in `src/policy/tiers.rs`'s enum and everywhere it's
matched (`src/cli.rs`'s mirrored `TierName`, `src/main.rs`'s tier-name
conversion). `developer_rules()` extends `standard_rules()`, following
the existing `standard` extends `safe` pattern exactly: everything
`standard` allows remains allowed, plus the new developer-tier
allowlist.

`config.toml` gains a new field:

```toml
# Required when tier is "developer" or higher. The OS username whose
# identity developer-tier code execution (bash, python3, gcc, cc, node,
# npm, cargo, make) runs as, instead of root. RedWrench refuses to start
# if the tier requires this and it is missing or does not resolve to a
# real account.
developer_user = "macgyver"
```

`Config::load` (or equivalent startup validation in `main.rs`, alongside
the existing `unrestricted` tier gate) resolves `developer_user` to a
real UID/GID via the system's user database (the `nix` crate's
`nix::unistd::User::from_name`, or equivalent) when the active tier is
`Developer` or `Unrestricted`. Missing, empty, or unresolvable
`developer_user` under those tiers is a hard startup failure with a clear
message, the same posture the `unrestricted` tier's
`--i-understand-the-risk` gate already takes: fail loudly, not silently
degrade. `developer_user` is not required, and is ignored if present,
under `safe`/`standard`.

Setting the tier itself (`redwrench config set-tier developer`) needs no
new confirmation flag beyond what already exists. The deliberate-choice
gate for this tier is `developer_user` itself: an admin must explicitly
name a real account before the server will even start under this tier,
which is a stronger, self-verifying gate than a flag that just needs to
be present. `--i-understand-the-risk` remains specific to `unrestricted`.

### The allowlist

In `developer_rules()`, added to what `standard_rules()` already
provides:

```rust
allow("bash", None),
allow("sh", None),
allow("python3", None),
allow("gcc", None),
allow("cc", None),
allow("node", None),
allow("npm", None),
allow("cargo", None),
allow("make", None),
```

Each unconditional, no `arg_pattern`, matching the shape of the existing
`vmstat`/`sar`-style monitoring allows rather than the heavily
argument-restricted rules elsewhere in the file. No deny-before-allow
pairing is needed for these specifically, because (per "Why not
command/argument filtering" above) there is no meaningful subset of safe
arguments to carve out; the privilege drop is what bounds them.

### Privilege drop

Scoped to calls matching the developer-tier allowlist specifically, not
tier-wide. `dispatch()` (`src/tools/mod.rs`) already knows the resolved
`command` string before calling `execute()`; it checks whether `command`
is one of the developer-tier binaries and, if so and `config.developer_user`
resolved successfully at startup, passes the resolved `(uid, gid)`
through to `execute()`. Calls to `systemctl`, `dnf`, `journalctl`, etc.
under `developer` tier are unaffected and continue running as root,
exactly as under `standard`, since those genuinely need root privilege to
function regardless of which tier is active.

`execute()` (`src/executor.rs`) gains a new parameter,
`run_as: Option<(u32, u32)>` (uid, gid). When `Some`, it calls
`std::os::unix::process::CommandExt::uid()` and `.gid()` on the
`tokio::process::Command` builder before `.spawn()`. `tokio::process::Command`
re-exports the same `CommandExt` trait `std::process::Command` uses on
Unix, so this is a direct, well-supported addition, not a workaround.
When `None` (every existing call site, and every developer-tier call to a
non-allowlisted-for-this-purpose binary), behaviour is byte-identical to
today: the child inherits RedWrench's own root identity.

### Data flow

```
MCP tool call (e.g. run_command bash "-c" "cat > hello.c <<'EOF' ...")
  -> dispatch()
     -> PolicyEngine::evaluate("bash", args)
        -> developer_rules() (extends standard_rules()): allow("bash", None) matches
     -> command ("bash") is in the developer-tier binary list
     -> config.developer_user resolved at startup to (uid, gid)
     -> execute(..., run_as: Some((uid, gid)))
        -> Command::new("bash").args(...).uid(uid).gid(gid).spawn()
        -> child process runs as the operator's account, confined by
           real filesystem permissions to whatever that account can
           already touch
```

A `bash` script that writes `hello.c` to `~/hello.c`, compiles it with
`gcc`, and runs the resulting binary is therefore expressible as a single
`bash -c "..."` call: no dedicated `write_file` tool is needed, `bash`'s
own redirection and heredoc syntax is the file-write mechanism, exactly
as a real interactive developer session would use it.

### Error handling

- Startup: `developer`/`unrestricted` tier with missing or unresolvable
  `developer_user` refuses to start, mirroring the existing
  `unrestricted`-without-the-flag failure mode in `main.rs`.
- Runtime: if `Command::spawn()` fails because of the UID/GID change
  (e.g. RedWrench somehow lost the capability to drop privileges, or the
  resolved UID no longer exists), this surfaces through `execute()`'s
  existing `Err(err)` branch exactly like any other spawn failure,
  `stderr: format!("failed to spawn command: {err}")`. No new error path
  needed.

## Testing

Per `CONTRIBUTING.md`'s test bar for `src/policy/` changes:

1. Each developer-tier binary (`bash`, `sh`, `python3`, `gcc`, `cc`,
   `node`, `npm`, `cargo`, `make`) is allowed under `developer` and still
   denied under `safe` and `standard` (regression, confirms the tier
   boundary actually holds).
2. Config validation: `developer`/`unrestricted` tier with
   `developer_user` unset, empty, or naming a nonexistent account fails
   to start with a clear message; `safe`/`standard` with no
   `developer_user` set starts normally (the field is genuinely optional
   there).
3. **The privilege drop itself must be exercised directly, not assumed
   from the `Command` builder being configured.** A test that runs (as
   root, since this is exactly the scenario being guarded) something
   that reports its own effective UID (`id -u`, or an equivalent
   `bash -c` one-liner) with `run_as` set to a known non-root UID/GID
   present on the test machine, and asserts the reported UID matches the
   dropped identity, not RedWrench's own root UID. This is the one thing
   in this whole feature that must not be taken on faith: if the drop
   silently fails to apply, every other test in this list would still
   pass while the actual security guarantee did not hold.
4. Add UAT scenarios to `docs/uat/v1-uat-scenarios.md`: write and compile
   a trivial C program end to end under `developer` tier, and confirm
   (via `ps`/`id` on the target machine while it runs, or by inspecting
   the audit log) that the process ran under `developer_user`'s identity,
   not root. A follow-up scenario attempting `rm -rf /` (or a
   sufficiently contained proxy for it, e.g. `rm -rf /root` if `/root`
   isn't writable by the test account) under `developer` tier should
   confirm it fails with a permissions error, not a policy denial, the
   distinction that proves the guarantee is structural.

## Open questions carried into planning

- Exact mechanism for UID/GID resolution (which crate: `nix`, `users`, or
  a small amount of hand-written `libc` FFI) is an implementation detail
  for the plan to settle, not fixed here.
- Whether `sh` should really be a separate allow entry from `bash` given
  on most systems it's a symlink to `bash` or `dash`, or whether covering
  `bash` alone is sufficient, left for the plan/implementation to
  confirm against the actual target distribution's `/bin/sh`.
