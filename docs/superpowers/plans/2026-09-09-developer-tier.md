# Developer Policy Tier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth policy tier, `developer`, between `standard` and `unrestricted`, unlocking a short allowlist of interpreters/compilers/build tools whose execution drops privilege to a configured operator account instead of running as root.

**Architecture:** Extend the existing tier-composition pattern (`developer_rules()` extends `standard_rules()`, exactly as `standard` extends `safe`) with one new mechanism the codebase doesn't have yet: per-call privilege dropping in the executor, gated on both the resolved command being in a fixed tool list and the server having a validated `developer_user` configured. Everything else (policy evaluation, audit logging, timeout/streaming) is unchanged and reused as-is.

**Tech Stack:** Rust, `tokio::process::Command` (native `.uid()`/`.gid()` support on Unix, no extra trait import needed), the `nix` crate for username-to-UID/GID resolution.

**Spec:** `docs/superpowers/specs/2026-09-09-developer-tier-design.md`

## Global Constraints

- The privilege drop applies **only** to calls matching the developer-tier tool list, and **only** when the active tier is exactly `developer`. It must not apply under `unrestricted` (spec's explicit non-goal: "not inherited upward") and must not apply to non-developer-tools even under `developer` tier (`systemctl`/`dnf`/etc. keep running as root there, same as under `standard`).
- No argument or content filtering on the developer-tier tools (`bash`, `sh`, `python3`, `gcc`, `cc`, `node`, `npm`, `cargo`, `make`). The privilege drop is the entire safety mechanism; do not add `arg_pattern` restrictions to these allow rules.
- `developer_user` is required and validated at startup when the tier is `developer`; missing or unresolvable is a hard failure with a clear message, matching the existing `unrestricted`-without-`--i-understand-the-risk` failure style in `src/main.rs`. It is optional and ignored under every other tier.
- A caller that never reaches a developer-tier tool must see byte-identical behaviour to before this plan (existing tiers, existing tools, existing tests all still pass unmodified in their assertions).
- `cargo build`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` must all be clean at the end of every task.

---

### Task 1: Policy engine, the `developer` tier and its tool allowlist

**Files:**
- Modify: `src/policy/tiers.rs`

**Interfaces:**
- Produces: `TierName::Developer` variant; `pub const DEVELOPER_TOOLS: &[&str]`; `developer_rules() -> Vec<Rule>` (private, same visibility as `safe_rules`/`standard_rules`); `rules_for_tier` gains a `TierName::Developer => developer_rules()` arm.
- Consumes: nothing new; builds on the existing `allow`/`deny` helpers and `standard_rules()` already in this file.

- [ ] **Step 1: Add the `Developer` variant to `TierName`**

In `src/policy/tiers.rs`, change:

```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TierName {
    Safe,
    Standard,
    Unrestricted,
}
```

to:

```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TierName {
    Safe,
    Standard,
    Developer,
    Unrestricted,
}
```

This alone will not compile: `rules_for_tier`'s `match` and every other exhaustive `match` on `TierName` elsewhere in the crate now need a `Developer` arm. That's expected; later steps in this task and Task 2 add them. Do not run `cargo build` expecting success until Step 3 of this task.

- [ ] **Step 2: Write the failing tests for the new tool allowlist**

Add to the `#[cfg(test)] mod tests` block at the bottom of `src/policy/tiers.rs` (append after the existing tests, using the same `PolicyEngine::new(rules_for_tier(&TierName::...))` pattern already used throughout this file):

```rust
#[test]
fn developer_tier_allows_each_developer_tool_unconditionally() {
    let engine = PolicyEngine::new(rules_for_tier(&TierName::Developer));
    for tool in DEVELOPER_TOOLS {
        assert!(
            matches!(engine.evaluate(tool, &["--version".into()]), Decision::Allowed),
            "{tool} should be allowed under the developer tier"
        );
        // No argument restriction at all: an arbitrary-looking argument
        // must not be denied either, since the privilege drop, not
        // argument filtering, is this tier's safety mechanism.
        assert!(
            matches!(
                engine.evaluate(tool, &["-c".into(), "whatever this is".into()]),
                Decision::Allowed
            ),
            "{tool} must not have any argument restriction under developer"
        );
    }
}

#[test]
fn safe_and_standard_tiers_still_deny_every_developer_tool() {
    for tier in [TierName::Safe, TierName::Standard] {
        let engine = PolicyEngine::new(rules_for_tier(&tier));
        for tool in DEVELOPER_TOOLS {
            assert!(
                matches!(engine.evaluate(tool, &[]), Decision::Denied(_)),
                "{tool} must still be denied under {tier:?}"
            );
        }
    }
}

#[test]
fn developer_tier_inherits_every_standard_tier_allowance() {
    // developer_rules() must extend standard_rules(), not replace it:
    // service control and package management stay available.
    let engine = PolicyEngine::new(rules_for_tier(&TierName::Developer));
    assert!(matches!(
        engine.evaluate("systemctl", &["restart".into(), "sshd".into()]),
        Decision::Allowed
    ));
    assert!(matches!(
        engine.evaluate("dnf", &["install".into(), "-y".into(), "htop".into()]),
        Decision::Allowed
    ));
    // And standard's own hardening (dnf trust-bypass flags) still applies.
    assert!(matches!(
        engine.evaluate("dnf", &["install".into(), "--nogpgcheck".into(), "htop".into()]),
        Decision::Denied(_)
    ));
}
```

- [ ] **Step 3: Run the tests to verify they fail to compile**

Run: `cargo test --lib policy::tiers`
Expected: compile error, `DEVELOPER_TOOLS` and `developer_rules`/`TierName::Developer` arm do not exist yet, and the existing `rules_for_tier` match is now non-exhaustive.

- [ ] **Step 4: Add `DEVELOPER_TOOLS`, `developer_rules()`, and wire it into `rules_for_tier`**

Immediately above `fn rules_for_tier` in `src/policy/tiers.rs`, add:

```rust
/// Interpreters, compilers, and build tools unlocked by the `developer`
/// tier. Each is allowed unconditionally (no `arg_pattern`): there is no
/// useful subset of "safe bash scripts" or "safe compiler flags"
/// expressible as a regex the way "safe `ip` subcommands" is, and
/// attempting one would be an illusion of safety a few characters of
/// obfuscation defeats. The actual safety mechanism for this tier is the
/// privilege drop in `dispatch()`/`execute()` (see `RedWrenchServer`'s
/// `developer_identity` field and `src/executor.rs`'s `run_as`
/// parameter): whatever these tools do, they do it as the configured
/// `developer_user`, not as root, so the guarantee is ordinary Unix
/// permissions, not command filtering.
pub const DEVELOPER_TOOLS: &[&str] =
    &["bash", "sh", "python3", "gcc", "cc", "node", "npm", "cargo", "make"];

fn developer_rules() -> Vec<Rule> {
    let mut rules = standard_rules();
    rules.extend(DEVELOPER_TOOLS.iter().map(|tool| allow(tool, None)));
    rules
}
```

Then update `rules_for_tier`:

```rust
pub fn rules_for_tier(tier: &TierName) -> Vec<Rule> {
    match tier {
        TierName::Safe => safe_rules(),
        TierName::Standard => standard_rules(),
        TierName::Developer => developer_rules(),
        TierName::Unrestricted => vec![Rule {
            command: String::new(),
            arg_pattern: None,
            effect: Effect::Allow,
        }],
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib policy::tiers`
Expected: PASS, including the three new tests. This module will not fully compile as part of the whole crate yet, other files still have non-exhaustive `match`es on `TierName` (Task 2 fixes those); `cargo test --lib policy::tiers` alone will still fail to link until Task 2 is done. If your toolchain requires a full-crate build to run even a filtered test, skip ahead and run the full suite at the end of Task 2 instead; do not consider Task 1 blocked on this.

- [ ] **Step 6: Commit**

```bash
git add src/policy/tiers.rs
git commit -m "policy: add the developer tier and its tool allowlist"
```

---

### Task 2: CLI and config plumbing (`developer` tier setting, `developer_user` field)

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `src/config.rs`

**Interfaces:**
- Consumes: `policy::tiers::TierName::Developer` from Task 1.
- Produces: `cli::TierName::Developer`; `Config.developer_user: Option<String>`; every exhaustive `match` on either `TierName` enum in the crate compiles again.

- [ ] **Step 1: Add `Developer` to the CLI's mirrored `TierName`**

In `src/cli.rs`, change:

```rust
#[derive(Debug, Clone, PartialEq, clap::ValueEnum)]
pub enum TierName {
    Safe,
    Standard,
    Unrestricted,
}
```

to:

```rust
#[derive(Debug, Clone, PartialEq, clap::ValueEnum)]
pub enum TierName {
    Safe,
    Standard,
    Developer,
    Unrestricted,
}
```

`clap::ValueEnum`'s derive lowercases the variant name for the CLI string automatically (matching how `Unrestricted` already becomes `unrestricted` with no explicit rename attribute), so `developer` needs no extra attribute either.

- [ ] **Step 2: Write the failing test for CLI parsing**

Add to `src/cli.rs`'s existing `#[cfg(test)] mod tests` block, alongside `set_tier_unrestricted_requires_the_risk_flag`:

```rust
#[test]
fn set_tier_developer_parses_without_requiring_the_risk_flag() {
    let cli = Cli::try_parse_from(["redwrench", "config", "set-tier", "developer"]).unwrap();
    match cli.command {
        Some(Command::Config {
            command:
                ConfigCommand::SetTier {
                    tier,
                    i_understand_the_risk,
                },
        }) => {
            assert_eq!(tier, TierName::Developer);
            assert!(!i_understand_the_risk);
        }
        _ => panic!("expected Config(SetTier) command"),
    }
}
```

- [ ] **Step 3: Run the test to verify it fails to compile**

Run: `cargo test --bin redwrench cli::tests::set_tier_developer`
Expected: compile error, `TierName::Developer` doesn't exist in `cli.rs` yet if Step 1 wasn't done first, or (if Step 1 was done) this specific test should actually compile and pass already since `clap::ValueEnum` needs no further wiring for parsing alone. The remaining failures at this point come from `src/main.rs`'s now-non-exhaustive matches on both `TierName` enums, fixed next.

- [ ] **Step 4: Fix `src/main.rs`'s two non-exhaustive `TierName` matches**

In `main()`'s `Command::Config` handling, change:

```rust
let tier = match tier {
    cli::TierName::Safe => policy::tiers::TierName::Safe,
    cli::TierName::Standard => policy::tiers::TierName::Standard,
    cli::TierName::Unrestricted => policy::tiers::TierName::Unrestricted,
};
```

to:

```rust
let tier = match tier {
    cli::TierName::Safe => policy::tiers::TierName::Safe,
    cli::TierName::Standard => policy::tiers::TierName::Standard,
    cli::TierName::Developer => policy::tiers::TierName::Developer,
    cli::TierName::Unrestricted => policy::tiers::TierName::Unrestricted,
};
```

In `update_tier_in_config`, change:

```rust
let tier_str = match tier {
    policy::tiers::TierName::Safe => "safe",
    policy::tiers::TierName::Standard => "standard",
    policy::tiers::TierName::Unrestricted => "unrestricted",
};
```

to:

```rust
let tier_str = match tier {
    policy::tiers::TierName::Safe => "safe",
    policy::tiers::TierName::Standard => "standard",
    policy::tiers::TierName::Developer => "developer",
    policy::tiers::TierName::Unrestricted => "unrestricted",
};
```

- [ ] **Step 5: Fix `src/config.rs`'s non-exhaustive match in the empty-custom-rule-command error**

In `Config::load`, inside the `custom_rules.into_iter().map(...)` closure, change:

```rust
match raw.tier {
    TierName::Safe => "safe",
    TierName::Standard => "standard",
    TierName::Unrestricted => "unrestricted",
}
```

to:

```rust
match raw.tier {
    TierName::Safe => "safe",
    TierName::Standard => "standard",
    TierName::Developer => "developer",
    TierName::Unrestricted => "unrestricted",
}
```

- [ ] **Step 6: Run the CLI test to verify it passes, and confirm the whole crate compiles**

Run: `cargo build && cargo test --bin redwrench cli::tests::set_tier_developer`
Expected: clean build, test PASS.

- [ ] **Step 7: Write the failing tests for the `developer_user` config field**

Add to `src/config.rs`'s `#[cfg(test)] mod tests` block, alongside the other `Config::load` tests:

```rust
#[test]
fn developer_user_is_read_from_the_config_when_present() {
    let file = write_temp_config(
        r#"
        bind_address = "100.64.0.1:8443"
        bearer_token = "test-token"
        tier = "developer"
        developer_user = "macgyver"
        "#,
    );
    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.developer_user.as_deref(), Some("macgyver"));
}

#[test]
fn developer_user_defaults_to_none_when_absent() {
    let file = write_temp_config(
        r#"
        bind_address = "100.64.0.1:8443"
        bearer_token = "test-token"
        tier = "safe"
        "#,
    );
    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.developer_user, None);
}
```

- [ ] **Step 8: Run the tests to verify they fail**

Run: `cargo test --lib config::tests::developer_user`
Expected: compile error, `developer_user` is not a field on `Config` yet.

- [ ] **Step 9: Add the `developer_user` field to `RawConfig` and `Config`**

In `src/config.rs`, add to `RawConfig`:

```rust
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    bind_address: String,
    bearer_token: String,
    tier: TierName,
    #[serde(default)]
    custom_rules: Vec<RawRule>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    max_stream_duration_secs: Option<u64>,
    /// Required when `tier` is `developer` (or higher). The OS username
    /// developer-tier tool execution runs as instead of root. Validated
    /// at server startup (see `src/main.rs`), not here: this struct only
    /// parses the config's shape, cross-cutting tier preconditions are
    /// checked at the point the tier is actually turned into a running
    /// server, matching how the `unrestricted` tier's CLI-flag
    /// requirement is already checked in `main.rs`, not in `Config::load`.
    #[serde(default)]
    developer_user: Option<String>,
}
```

and to `Config`:

```rust
#[derive(Debug)]
pub struct Config {
    pub bind_address: String,
    pub bearer_token: String,
    pub tier: TierName,
    pub custom_rules: Vec<Rule>,
    pub timeout_secs: u64,
    pub max_stream_duration_secs: u64,
    pub developer_user: Option<String>,
}
```

and in `Config::load`'s final `Ok(Config { ... })` construction, add:

```rust
developer_user: raw.developer_user,
```

- [ ] **Step 10: Run the tests to verify they pass**

Run: `cargo build && cargo test --lib config::tests`
Expected: PASS, all config tests including the two new ones and every pre-existing one (this field is additive and optional, nothing else should change).

- [ ] **Step 11: Run the full existing suite to confirm nothing else broke**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS / clean. This is the point where every pre-existing test in the crate must still pass unmodified, confirming the two new enum variants and the new config field are additive and don't change any existing behaviour.

- [ ] **Step 12: Commit**

```bash
git add src/cli.rs src/main.rs src/config.rs
git commit -m "cli/config: wire the developer tier through CLI parsing and config loading"
```

---

### Task 3: Username resolution and the startup validation gate

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/main.rs`
- Modify: `src/tools/mod.rs`

**Interfaces:**
- Consumes: `Config.tier`, `Config.developer_user` from Task 2.
- Produces: `fn resolve_user(username: &str) -> anyhow::Result<(u32, u32)>` in `main.rs`; `RedWrenchServer.developer_identity: Option<(u32, u32)>` field; `RedWrenchServer::new()` gains a fifth parameter.

- [ ] **Step 1: Add the `nix` dependency**

In `Cargo.toml`, add to `[dependencies]`:

```toml
nix = { version = "0.31", features = ["user"] }
```

Run: `cargo build` to confirm it resolves and the lockfile updates. Expected: clean build (this dependency isn't used by any code yet, so there's nothing to test at this step beyond "it compiles").

- [ ] **Step 2: Write the failing tests for `resolve_user`**

Add a `#[cfg(test)] mod tests` block to `src/main.rs` (create it if one doesn't already exist; check first, since `cli::tests` lives in `cli.rs`, not here):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_real_username_to_its_numeric_uid_and_gid() {
        // "root" (uid 0, gid 0) exists on every Linux system, including
        // CI, which is why it's used here purely to exercise the
        // resolution mechanism. It is not an example of a sane real
        // `developer_user` value, dropping privilege *to* root would
        // defeat the entire point of this tier.
        let (uid, gid) = resolve_user("root").unwrap();
        assert_eq!(uid, 0);
        assert_eq!(gid, 0);
    }

    #[test]
    fn returns_a_clear_error_for_a_nonexistent_username() {
        let result = resolve_user("this-user-should-not-exist-anywhere-12345");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("this-user-should-not-exist-anywhere-12345"));
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail to compile**

Run: `cargo test --bin redwrench resolve_user`
Expected: compile error, `resolve_user` does not exist yet.

- [ ] **Step 4: Implement `resolve_user`**

Add to `src/main.rs`, near `update_tier_in_config` (a similarly small, focused helper):

```rust
/// Resolves a username to its numeric `(uid, gid)`, for the `developer`
/// tier's privilege-drop mechanism. `Ok(None)` is never returned:
/// `nix::unistd::User::from_name` returning `Ok(None)` (username not
/// found) is turned into a proper error here, since every caller of this
/// function needs a resolved identity or a reason it failed, not a third
/// "maybe" state to handle separately.
fn resolve_user(username: &str) -> anyhow::Result<(u32, u32)> {
    let user = nix::unistd::User::from_name(username)
        .map_err(|err| anyhow::anyhow!("failed to look up user '{username}': {err}"))?
        .ok_or_else(|| anyhow::anyhow!("no such user '{username}' on this system"))?;
    Ok((user.uid.as_raw(), user.gid.as_raw()))
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --bin redwrench resolve_user`
Expected: PASS, both tests.

- [ ] **Step 6: Write the failing tests for the startup gate**

This gate lives in `run_server`, which isn't structured for direct unit testing today (it binds a real TCP listener and calls `axum::serve`, which never returns under normal operation). Rather than restructure `run_server` itself, extract just the validation logic into a small, pure, testable function first, then call it from `run_server`.

Add to `src/main.rs`'s test module:

```rust
#[test]
fn developer_tier_without_a_developer_user_is_rejected() {
    let result = validate_developer_tier_precondition(&policy::tiers::TierName::Developer, &None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("developer_user"));
}

#[test]
fn developer_tier_with_a_nonexistent_developer_user_is_rejected() {
    let result = validate_developer_tier_precondition(
        &policy::tiers::TierName::Developer,
        &Some("this-user-should-not-exist-anywhere-12345".to_string()),
    );
    assert!(result.is_err());
}

#[test]
fn developer_tier_with_a_real_developer_user_succeeds() {
    let result = validate_developer_tier_precondition(
        &policy::tiers::TierName::Developer,
        &Some("root".to_string()),
    );
    assert_eq!(result.unwrap(), Some((0, 0)));
}

#[test]
fn non_developer_tiers_ignore_a_missing_developer_user() {
    for tier in [
        policy::tiers::TierName::Safe,
        policy::tiers::TierName::Standard,
        policy::tiers::TierName::Unrestricted,
    ] {
        let result = validate_developer_tier_precondition(&tier, &None);
        assert_eq!(result.unwrap(), None);
    }
}
```

- [ ] **Step 7: Run the tests to verify they fail to compile**

Run: `cargo test --bin redwrench validate_developer_tier_precondition`
Expected: compile error, function doesn't exist yet.

- [ ] **Step 8: Implement `validate_developer_tier_precondition`**

Add to `src/main.rs`, near `resolve_user`:

```rust
/// Checks the `developer` tier's precondition (a valid `developer_user`)
/// and resolves it if the tier needs it. Returns the resolved identity
/// so the caller doesn't have to resolve the same username twice.
///
/// Extracted from `run_server` so it can be unit-tested directly: that
/// function binds a real TCP listener and calls `axum::serve`, which
/// never returns under normal operation, so it cannot itself be exercised
/// by a `#[test]` the way this pure validation step can.
fn validate_developer_tier_precondition(
    tier: &policy::tiers::TierName,
    developer_user: &Option<String>,
) -> anyhow::Result<Option<(u32, u32)>> {
    if !matches!(tier, policy::tiers::TierName::Developer) {
        return Ok(None);
    }
    let username = developer_user.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "config specifies the 'developer' policy tier, which requires \
             'developer_user' to be set (the account developer-tier tool \
             execution runs as instead of root). Refusing to start without it."
        )
    })?;
    Ok(Some(resolve_user(username).map_err(|err| {
        anyhow::anyhow!(
            "config specifies the 'developer' policy tier with \
             developer_user = \"{username}\", but that account could not be \
             resolved: {err}"
        )
    })?))
}
```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cargo test --bin redwrench validate_developer_tier_precondition`
Expected: PASS, all four tests.

- [ ] **Step 10: Add the `developer_identity` field to `RedWrenchServer` and thread it through the constructor**

In `src/tools/mod.rs`, change:

```rust
#[derive(Clone)]
pub struct RedWrenchServer {
    pub policy: std::sync::Arc<PolicyEngine>,
    pub timeout: Duration,
    pub max_stream_duration: Duration,
    pub tier_name: String,
    pub tool_router: ToolRouter<Self>,
}
```

to:

```rust
#[derive(Clone)]
pub struct RedWrenchServer {
    pub policy: std::sync::Arc<PolicyEngine>,
    pub timeout: Duration,
    pub max_stream_duration: Duration,
    pub tier_name: String,
    /// `Some((uid, gid))` only when the active tier is `developer` and its
    /// `developer_user` precondition resolved successfully at startup;
    /// `None` under every other tier, including `unrestricted` (the
    /// privilege drop is not inherited upward, see the design spec's
    /// non-goals). `dispatch()` consults this to decide whether a given
    /// call to a developer-tier tool should run under this identity
    /// instead of root.
    pub developer_identity: Option<(u32, u32)>,
    pub tool_router: ToolRouter<Self>,
}
```

and change `RedWrenchServer::new`:

```rust
pub fn new(
    policy: std::sync::Arc<PolicyEngine>,
    timeout: Duration,
    tier_name: String,
    max_stream_duration: Duration,
) -> Self {
    Self {
        policy,
        timeout,
        max_stream_duration,
        tier_name,
        tool_router: Self::run_command_router()
            + Self::systemctl_router()
            + Self::dnf_router()
            + Self::journalctl_router()
            + Self::network_router(),
    }
}
```

to:

```rust
pub fn new(
    policy: std::sync::Arc<PolicyEngine>,
    timeout: Duration,
    tier_name: String,
    max_stream_duration: Duration,
    developer_identity: Option<(u32, u32)>,
) -> Self {
    Self {
        policy,
        timeout,
        max_stream_duration,
        tier_name,
        developer_identity,
        tool_router: Self::run_command_router()
            + Self::systemctl_router()
            + Self::dnf_router()
            + Self::journalctl_router()
            + Self::network_router(),
    }
}
```

- [ ] **Step 11: Fix every existing call site of `RedWrenchServer::new`**

This will not compile until every call site passes the fifth argument. In `src/tools/mod.rs`'s test module, update both `allow_all_server` and `deny_all_server`:

```rust
fn allow_all_server(timeout: Duration) -> RedWrenchServer {
    RedWrenchServer::new(
        std::sync::Arc::new(PolicyEngine::new(vec![Rule {
            command: String::new(),
            arg_pattern: None,
            effect: Effect::Allow,
        }])),
        timeout,
        "unrestricted".to_string(),
        Duration::from_secs(1800),
        None,
    )
}

fn deny_all_server(timeout: Duration) -> RedWrenchServer {
    RedWrenchServer::new(
        std::sync::Arc::new(PolicyEngine::new(vec![])),
        timeout,
        "safe".to_string(),
        Duration::from_secs(1800),
        None,
    )
}
```

- [ ] **Step 12: Wire the gate and the resolved identity into `run_server` in `src/main.rs`**

In `run_server`, immediately after the existing `unrestricted`-tier gate block (after its closing `}`, before `let tier_name = ...`), add:

```rust
let developer_identity =
    validate_developer_tier_precondition(&config.tier, &config.developer_user)?;
```

Then change the `RedWrenchServer::new` call:

```rust
let server = RedWrenchServer::new(
    Arc::new(policy::PolicyEngine::new(config.effective_rules())),
    Duration::from_secs(config.timeout_secs),
    tier_name,
    Duration::from_secs(config.max_stream_duration_secs),
);
```

to:

```rust
let server = RedWrenchServer::new(
    Arc::new(policy::PolicyEngine::new(config.effective_rules())),
    Duration::from_secs(config.timeout_secs),
    tier_name,
    Duration::from_secs(config.max_stream_duration_secs),
    developer_identity,
);
```

- [ ] **Step 13: Run the full suite to confirm everything compiles and passes**

Run: `cargo build && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: clean build, all tests PASS (including every pre-existing test in `src/tools/mod.rs`, unaffected since `developer_identity` is `None` in both test-helper servers), clippy and fmt clean.

- [ ] **Step 14: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs src/tools/mod.rs
git commit -m "main: resolve and validate developer_user, thread the identity into RedWrenchServer"
```

---

### Task 4: The privilege drop itself, in the executor and `dispatch()`

**Files:**
- Modify: `src/executor.rs`
- Modify: `src/tools/mod.rs`

**Interfaces:**
- Consumes: `RedWrenchServer.developer_identity` from Task 3; `policy::tiers::DEVELOPER_TOOLS` from Task 1.
- Produces: `execute()` gains a sixth parameter, `run_as: Option<(u32, u32)>`.

This is the task the whole tier exists for. Its own test (Step 6 below) is the one piece of this entire feature that must not be taken on faith.

- [ ] **Step 1: Write the failing test for the privilege drop**

Add to `src/executor.rs`'s `#[cfg(test)] mod tests` block:

```rust
#[tokio::test]
async fn run_as_drops_privilege_to_the_given_uid_and_gid() {
    // "nobody" exists on every Fedora system (this project's own
    // documented test environment, see CONTRIBUTING.md) and is never
    // uid/gid 0, which is exactly what this test needs to distinguish
    // "dropped" from "still root". Resolved dynamically rather than
    // hardcoding a numeric uid, since that number is a convention, not a
    // guarantee.
    let user = nix::unistd::User::from_name("nobody")
        .unwrap()
        .expect("'nobody' must exist on the Fedora test environment this project requires");
    let (uid, gid) = (user.uid.as_raw(), user.gid.as_raw());
    assert_ne!(uid, 0, "test is meaningless if 'nobody' resolved to root");

    let result = execute(
        "id",
        &["-u".to_string()],
        Duration::from_secs(5),
        None,
        None,
        Some((uid, gid)),
    )
    .await;

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(
        result.stdout.trim(),
        uid.to_string(),
        "the spawned process's own reported uid must match the dropped identity, \
         not RedWrench's (root's) uid"
    );
}

#[tokio::test]
async fn no_run_as_means_no_behavioural_change_from_the_existing_path() {
    // Regression guard: every existing caller passes `None` here, and
    // must see exactly today's behaviour.
    let result = execute(
        "echo",
        &["hello".to_string()],
        Duration::from_secs(5),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout.trim(), "hello");
}
```

Add `nix` as a dev-dependency-visible import at the top of the test module if it isn't already in scope crate-wide (it's a normal dependency from Task 3, so `nix::unistd::User` is reachable from anywhere in the crate, including tests, with no separate dev-dependency entry needed).

- [ ] **Step 2: Run the tests to verify they fail to compile**

Run: `cargo test --lib executor::tests::run_as_drops_privilege`
Expected: compile error, `execute()` doesn't take a sixth argument yet, and every other existing call to `execute()` in this same test module now has the wrong argument count too.

- [ ] **Step 3: Add the `run_as` parameter to `execute()` and apply it before spawn**

In `src/executor.rs`, change the signature:

```rust
pub async fn execute(
    command: &str,
    args: &[String],
    timeout: Duration,
    cancellation: Option<tokio_util::sync::CancellationToken>,
    chunk_sink: Option<ChunkSink>,
) -> ExecutionResult {
```

to:

```rust
pub async fn execute(
    command: &str,
    args: &[String],
    timeout: Duration,
    cancellation: Option<tokio_util::sync::CancellationToken>,
    chunk_sink: Option<ChunkSink>,
    run_as: Option<(u32, u32)>,
) -> ExecutionResult {
```

Update its doc comment to mention the new parameter:

```rust
/// Runs `command` with `args` as an argv vector (never through a shell),
/// bounded by `timeout`, optionally cancellable, optionally streaming each
/// output chunk to `chunk_sink` as it arrives, optionally spawned under a
/// different `(uid, gid)` than RedWrench's own (the `developer` tier's
/// privilege-drop mechanism, see `policy::tiers::DEVELOPER_TOOLS`).
```

Then change the spawn site from a single fluent expression into a builder that can conditionally take the identity, since `.uid()`/`.gid()` need to be called before `.spawn()` but only when `run_as` is `Some`:

```rust
let mut cmd = Command::new(command);
cmd.args(args)
    .kill_on_drop(true)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
if let Some((uid, gid)) = run_as {
    cmd.uid(uid).gid(gid);
}
let mut child = match cmd.spawn() {
    Ok(child) => child,
    Err(err) => {
        return ExecutionResult {
            exit_code: None,
            stdout: String::new(),
            stderr: format!("failed to spawn command: {err}"),
            timed_out: false,
            cancelled: false,
        };
    }
};
```

`tokio::process::Command::uid`/`.gid` are inherent methods (no extra trait import needed on this platform).

- [ ] **Step 4: Fix every existing call to `execute()` in this file's test module**

Every existing test in `src/executor.rs` calls `execute(...)` with five arguments. Add `None` as the sixth (trailing) argument to each one. There are several (the exact count depends on the current state of the file; search for `execute(` within `#[cfg(test)] mod tests` and update every match, not just a few). For example:

```rust
let result = execute(
    "echo",
    &["hello".to_string()],
    Duration::from_secs(5),
    None,
    None,
)
.await;
```

becomes:

```rust
let result = execute(
    "echo",
    &["hello".to_string()],
    Duration::from_secs(5),
    None,
    None,
    None,
)
.await;
```

Do this for every pre-existing call in the file (do not skip any; a missed one is a compile error naming its own line number, which is the fastest way to find it if any are missed).

- [ ] **Step 5: Run the full executor test module to verify everything compiles**

Run: `cargo build`
Expected: clean build. If it fails, the error will name every remaining `execute()` call site still missing the sixth argument; fix each and re-run.

- [ ] **Step 6: Run the new tests to verify they pass**

Run: `cargo test --lib executor::tests`
Expected: PASS, all tests in this module, including the two new ones. `run_as_drops_privilege_to_the_given_uid_and_gid` is the test that must not be taken on faith: if it passes, the reported UID inside the spawned process genuinely matches the dropped identity, not RedWrench's own root UID. If this environment cannot run as root (needed to drop privilege away from root in the first place) and the test fails for that reason specifically, note it in the task report rather than weakening the assertion, per `CONTRIBUTING.md` this project's own tests are expected to run on a real Fedora machine, not a sandboxed non-root CI shell, exactly to make tests like this meaningful.

- [ ] **Step 7: Write the failing test for `dispatch()`'s pass-through logic**

Add to `src/tools/mod.rs`'s `#[cfg(test)] mod tests` block. This needs a server with a non-`None` `developer_identity`, so add a small helper alongside `allow_all_server`/`deny_all_server`:

```rust
fn developer_tier_server(timeout: Duration, developer_identity: (u32, u32)) -> RedWrenchServer {
    RedWrenchServer::new(
        std::sync::Arc::new(PolicyEngine::new(
            crate::policy::tiers::rules_for_tier(&crate::policy::tiers::TierName::Developer),
        )),
        timeout,
        "developer".to_string(),
        Duration::from_secs(1800),
        Some(developer_identity),
    )
}

#[tokio::test]
async fn dispatch_drops_privilege_for_a_developer_tool_call() {
    let user = nix::unistd::User::from_name("nobody")
        .unwrap()
        .expect("'nobody' must exist on the Fedora test environment this project requires");
    let (uid, gid) = (user.uid.as_raw(), user.gid.as_raw());

    let server = developer_tier_server(Duration::from_secs(5), (uid, gid));
    let (ctx, _guard) = test_request_context(&server);
    let result = server
        .dispatch(
            "run_command",
            "sh",
            vec!["-c".to_string(), "id -u".to_string()],
            ctx,
            None,
        )
        .await;

    assert_eq!(result.is_error, Some(false));
    // dispatch() formats a successful result as "exit code: ...\nstdout:\n<output>\nstderr:\n",
    // so asserting the dropped uid appears right after "stdout:\n" confirms
    // it's the command's own reported identity, not a coincidental match
    // elsewhere in the formatted text.
    assert!(
        text_of(&result).contains(&format!("stdout:\n{uid}")),
        "expected the dropped uid ({uid}) in the command output, got: {}",
        text_of(&result)
    );
}

#[tokio::test]
async fn dispatch_does_not_drop_privilege_for_a_non_developer_tool_call() {
    // systemctl under the developer tier must behave exactly as it does
    // under standard: root, unaffected by developer_identity being set.
    // `systemctl status` is allowed under developer (inherited from
    // standard/safe) but `systemctl` is not in DEVELOPER_TOOLS, so this
    // call must not have privilege dropped. This test confirms the call
    // reaches the executor at all (is not denied by policy), it cannot
    // itself observe "ran as root" without a real systemctl target on the
    // test machine, that is what the run_as_drops_privilege tests in
    // executor.rs already cover for the mechanism itself.
    let server = developer_tier_server(Duration::from_secs(5), (65534, 65534));
    let (ctx, _guard) = test_request_context(&server);
    let result = server
        .dispatch(
            "systemctl_status",
            "systemctl",
            vec!["status".to_string(), "sshd".to_string()],
            ctx,
            None,
        )
        .await;
    assert!(
        !text_of(&result).starts_with("Denied:"),
        "systemctl status must still be allowed under developer tier, got: {}",
        text_of(&result)
    );
}
```

- [ ] **Step 8: Run the tests to verify they fail to compile or fail**

Run: `cargo test --lib tools::tests::dispatch_drops_privilege`
Expected: compile error or failure, `dispatch()` doesn't consult `developer_identity` yet.

- [ ] **Step 9: Implement the pass-through in `dispatch()`**

In `src/tools/mod.rs`'s `dispatch()`, the call to `crate::executor::execute` currently reads:

```rust
let result = crate::executor::execute(
    command,
    &args,
    effective_timeout,
    Some(ctx.ct.clone()),
    chunk_sink,
)
.await;
```

Immediately before this call, compute the identity to pass through:

```rust
// The privilege drop applies only to a developer-tier tool call, and
// only when this server actually has a resolved developer_identity
// (i.e. the active tier is exactly `developer`, see the field's own
// doc comment on RedWrenchServer, it is never Some under any other
// tier including unrestricted, so this check alone is sufficient,
// no separate tier-name comparison needed here).
let run_as = self
    .developer_identity
    .filter(|_| crate::policy::tiers::DEVELOPER_TOOLS.contains(&command));
```

Then update the call:

```rust
let result = crate::executor::execute(
    command,
    &args,
    effective_timeout,
    Some(ctx.ct.clone()),
    chunk_sink,
    run_as,
)
.await;
```

- [ ] **Step 10: Run the tests to verify they pass**

Run: `cargo test --lib tools::tests`
Expected: PASS, all tests in this module including the two new ones.

- [ ] **Step 11: Run the full suite**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: clean, every test in the crate PASS.

- [ ] **Step 12: Commit**

```bash
git add src/executor.rs src/tools/mod.rs
git commit -m "executor/dispatch: drop privilege to developer_identity for developer-tier tool calls"
```

---

### Task 5: Documentation and UAT scenarios

**Files:**
- Modify: `README.md`
- Modify: `docs/uat/v1-uat-scenarios.md`
- Modify: `ARCHITECTURE.md` (only if it names the tier list explicitly; check first)

**Interfaces:**
- Consumes: nothing new; this task only documents what Tasks 1-4 built.

- [ ] **Step 1: Add a `developer` row to the README's policy tiers table**

In `README.md`, the "Policy tiers" section's table currently reads:

```markdown
| Tier | What it permits |
| --- | --- |
| `safe` | Read-only diagnostics: ... |
| `standard` | Everything in `safe`, plus service start/stop/restart/enable/disable and `dnf`/`rpm-ostree` install/remove/upgrade. ... |
| `unrestricted` | Everything, including unfiltered raw command execution. No policy restrictions at all. |
```

Insert a new row between `standard` and `unrestricted`:

```markdown
| `developer` | Everything in `standard`, plus `bash`, `sh`, `python3`, `gcc`, `cc`, `node`, `npm`, `cargo`, and `make`, unconditionally (no argument restriction). These run under a configured `developer_user` account instead of root, not RedWrench's own filtering, that account's own Unix permissions are what bound the risk. Requires `developer_user` to be set in `config.toml`; the server refuses to start under this tier without it. |
```

Also add a short paragraph after the table (matching the existing style of the `unrestricted` explanation paragraph that follows it) explaining the `developer_user` requirement and the privilege-drop rationale in plain terms, a sentence or two, not a restatement of the whole design spec.

- [ ] **Step 2: Add the `developer_user` config key to the README's example config**

In the same example `config.toml` block the README already shows (with `bind_address`, `bearer_token`, `tier`, `timeout_secs`, `max_stream_duration_secs`), add, with a comment matching the style of the others:

```toml
# Required only when tier = "developer". The OS username developer-tier
# tool execution (bash, python3, gcc, npm, cargo, etc.) runs as, instead
# of root. The server refuses to start under the developer tier without
# this set to a real account on the machine.
developer_user = "your-username-here"
```

- [ ] **Step 3: Check `ARCHITECTURE.md` for an explicit tier list, update if present**

Read `ARCHITECTURE.md` and search for `safe`/`standard`/`unrestricted` mentioned together as a list. If found, add `developer` in the correct position with a one-line description consistent with how the others are described there. If the tier list isn't named explicitly there (only referenced generically, e.g. "three built-in tiers"), update any such count language to say "four" and leave the rest of the file's structure alone rather than adding a new section that duplicates the README's table.

- [ ] **Step 4: Add UAT scenarios**

Append to `docs/uat/v1-uat-scenarios.md`, following the existing scenario numbering and format (read the file's existing scenarios first to match the exact heading/step/expected style):

```markdown
## Scenario N: developer tier can write, compile, and run a trivial program, under a dropped identity

1. Set `tier = "developer"` and `developer_user = "<a real, non-root account on the test machine>"` in `config.toml`. Start `redwrench`.
2. From an MCP client, call `run_command` with `{"command": "bash", "args": ["-c", "cat > /home/<developer_user>/hello.c <<'EOF'\n#include <stdio.h>\nint main(void) { printf(\"hello world\\n\"); return 0; }\nEOF\ngcc /home/<developer_user>/hello.c -o /home/<developer_user>/hello && /home/<developer_user>/hello"]}`.
3. **Expected:** the call succeeds, output includes `hello world`.
4. On the target machine, while a longer-running variant of the same call is in flight (e.g. append `sleep 5` before the final run step), check `ps -o user= -p <pid>` for the `gcc`/`hello` process.
   **Expected:** the process's user is `developer_user`, not `root`.

## Scenario N+1: developer tier cannot destroy the system, structurally

1. With the same `developer` tier config as Scenario N, call `run_command` with `{"command": "bash", "args": ["-c", "rm -rf /root"]}` (or another root-owned path the `developer_user` account has no write access to; do not actually target `/` itself even though the same principle applies, to avoid needing to rebuild the test machine if something about the test setup is wrong).
2. **Expected:** the command runs (it is allowed by policy, `bash` is unconditionally allowed at this tier) but fails with a permissions error from `rm` itself (e.g. `rm: cannot remove '/root': Permission denied`), confirming the protection is the account's real Unix permissions, not a policy-level denial. Check the redwrench audit log for this call: it should show `decision="allowed"` (the policy engine permitted the call) with a nonzero exit code from `rm`, not `decision="denied"`, that distinction is what proves the guarantee is structural rather than pattern-matched.
```

- [ ] **Step 5: Run the full suite one final time**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: clean, every test passing. This task only touches documentation files, so this is a final confirmation nothing drifted, not an expectation of new test activity.

- [ ] **Step 6: Commit**

```bash
git add README.md docs/uat/v1-uat-scenarios.md ARCHITECTURE.md
git commit -m "docs: document the developer tier, its config, and its UAT scenarios"
```
