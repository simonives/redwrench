# RedWrench v1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a working RedWrench v1.0: a Rust MCP server that lets an agent run policy-gated commands on a Fedora machine over Streamable HTTP, with a tiered permission model, an audit trail, and documentation good enough for a cold-start contributor (human or AI).

**Architecture:** One binary. A rule-matching policy engine decides allow/deny for every command. A single executor (`tokio::process`) runs approved commands, structured tools (`systemctl_status`, `dnf_install`, etc.) are thin builders of a command string that flow through the same executor and the same policy check as the general-purpose `run_command` tool, there is no second code path. Every invocation is logged to the systemd journal via `tracing-journald`. Transport is `rmcp` over Streamable HTTP behind a bearer-token check and a bind-address safety guard.

**Tech Stack:** Rust, `rmcp` 3.x (`server`, `transport-streamable-http-server` features), `axum`, `tokio`, `clap` + `clap_mangen`, `serde` + `toml`, `regex`, `tracing` + `tracing-journald`, `anyhow`.

**Spec:** `docs/superpowers/specs/2026-09-07-redwrench-design.md`

## Global Constraints

- Dual-licensed **MIT OR Apache-2.0** (spec, "Licensing"). Every source file that needs a license header uses both.
- Server must refuse to bind to `0.0.0.0` (or any address the bind-guard classifies as blanket-public) unless an explicit override flag is passed (spec, "MCP transport layer").
- Bearer token is checked before any other request processing (spec, "Data flow", step 2).
- Switching to the `unrestricted` tier requires an explicit `--i-understand-the-risk` flag; it cannot happen via a bare config edit alone (spec, "Policy engine").
- Every invocation, allowed or denied, is logged to the systemd journal (spec, "Executor and logger").
- v1.0 output is buffered, not streamed (spec, "Non-goals"). Do not build streaming support in this plan.
- CLI-first: no GUI work in this plan (spec, "Goals").
- Crate and repo name is `redwrench`, all lowercase (spec, "Naming").

---

## File Structure

```
redwrench/
├── Cargo.toml
├── LICENSE-MIT
├── LICENSE-APACHE
├── README.md
├── CONTRIBUTING.md
├── AGENTS.md
├── CLAUDE.md              (symlink to AGENTS.md)
├── ARCHITECTURE.md
├── justfile
├── build.rs               (generates man pages at build time)
├── .github/workflows/ci.yml
├── src/
│   ├── main.rs            (wires everything together, CLI entry point)
│   ├── cli.rs             (clap argument definitions)
│   ├── config.rs          (Config struct, TOML loading)
│   ├── policy/
│   │   ├── mod.rs         (PolicyEngine, Rule, Decision, Effect)
│   │   └── tiers.rs       (safe_tier, standard_tier, unrestricted_tier)
│   ├── executor.rs        (execute(), ExecutionResult)
│   ├── audit.rs           (init_journal_logging, record_invocation)
│   ├── auth.rs            (bearer token middleware, bind-address guard)
│   └── tools/
│       ├── mod.rs         (RedWrenchServer, shared dispatch())
│       ├── run_command.rs
│       ├── systemctl.rs
│       ├── dnf.rs
│       ├── journalctl.rs
│       └── network.rs
├── tests/
│   └── transport_auth.rs  (integration tests for auth.rs, run outside Fedora)
├── docs/
│   ├── uat/
│   │   └── v1-uat-scenarios.md
│   └── superpowers/{specs,plans}/...
└── packaging/
    └── redwrench.spec     (RPM spec for rust2rpm)
```

Rationale: `policy/`, `tools/` get their own directories because each will grow (more tiers, more tools) without the files that already exist changing shape. `config.rs`, `executor.rs`, `audit.rs`, `auth.rs` stay flat single-purpose files at the top of `src/`, each answers one question (what's configured, how do we run a command, how do we log it, how do we gate access).

---

### Task 1: Project scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `LICENSE-MIT`
- Create: `LICENSE-APACHE`
- Create: `README.md`
- Create: `.gitignore`
- Create: `src/main.rs`

**Interfaces:**
- Produces: a compiling, empty binary crate named `redwrench`.

- [ ] **Step 1: Create `Cargo.toml`**

```toml
[package]
name = "redwrench"
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
description = "A security-conscious MCP server exposing Fedora hardware and OS control to AI coding agents"
repository = "https://github.com/simonives/redwrench"

[dependencies]
rmcp = { version = "3.0", features = ["server", "transport-streamable-http-server"] }
tokio = { version = "1", features = ["full"] }
axum = "0.7"
tower = "0.4"
serde = { version = "1.0", features = ["derive"] }
schemars = "0.8"
toml = "0.8"
regex = "1"
tracing = "0.1"
tracing-journald = "0.3"
tracing-subscriber = "0.3"
clap = { version = "4", features = ["derive"] }
anyhow = "1"

[build-dependencies]
clap = { version = "4", features = ["derive"] }
clap_mangen = "0.2"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Add standard Rust `.gitignore`**

```
/target
Cargo.lock
```

(`Cargo.lock` is excluded because this is a binary-and-library-adjacent tool where reproducing exact lockfile behaviour isn't yet a project goal; revisit if packaging requires it committed.)

- [ ] **Step 3: Add `LICENSE-MIT` and `LICENSE-APACHE`**

Use the standard, unmodified text of the MIT license and the Apache License 2.0 (both are fixed, well-known texts, copy verbatim from https://opensource.org/license/mit and https://www.apache.org/licenses/LICENSE-2.0.txt, filling in `Copyright (c) 2026 Simon Ives` in the MIT file's copyright line).

- [ ] **Step 4: Write a minimal `src/main.rs`**

```rust
fn main() {
    println!("redwrench v{}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 5: Write a stub `README.md`**

```markdown
# RedWrench

A security-conscious MCP (Model Context Protocol) server exposing
hardware and OS control on a Fedora machine to AI coding agents
(Claude Code, Codex, Google Antigravity, etc.) running elsewhere on
the network.

Design spec: `docs/superpowers/specs/2026-09-07-redwrench-design.md`

Status: early development, not yet functional.

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and
`LICENSE-APACHE`.
```

- [ ] **Step 6: Verify it builds**

Run: `cargo build`
Expected: compiles cleanly, produces `target/debug/redwrench`.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml .gitignore LICENSE-MIT LICENSE-APACHE src/main.rs README.md
git commit -m "Scaffold redwrench crate with dual MIT/Apache-2.0 license"
```

---

### Task 2: Policy engine core types and matching

**Files:**
- Create: `src/policy/mod.rs`
- Modify: `src/main.rs:1` (add `mod policy;`)

**Interfaces:**
- Produces:
  - `pub struct Rule { pub command: String, pub arg_pattern: Option<Regex>, pub effect: Effect }`
  - `pub enum Effect { Allow, Deny }`
  - `pub enum Decision { Allowed, Denied(String) }` (the `String` is a human-readable reason)
  - `pub struct PolicyEngine { rules: Vec<Rule> }`
  - `impl PolicyEngine { pub fn new(rules: Vec<Rule>) -> Self; pub fn evaluate(&self, command: &str, args: &[String]) -> Decision }`

- [ ] **Step 1: Write the failing tests**

```rust
// src/policy/mod.rs (bottom of file, #[cfg(test)] mod)
#[cfg(test)]
mod tests {
    use super::*;

    fn rule(command: &str, arg_pattern: Option<&str>, effect: Effect) -> Rule {
        Rule {
            command: command.to_string(),
            arg_pattern: arg_pattern.map(|p| Regex::new(p).unwrap()),
            effect,
        }
    }

    #[test]
    fn allows_a_command_matching_an_allow_rule() {
        let engine = PolicyEngine::new(vec![rule("systemctl", Some("^status"), Effect::Allow)]);
        let decision = engine.evaluate("systemctl", &["status".into(), "sshd".into()]);
        assert!(matches!(decision, Decision::Allowed));
    }

    #[test]
    fn denies_a_command_with_no_matching_rule() {
        let engine = PolicyEngine::new(vec![rule("systemctl", Some("^status"), Effect::Allow)]);
        let decision = engine.evaluate("systemctl", &["stop".into(), "sshd".into()]);
        assert!(matches!(decision, Decision::Denied(_)));
    }

    #[test]
    fn first_matching_rule_wins() {
        let engine = PolicyEngine::new(vec![
            rule("systemctl", Some("^stop"), Effect::Deny),
            rule("systemctl", None, Effect::Allow),
        ]);
        let decision = engine.evaluate("systemctl", &["stop".into(), "sshd".into()]);
        assert!(matches!(decision, Decision::Denied(_)));
    }

    #[test]
    fn a_rule_with_no_arg_pattern_matches_any_arguments() {
        let engine = PolicyEngine::new(vec![rule("journalctl", None, Effect::Allow)]);
        let decision = engine.evaluate("journalctl", &["-u".into(), "sshd".into()]);
        assert!(matches!(decision, Decision::Allowed));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test policy::tests`
Expected: FAIL to compile, `PolicyEngine`, `Rule`, `Effect`, `Decision` don't exist yet.

- [ ] **Step 3: Write the implementation**

```rust
// src/policy/mod.rs (top of file, above the tests module)
use regex::Regex;

#[derive(Debug, Clone)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub command: String,
    pub arg_pattern: Option<Regex>,
    pub effect: Effect,
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Allowed,
    Denied(String),
}

pub struct PolicyEngine {
    rules: Vec<Rule>,
}

impl PolicyEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn evaluate(&self, command: &str, args: &[String]) -> Decision {
        let joined_args = args.join(" ");
        for rule in &self.rules {
            if rule.command != command {
                continue;
            }
            let arg_matches = match &rule.arg_pattern {
                Some(pattern) => pattern.is_match(&joined_args),
                None => true,
            };
            if !arg_matches {
                continue;
            }
            return match rule.effect {
                Effect::Allow => Decision::Allowed,
                Effect::Deny => Decision::Denied(format!(
                    "'{command} {joined_args}' is denied by policy"
                )),
            };
        }
        Decision::Denied(format!(
            "'{command} {joined_args}' has no matching allow rule"
        ))
    }
}
```

Note the `Decision` derive drops `PartialEq` from the `Denied` variant test assertions above (they use `matches!`, not `==`), so the derive is safe even though the message strings will never be equal across two independently-constructed `Denied` values.

- [ ] **Step 4: Add `mod policy;` to `src/main.rs`**

```rust
mod policy;

fn main() {
    println!("redwrench v{}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test policy::tests`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add src/policy/mod.rs src/main.rs
git commit -m "Add policy engine core: Rule, Effect, Decision, PolicyEngine::evaluate"
```

---

### Task 3: Policy engine hardening against injection-shaped arguments

**Files:**
- Modify: `src/policy/mod.rs` (tests only)

**Interfaces:**
- Consumes: `PolicyEngine::evaluate` from Task 2, unchanged signature.

This task exists because the spec explicitly calls for tests confirming argument-pattern matching isn't fooled by shell-injection-shaped input. It's a test-only task: if these tests fail, the fix belongs in how callers construct `args` (never pass a raw unsplit string to a single arg slot), not in the engine itself, so this task also documents that constraint for `executor.rs` in Task 6.

- [ ] **Step 1: Write the failing tests**

```rust
// src/policy/mod.rs, inside the existing #[cfg(test)] mod tests block

#[test]
fn a_trailing_shell_metacharacter_in_an_argument_does_not_bypass_a_deny_rule() {
    let engine = PolicyEngine::new(vec![
        rule("systemctl", Some("^stop"), Effect::Deny),
        rule("systemctl", None, Effect::Allow),
    ]);
    // Simulates an agent trying to smuggle a second command past the
    // "stop" deny by appending it to the same argument.
    let decision = engine.evaluate("systemctl", &["status".into(), "sshd; systemctl stop sshd".into()]);
    // This must be Denied, because the joined-args string still
    // contains "stop", and the deny rule for "stop" is checked before
    // the allow rule. If this ever becomes Allowed, the rule
    // ordering or matching logic has regressed.
    assert!(matches!(decision, Decision::Denied(_)));
}

#[test]
fn args_are_never_shell_interpreted_by_the_engine_itself() {
    // The policy engine only does regex matching on a joined string,
    // it never invokes a shell. This test documents that the engine
    // has no code path that could interpret `;`, `&&`, backticks,
    // or `$()` as anything other than literal characters to match
    // against. The real defence against shell interpretation lives
    // in executor.rs (Task 6), which must invoke commands via
    // tokio::process::Command with separate argv entries, never via
    // a shell (`sh -c`).
    let engine = PolicyEngine::new(vec![rule("echo", None, Effect::Allow)]);
    let decision = engine.evaluate("echo", &["hello `rm -rf /`".into()]);
    assert!(matches!(decision, Decision::Allowed));
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test policy::tests`
Expected: both new tests PASS immediately, since Task 2's implementation already joins args as plain strings for matching and never shells out. This task exists to lock that property in with an explicit test, not to fix a bug.

- [ ] **Step 3: Commit**

```bash
git add src/policy/mod.rs
git commit -m "Add regression tests for injection-shaped policy engine arguments"
```

---

### Task 4: Built-in tiers

**Files:**
- Create: `src/policy/tiers.rs`
- Modify: `src/policy/mod.rs:1` (add `pub mod tiers;`, make `Rule`/`Effect` fields usable from the submodule, they already are `pub`)

**Interfaces:**
- Consumes: `Rule`, `Effect` from Task 2.
- Produces:
  - `pub enum TierName { Safe, Standard, Unrestricted }`
  - `pub fn rules_for_tier(tier: &TierName) -> Vec<Rule>`

- [ ] **Step 1: Write the failing tests**

```rust
// src/policy/tiers.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Decision, PolicyEngine};

    #[test]
    fn safe_tier_allows_systemctl_status_but_denies_stop() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("systemctl", &["status".into(), "sshd".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate("systemctl", &["stop".into(), "sshd".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn safe_tier_denies_dnf_and_raw_run_command_entirely() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
        assert!(matches!(
            engine.evaluate("dnf", &["install".into(), "-y".into(), "htop".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn standard_tier_allows_systemctl_stop_and_dnf_install() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        assert!(matches!(
            engine.evaluate("systemctl", &["stop".into(), "sshd".into()]),
            Decision::Allowed
        ));
        assert!(matches!(
            engine.evaluate("dnf", &["install".into(), "-y".into(), "htop".into()]),
            Decision::Allowed
        ));
    }

    #[test]
    fn standard_tier_still_denies_arbitrary_raw_commands() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
        assert!(matches!(
            engine.evaluate("rm", &["-rf".into(), "/".into()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn unrestricted_tier_allows_anything() {
        let engine = PolicyEngine::new(rules_for_tier(&TierName::Unrestricted));
        assert!(matches!(
            engine.evaluate("rm", &["-rf".into(), "/".into()]),
            Decision::Allowed
        ));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test policy::tiers::tests`
Expected: FAIL to compile, `rules_for_tier` and `TierName` don't exist yet.

- [ ] **Step 3: Write the implementation**

```rust
// src/policy/tiers.rs (above the tests module)
use super::{Effect, Rule};
use regex::Regex;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TierName {
    Safe,
    Standard,
    Unrestricted,
}

fn allow(command: &str, arg_pattern: Option<&str>) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: arg_pattern.map(|p| Regex::new(p).unwrap()),
        effect: Effect::Allow,
    }
}

fn deny_all(command: &str) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: None,
        effect: Effect::Deny,
    }
}

fn safe_rules() -> Vec<Rule> {
    vec![
        allow("systemctl", Some("^status")),
        allow("systemctl", Some("^is-active")),
        allow("systemctl", Some("^is-enabled")),
        allow("journalctl", None),
        allow("ping", None),
        allow("ip", Some("^(addr|route|link)")),
    ]
}

fn standard_rules() -> Vec<Rule> {
    let mut rules = safe_rules();
    rules.extend(vec![
        allow("systemctl", Some("^(start|stop|restart|enable|disable)")),
        allow("dnf", Some("^(install|remove|upgrade)")),
        allow("rpm-ostree", Some("^(install|upgrade|status)")),
    ]);
    rules
}

pub fn rules_for_tier(tier: &TierName) -> Vec<Rule> {
    match tier {
        TierName::Safe => safe_rules(),
        TierName::Standard => standard_rules(),
        TierName::Unrestricted => vec![Rule {
            command: String::new(),
            arg_pattern: None,
            effect: Effect::Allow,
        }],
    }
}
```

`Unrestricted` needs a small adjustment to `PolicyEngine::evaluate` from Task 2, since matching currently requires `rule.command == command` exactly, an empty-string wildcard won't match anything. Update `evaluate` before running these tests:

```rust
// src/policy/mod.rs, inside impl PolicyEngine, replace the rule-matching loop's
// first check with:
if !rule.command.is_empty() && rule.command != command {
    continue;
}
```

- [ ] **Step 4: Add `pub mod tiers;` to `src/policy/mod.rs`**

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test policy`
Expected: all policy tests (Tasks 2, 3, 4) pass, 9 total.

- [ ] **Step 6: Commit**

```bash
git add src/policy/mod.rs src/policy/tiers.rs
git commit -m "Add safe/standard/unrestricted policy tiers"
```

---

### Task 5: Config loading

**Files:**
- Create: `src/config.rs`
- Modify: `src/main.rs:1` (add `mod config;`)

**Interfaces:**
- Consumes: `TierName`, `Rule`, `Effect` from Tasks 2 and 4.
- Produces:
  - `pub struct Config { pub bind_address: String, pub bearer_token: String, pub tier: TierName, pub custom_rules: Vec<Rule> }`
  - `impl Config { pub fn load(path: &std::path::Path) -> anyhow::Result<Self> }`
  - `impl Config { pub fn effective_rules(&self) -> Vec<Rule> }` (tier rules + custom rules appended, since custom rules should be checked after tier defaults per the spec's "layer custom allow/deny rules on top of whichever tier is active")

- [ ] **Step 1: Write the failing tests**

```rust
// src/config.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_config(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    #[test]
    fn loads_a_minimal_config() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.bind_address, "100.64.0.1:8443");
        assert_eq!(config.bearer_token, "test-token");
        assert_eq!(config.tier, crate::policy::tiers::TierName::Safe);
        assert!(config.custom_rules.is_empty());
    }

    #[test]
    fn effective_rules_appends_custom_rules_after_tier_defaults() {
        let file = write_temp_config(
            r#"
            bind_address = "100.64.0.1:8443"
            bearer_token = "test-token"
            tier = "safe"

            [[custom_rules]]
            command = "curl"
            effect = "allow"
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        let rules = config.effective_rules();
        let tier_only_len = crate::policy::tiers::rules_for_tier(&crate::policy::tiers::TierName::Safe).len();
        assert_eq!(rules.len(), tier_only_len + 1);
        assert_eq!(rules.last().unwrap().command, "curl");
    }

    #[test]
    fn missing_file_returns_an_error() {
        let result = Config::load(std::path::Path::new("/nonexistent/redwrench.toml"));
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test config::tests`
Expected: FAIL to compile, `Config` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

```rust
// src/config.rs (above the tests module)
use crate::policy::tiers::TierName;
use crate::policy::{Effect, Rule};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RawRule {
    command: String,
    arg_pattern: Option<String>,
    effect: String,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    bind_address: String,
    bearer_token: String,
    tier: TierName,
    #[serde(default)]
    custom_rules: Vec<RawRule>,
}

#[derive(Debug)]
pub struct Config {
    pub bind_address: String,
    pub bearer_token: String,
    pub tier: TierName,
    pub custom_rules: Vec<Rule>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let raw: RawConfig = toml::from_str(&contents)?;
        let custom_rules = raw
            .custom_rules
            .into_iter()
            .map(|r| {
                Ok(Rule {
                    command: r.command,
                    arg_pattern: r.arg_pattern.map(|p| regex::Regex::new(&p)).transpose()?,
                    effect: match r.effect.as_str() {
                        "allow" => Effect::Allow,
                        "deny" => Effect::Deny,
                        other => anyhow::bail!("unknown effect '{other}', expected 'allow' or 'deny'"),
                    },
                })
            })
            .collect::<anyhow::Result<Vec<Rule>>>()?;
        Ok(Config {
            bind_address: raw.bind_address,
            bearer_token: raw.bearer_token,
            tier: raw.tier,
            custom_rules,
        })
    }

    pub fn effective_rules(&self) -> Vec<Rule> {
        let mut rules = crate::policy::tiers::rules_for_tier(&self.tier);
        rules.extend(self.custom_rules.iter().cloned());
        rules
    }
}
```

`TierName` needs `Deserialize` derived in Task 4's definition, confirm it's there (it is, added in Task 4's implementation step). `Rule` needs `Clone` derived for the `.cloned()` call, confirm Task 2's `#[derive(Debug, Clone)]` on `Rule` covers this (it does).

- [ ] **Step 4: Add `mod config;` to `src/main.rs`**

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test config::tests`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add src/config.rs src/main.rs
git commit -m "Add Config::load with TOML parsing and custom rule layering"
```

---

### Task 6: Executor

**Files:**
- Create: `src/executor.rs`
- Modify: `src/main.rs:1` (add `mod executor;`)

**Interfaces:**
- Produces:
  - `pub struct ExecutionResult { pub exit_code: Option<i32>, pub stdout: String, pub stderr: String, pub timed_out: bool }`
  - `pub async fn execute(command: &str, args: &[String], timeout: std::time::Duration) -> ExecutionResult`

This is the only place in the codebase that spawns a process. It always uses `tokio::process::Command` with `command` and `args` as separate argv entries, never a shell string, this is the concrete enforcement of the property Task 3 documented in tests.

- [ ] **Step 1: Write the failing tests**

```rust
// src/executor.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn captures_stdout_and_exit_code_of_a_successful_command() {
        let result = execute("echo", &["hello".to_string()], Duration::from_secs(5)).await;
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout.trim(), "hello");
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn captures_stderr_and_nonzero_exit_code_of_a_failing_command() {
        let result = execute("ls", &["/nonexistent-path-xyz".to_string()], Duration::from_secs(5)).await;
        assert_ne!(result.exit_code, Some(0));
        assert!(!result.stderr.is_empty());
    }

    #[tokio::test]
    async fn a_shell_metacharacter_in_an_argument_is_never_interpreted() {
        // If this were run via a shell, `; echo pwned` would execute
        // as a second command. Since it's passed as a literal argv
        // entry to `echo`, it must appear verbatim in stdout instead.
        let result = execute(
            "echo",
            &["hello; echo pwned".to_string()],
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(result.stdout.trim(), "hello; echo pwned");
    }

    #[tokio::test]
    async fn a_command_exceeding_the_timeout_is_killed_and_marked_timed_out() {
        let result = execute("sleep", &["5".to_string()], Duration::from_millis(100)).await;
        assert!(result.timed_out);
        assert_eq!(result.exit_code, None);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test executor::tests`
Expected: FAIL to compile, `execute` and `ExecutionResult` don't exist yet.

- [ ] **Step 3: Write the implementation**

```rust
// src/executor.rs (above the tests module)
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug)]
pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

pub async fn execute(command: &str, args: &[String], timeout: Duration) -> ExecutionResult {
    let child = Command::new(command)
        .args(args)
        .output();

    match tokio::time::timeout(timeout, child).await {
        Ok(Ok(output)) => ExecutionResult {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            timed_out: false,
        },
        Ok(Err(err)) => ExecutionResult {
            exit_code: None,
            stdout: String::new(),
            stderr: format!("failed to spawn command: {err}"),
            timed_out: false,
        },
        Err(_elapsed) => ExecutionResult {
            exit_code: None,
            stdout: String::new(),
            stderr: format!("command timed out after {timeout:?}"),
            timed_out: true,
        },
    }
}
```

Note: `tokio::time::timeout` on a `.output()` future drops the future on timeout, which drops the `Child`, which (per `tokio::process` documentation) kills the child process. No explicit `.kill()` call is needed, but this behaviour is exactly what Step 4's test below confirms, don't remove that test if refactoring this later.

- [ ] **Step 4: Add `mod executor;` to `src/main.rs`**

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test executor::tests`
Expected: 4 passed. (These require a Unix-like environment with `echo`, `ls`, `sleep` on PATH, they will pass on the Fedora dev box; they are not expected to pass if ever run on a bare Windows CI runner, which this project does not target.)

- [ ] **Step 6: Commit**

```bash
git add src/executor.rs src/main.rs
git commit -m "Add executor: argv-only process spawning with timeout"
```

---

### Task 7: Audit logging

**Files:**
- Create: `src/audit.rs`
- Modify: `src/main.rs:1` (add `mod audit;`)

**Interfaces:**
- Produces:
  - `pub fn init_journal_logging() -> anyhow::Result<()>`
  - `pub fn record_invocation(tool: &str, command: &str, tier: &str, decision: &str, exit_code: Option<i32>)`

`decision` is a plain `&str` (`"allowed"` or `"denied"`) rather than reusing `policy::Decision` directly, so `audit.rs` doesn't need to depend on `policy`'s internals, it only needs to know what happened, not why.

- [ ] **Step 1: Write the implementation**

There isn't a meaningful unit test for "did this write to the systemd journal", journal output isn't easily captured in a `cargo test` run, and mocking `tracing`'s subscriber to assert on emitted events is more test-framework ceremony than this warrants for a hobby project's audit shim. Instead, this task is verified by a UAT scenario (Task 17) that actually runs `journalctl` and confirms an entry appears. Write the implementation directly:

```rust
// src/audit.rs
use tracing_subscriber::prelude::*;

pub fn init_journal_logging() -> anyhow::Result<()> {
    let journald_layer = tracing_journald::layer()?;
    tracing_subscriber::registry().with(journald_layer).init();
    Ok(())
}

pub fn record_invocation(tool: &str, command: &str, tier: &str, decision: &str, exit_code: Option<i32>) {
    tracing::info!(
        target: "redwrench::audit",
        tool,
        command,
        tier,
        decision,
        exit_code,
        "tool invocation"
    );
}
```

- [ ] **Step 2: Add `mod audit;` to `src/main.rs`**

- [ ] **Step 3: Verify it builds**

Run: `cargo build`
Expected: compiles cleanly. `tracing_journald::layer()` will fail at runtime on a non-systemd machine (returns an `Err`), which is why `init_journal_logging` returns a `Result`, callers (Task 9's `main`) must handle that failure rather than unwrap it, since this crate may occasionally be built and test-compiled on machines without a systemd journal (e.g. inside certain CI containers).

- [ ] **Step 4: Commit**

```bash
git add src/audit.rs src/main.rs
git commit -m "Add systemd journal audit logging via tracing-journald"
```

---

### Task 8: Bind-address guard and bearer token auth

**Files:**
- Create: `src/auth.rs`
- Modify: `src/main.rs:1` (add `mod auth;`)

**Interfaces:**
- Produces:
  - `pub fn validate_bind_address(addr: &str, allow_public: bool) -> anyhow::Result<()>`
  - `pub async fn require_bearer_token(expected_token: String, req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response` (an axum middleware function, used via `axum::middleware::from_fn_with_state` or a closure capturing `expected_token`, wired in Task 9)

- [ ] **Step 1: Write the failing tests**

```rust
// src/auth.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_0_0_0_0_without_override() {
        let result = validate_bind_address("0.0.0.0:8443", false);
        assert!(result.is_err());
    }

    #[test]
    fn allows_0_0_0_0_with_explicit_override() {
        let result = validate_bind_address("0.0.0.0:8443", true);
        assert!(result.is_ok());
    }

    #[test]
    fn allows_a_specific_tailscale_style_address_without_override() {
        let result = validate_bind_address("100.64.0.1:8443", false);
        assert!(result.is_ok());
    }

    #[test]
    fn allows_localhost_without_override() {
        let result = validate_bind_address("127.0.0.1:8443", false);
        assert!(result.is_ok());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test auth::tests`
Expected: FAIL to compile, `validate_bind_address` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

```rust
// src/auth.rs (above the tests module)
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

pub fn validate_bind_address(addr: &str, allow_public: bool) -> anyhow::Result<()> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let is_blanket_public = host == "0.0.0.0" || host == "::";
    if is_blanket_public && !allow_public {
        anyhow::bail!(
            "refusing to bind to blanket-public address '{addr}'. \
             If you genuinely intend this, pass --allow-public-bind. \
             This tool executes commands on your system; binding it to \
             every interface, including the public internet, is almost \
             never what you want."
        );
    }
    Ok(())
}

pub async fn require_bearer_token(expected_token: String, req: Request, next: Next) -> Response {
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if token == expected_token => next.run(req).await,
        _ => {
            tracing::warn!(target: "redwrench::audit", "rejected request with invalid or missing bearer token");
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(axum::body::Body::empty())
                .unwrap()
        }
    }
}
```

- [ ] **Step 4: Add `mod auth;` to `src/main.rs`**

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test auth::tests`
Expected: 4 passed. (`require_bearer_token` is exercised by an integration test in Task 9, once there's a real router to send requests through, not here, it needs a live `axum::Router` to test meaningfully.)

- [ ] **Step 6: Commit**

```bash
git add src/auth.rs src/main.rs
git commit -m "Add bind-address safety guard and bearer token auth middleware"
```

---

### Task 9: Wire up the MCP transport with the `run_command` tool

**Files:**
- Create: `src/tools/mod.rs`
- Create: `src/tools/run_command.rs`
- Create: `src/cli.rs`
- Modify: `src/main.rs` (replace stub with real assembly)
- Create: `tests/transport_auth.rs`

**Interfaces:**
- Consumes: `Config` (Task 5), `PolicyEngine`/`Decision` (Task 2), `execute`/`ExecutionResult` (Task 6), `record_invocation` (Task 7), `validate_bind_address`/`require_bearer_token` (Task 8).
- Produces:
  - `pub struct RedWrenchServer { policy: std::sync::Arc<PolicyEngine>, timeout: std::time::Duration, tier_name: String }`
  - `impl RedWrenchServer { pub async fn dispatch(&self, tool: &str, command: &str, args: Vec<String>) -> String }` (reads `self.tier_name` internally rather than taking it as a parameter; the shared path every tool in Tasks 10-13 calls into: policy check, execute, audit log, format result as a string for the MCP response)
  - `run_command` exposed as an MCP tool via `#[tool_router(server_handler)]`.

This is the task where the whole stack proves itself end to end for the first time: an agent can connect, call `run_command`, and get a real, policy-checked, audited result back.

- [ ] **Step 1: Write `src/tools/mod.rs` with the shared dispatch logic**

```rust
// src/tools/mod.rs
use crate::policy::{Decision, PolicyEngine};
use std::time::Duration;

pub mod run_command;

#[derive(Clone)]
pub struct RedWrenchServer {
    pub policy: std::sync::Arc<PolicyEngine>,
    pub timeout: Duration,
    pub tier_name: String,
}

impl RedWrenchServer {
    pub async fn dispatch(&self, tool: &str, command: &str, args: Vec<String>) -> String {
        match self.policy.evaluate(command, &args) {
            Decision::Denied(reason) => {
                crate::audit::record_invocation(tool, command, &self.tier_name, "denied", None);
                format!("Denied: {reason} (active tier: {})", self.tier_name)
            }
            Decision::Allowed => {
                let result = crate::executor::execute(command, &args, self.timeout).await;
                crate::audit::record_invocation(
                    tool,
                    command,
                    &self.tier_name,
                    "allowed",
                    result.exit_code,
                );
                if result.timed_out {
                    format!("Command timed out after {:?}", self.timeout)
                } else {
                    format!(
                        "exit code: {:?}\nstdout:\n{}\nstderr:\n{}",
                        result.exit_code, result.stdout, result.stderr
                    )
                }
            }
        }
    }
}
```

- [ ] **Step 2: Write `src/tools/run_command.rs`**

```rust
// src/tools/run_command.rs
use super::RedWrenchServer;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunCommandParams {
    /// The executable to run, e.g. "systemctl". Never a full shell string.
    pub command: String,
    /// Arguments to pass, as separate argv entries, e.g. ["status", "sshd"].
    #[serde(default)]
    pub args: Vec<String>,
}

#[tool_router(router = run_command_router)]
impl RedWrenchServer {
    #[tool(
        description = "Run an arbitrary command on the Fedora host, subject to the \
        active policy tier. Denied commands return an explanation of why, including \
        the active tier name, rather than a generic failure."
    )]
    pub async fn run_command(
        &self,
        Parameters(RunCommandParams { command, args }): Parameters<RunCommandParams>,
    ) -> String {
        self.dispatch("run_command", &command, args).await
    }
}
```

- [ ] **Step 3: Write `src/cli.rs`**

```rust
// src/cli.rs
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "redwrench", about = "MCP server for Fedora hardware and OS control")]
pub struct Cli {
    /// Path to the config file.
    #[arg(long, default_value = "/etc/redwrench/config.toml")]
    pub config: std::path::PathBuf,

    /// Allow binding to a blanket-public address (0.0.0.0 or ::). Dangerous.
    #[arg(long, default_value_t = false)]
    pub allow_public_bind: bool,
}
```

- [ ] **Step 4: Rewrite `src/main.rs`**

```rust
// src/main.rs
mod audit;
mod auth;
mod cli;
mod config;
mod executor;
mod policy;
mod tools;

use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tools::RedWrenchServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    if let Err(err) = audit::init_journal_logging() {
        eprintln!("warning: could not initialise journal logging: {err}");
    }

    let config = config::Config::load(&cli.config)?;
    auth::validate_bind_address(&config.bind_address, cli.allow_public_bind)?;

    let tier_name = format!("{:?}", config.tier).to_lowercase();
    let server = RedWrenchServer {
        policy: Arc::new(policy::PolicyEngine::new(config.effective_rules())),
        timeout: Duration::from_secs(30),
        tier_name,
    };

    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    let http_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        http_config,
    );

    let bearer_token = config.bearer_token.clone();
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn(move |req, next| {
            let token = bearer_token.clone();
            async move { auth::require_bearer_token(token, req, next).await }
        }),
    );

    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    tracing::info!(target: "redwrench::audit", bind_address = %config.bind_address, "redwrench starting");
    axum::serve(listener, router).await?;
    Ok(())
}
```

Note: `RedWrenchServer` derives `Clone` (added in Step 1) because `StreamableHttpService::new` takes a factory closure that must be callable per-session; cloning an `Arc<PolicyEngine>` and a `String` is cheap.

`#[tool_router(router = run_command_router)]` names the generated router explicitly since later tasks add more `impl RedWrenchServer` blocks with their own `#[tool_router]`, and `rmcp` needs distinct router names to merge them, Task 10 shows the merge.

- [ ] **Step 5: Write an integration test for the auth middleware**

```rust
// tests/transport_auth.rs
// This test builds a minimal router using the same auth middleware as
// main.rs, without starting the full MCP service, to confirm the
// bearer token check actually rejects bad requests over real HTTP.
use axum::{routing::get, Router};
use tower::ServiceExt;

#[tokio::test]
async fn rejects_requests_without_a_valid_bearer_token() {
    let token = "expected-token".to_string();
    let app = Router::new().route("/ping", get(|| async { "pong" })).layer(
        axum::middleware::from_fn(move |req, next| {
            let token = token.clone();
            async move { redwrench::auth::require_bearer_token(token, req, next).await }
        }),
    );

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/ping")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}
```

This test requires `auth` to be reachable as `redwrench::auth`, which means `main.rs`'s modules need to also be exposed via a `src/lib.rs` re-exporting them, since integration tests in `tests/` can only see a crate's public library interface, not its binary's private modules. Add this now:

```rust
// src/lib.rs (new file)
pub mod audit;
pub mod auth;
pub mod config;
pub mod executor;
pub mod policy;
pub mod tools;
```

And change `Cargo.toml` to declare both a library and a binary target:

```toml
# Add to Cargo.toml, below [package]
[lib]
name = "redwrench"
path = "src/lib.rs"

[[bin]]
name = "redwrench"
path = "src/main.rs"
```

And change `src/main.rs`'s module declarations from `mod audit;` etc. to `use redwrench::{audit, auth, config, executor, policy, tools};`, since those now live in the library crate.

- [ ] **Step 6: Run everything**

Run: `cargo test`
Expected: all tests from Tasks 2-9 pass. This is the first point in the plan where `cargo test` exercises the whole crate, not just one module, treat any failure here as higher priority than moving to Task 10.

- [ ] **Step 7: Manual smoke test against a real agent**

This isn't automatable in this task (it needs a running server and a real MCP client), but do it now before moving on: create a minimal `/etc/redwrench/config.toml` with a `safe` tier and a real bearer token, run `cargo run -- --config /path/to/config.toml`, and connect to it from Claude Code (`claude mcp add --transport http redwrench http://<bind-address>/mcp`) or Antigravity. Confirm `run_command` with `{"command": "echo", "args": ["hello"]}` returns `hello`, and that a denied command (e.g. `rm`) returns the policy-denial message, not a crash. This becomes UAT Scenario 1 in Task 17, write down what you did so it can be turned into that document.

- [ ] **Step 8: Commit**

```bash
git add src/lib.rs src/main.rs src/cli.rs src/tools/mod.rs src/tools/run_command.rs tests/transport_auth.rs Cargo.toml
git commit -m "Wire up MCP transport, auth middleware, and run_command tool end to end"
```

---

### Task 10: `systemctl_status` and `systemctl_control` tools

**Files:**
- Create: `src/tools/systemctl.rs`
- Modify: `src/tools/mod.rs:1` (add `pub mod systemctl;`)
- Modify: `src/main.rs` (merge the new tool router)

**Interfaces:**
- Consumes: `RedWrenchServer::dispatch` from Task 9.
- Produces: two more MCP tools on `RedWrenchServer`, no new public types.

- [ ] **Step 1: Write `src/tools/systemctl.rs`**

```rust
// src/tools/systemctl.rs
use super::RedWrenchServer;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SystemctlStatusParams {
    /// The unit name to check, e.g. "sshd" or "sshd.service".
    pub unit: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SystemctlControlParams {
    /// One of: start, stop, restart, enable, disable.
    pub action: String,
    /// The unit name to act on, e.g. "sshd" or "sshd.service".
    pub unit: String,
}

#[tool_router(router = systemctl_router)]
impl RedWrenchServer {
    #[tool(description = "Check the status of a systemd unit (read-only, allowed under every tier).")]
    pub async fn systemctl_status(
        &self,
        Parameters(SystemctlStatusParams { unit }): Parameters<SystemctlStatusParams>,
    ) -> String {
        self.dispatch("systemctl_status", "systemctl", vec!["status".into(), unit])
            .await
    }

    #[tool(
        description = "Start, stop, restart, enable, or disable a systemd unit. \
        Requires at least the 'standard' policy tier."
    )]
    pub async fn systemctl_control(
        &self,
        Parameters(SystemctlControlParams { action, unit }): Parameters<SystemctlControlParams>,
    ) -> String {
        self.dispatch("systemctl_control", "systemctl", vec![action, unit])
            .await
    }
}
```

- [ ] **Step 2: Add `pub mod systemctl;` to `src/tools/mod.rs`**

- [ ] **Step 3: Merge the new router in `src/main.rs`**

`rmcp`'s `#[tool_router]` macro on multiple `impl` blocks for the same type generates separate router functions (`run_command_router`, `systemctl_router`); they need combining into one `ServerHandler` implementation. Add this to `src/tools/mod.rs`, below the `RedWrenchServer` struct:

```rust
// src/tools/mod.rs, additional code below the existing dispatch impl
use rmcp::{tool_handler, ServerHandler};

#[tool_handler]
impl ServerHandler for RedWrenchServer {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo {
            server_info: rmcp::model::Implementation {
                name: "redwrench".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            capabilities: rmcp::model::ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
```

`#[tool_handler]` (distinct from `#[tool_router]`) is what actually combines every `#[tool_router]`-annotated `impl` block on the same type into the single `ServerHandler` the transport layer needs, confirm this against the `rmcp` version pinned in `Cargo.toml` when implementing, since multi-router merging is exactly the kind of API detail that can shift between SDK versions, if `#[tool_handler]` doesn't auto-discover both routers, the fallback is combining them explicitly per `rmcp`'s current documented pattern for multiple tool groups on one type.

- [ ] **Step 4: Run the full test suite**

Run: `cargo test`
Expected: all prior tests still pass (this task adds no new automated tests, it's wiring; verification is the manual step below).

- [ ] **Step 5: Manual smoke test**

With the server running against a `standard`-tier config, call `systemctl_status` for a real unit (e.g. `sshd`) and confirm real status output comes back. Call `systemctl_control` with `action: "stop"` against a `safe`-tier config and confirm it's denied with a clear message naming the tier.

- [ ] **Step 6: Commit**

```bash
git add src/tools/systemctl.rs src/tools/mod.rs src/main.rs
git commit -m "Add systemctl_status and systemctl_control tools"
```

---

### Task 11: `dnf_install` and `dnf_remove` tools

**Files:**
- Create: `src/tools/dnf.rs`
- Modify: `src/tools/mod.rs:1` (add `pub mod dnf;`)

**Interfaces:**
- Consumes: `RedWrenchServer::dispatch` from Task 9.

- [ ] **Step 1: Write `src/tools/dnf.rs`**

```rust
// src/tools/dnf.rs
use super::RedWrenchServer;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DnfPackageParams {
    /// The package name, e.g. "htop". Only a single package per call.
    pub package: String,
}

#[tool_router(router = dnf_router)]
impl RedWrenchServer {
    #[tool(
        description = "Install a package via dnf. On immutable Fedora variants, \
        prefer rpm-ostree via run_command instead, dnf itself may not persist \
        changes across a reboot on those systems. Requires the 'standard' tier."
    )]
    pub async fn dnf_install(
        &self,
        Parameters(DnfPackageParams { package }): Parameters<DnfPackageParams>,
    ) -> String {
        self.dispatch(
            "dnf_install",
            "dnf",
            vec!["install".into(), "-y".into(), package],
        )
        .await
    }

    #[tool(description = "Remove a package via dnf. Requires the 'standard' tier.")]
    pub async fn dnf_remove(
        &self,
        Parameters(DnfPackageParams { package }): Parameters<DnfPackageParams>,
    ) -> String {
        self.dispatch(
            "dnf_remove",
            "dnf",
            vec!["remove".into(), "-y".into(), package],
        )
        .await
    }
}
```

- [ ] **Step 2: Add `pub mod dnf;` to `src/tools/mod.rs`**

- [ ] **Step 3: Run the full test suite**

Run: `cargo test`
Expected: no regressions.

- [ ] **Step 4: Manual smoke test**

Against a `standard`-tier config, call `dnf_install` with a small, harmless package (e.g. `htop`) and confirm it actually installs (`rpm -q htop` afterwards). Confirm `dnf_install` is denied under a `safe`-tier config.

- [ ] **Step 5: Commit**

```bash
git add src/tools/dnf.rs src/tools/mod.rs
git commit -m "Add dnf_install and dnf_remove tools"
```

---

### Task 12: `journalctl_tail` tool

**Files:**
- Create: `src/tools/journalctl.rs`
- Modify: `src/tools/mod.rs:1` (add `pub mod journalctl;`)

**Interfaces:**
- Consumes: `RedWrenchServer::dispatch` from Task 9.

- [ ] **Step 1: Write `src/tools/journalctl.rs`**

```rust
// src/tools/journalctl.rs
use super::RedWrenchServer;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JournalctlTailParams {
    /// Optional unit to filter by, e.g. "sshd.service". If omitted, tails
    /// the whole system journal.
    pub unit: Option<String>,
    /// How many of the most recent lines to return. Defaults to 50.
    #[serde(default = "default_lines")]
    pub lines: u32,
}

fn default_lines() -> u32 {
    50
}

#[tool_router(router = journalctl_router)]
impl RedWrenchServer {
    #[tool(
        description = "Return the most recent lines from the systemd journal, \
        optionally filtered to a single unit. This is a one-shot read, it does \
        not follow the log live; live-following is not supported in this \
        version. Allowed under every tier."
    )]
    pub async fn journalctl_tail(
        &self,
        Parameters(JournalctlTailParams { unit, lines }): Parameters<JournalctlTailParams>,
    ) -> String {
        let mut args = vec!["-n".to_string(), lines.to_string(), "--no-pager".to_string()];
        if let Some(unit) = unit {
            args.push("-u".to_string());
            args.push(unit);
        }
        self.dispatch("journalctl_tail", "journalctl", args).await
    }
}
```

- [ ] **Step 2: Add `pub mod journalctl;` to `src/tools/mod.rs`**

- [ ] **Step 3: Run the full test suite**

Run: `cargo test`
Expected: no regressions.

- [ ] **Step 4: Manual smoke test**

Call `journalctl_tail` with no arguments and confirm recent system log lines come back. Call it with `unit: "sshd.service"` and confirm the output is filtered.

- [ ] **Step 5: Commit**

```bash
git add src/tools/journalctl.rs src/tools/mod.rs
git commit -m "Add journalctl_tail tool"
```

---

### Task 13: Network diagnostics tool

**Files:**
- Create: `src/tools/network.rs`
- Modify: `src/tools/mod.rs:1` (add `pub mod network;`)

**Interfaces:**
- Consumes: `RedWrenchServer::dispatch` from Task 9.

- [ ] **Step 1: Write `src/tools/network.rs`**

```rust
// src/tools/network.rs
use super::RedWrenchServer;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PingParams {
    /// Hostname or IP address to ping.
    pub host: String,
    /// Number of echo requests to send. Defaults to 4.
    #[serde(default = "default_count")]
    pub count: u32,
}

fn default_count() -> u32 {
    4
}

#[tool_router(router = network_router)]
impl RedWrenchServer {
    #[tool(description = "Ping a host to check basic network reachability. Allowed under every tier.")]
    pub async fn ping(
        &self,
        Parameters(PingParams { host, count }): Parameters<PingParams>,
    ) -> String {
        self.dispatch("ping", "ping", vec!["-c".into(), count.to_string(), host])
            .await
    }

    #[tool(description = "Show network interface addresses. Allowed under every tier.")]
    pub async fn ip_addr(&self) -> String {
        self.dispatch("ip_addr", "ip", vec!["addr".into()]).await
    }
}
```

- [ ] **Step 2: Add `pub mod network;` to `src/tools/mod.rs`**

- [ ] **Step 3: Run the full test suite**

Run: `cargo test`
Expected: no regressions.

- [ ] **Step 4: Manual smoke test**

Call `ping` against `127.0.0.1` and confirm real ping output. Call `ip_addr` and confirm real interface listing.

- [ ] **Step 5: Commit**

```bash
git add src/tools/network.rs src/tools/mod.rs
git commit -m "Add ping and ip_addr network diagnostic tools"
```

---

### Task 14: `config set-tier` CLI subcommand with the unrestricted warning

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `TierName` (Task 4), `Config` (Task 5).
- Produces: `redwrench config set-tier <tier>` as a real subcommand, separate from running the server.

- [ ] **Step 1: Write the failing test**

```rust
// src/cli.rs, add at the bottom
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_tier_unrestricted_requires_the_risk_flag() {
        let result = Cli::try_parse_from(["redwrench", "config", "set-tier", "unrestricted"]);
        let cli = result.unwrap();
        if let Command::Config(ConfigCommand::SetTier { tier, i_understand_the_risk }) = cli.command {
            assert_eq!(tier, crate::policy::tiers::TierName::Unrestricted);
            assert!(!i_understand_the_risk);
        } else {
            panic!("expected Config(SetTier) command");
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test cli::tests`
Expected: FAIL to compile, `Command`, `ConfigCommand`, and the `config` subcommand don't exist yet.

- [ ] **Step 3: Rewrite `src/cli.rs`**

```rust
// src/cli.rs
use clap::{Parser, Subcommand};
use redwrench::policy::tiers::TierName;

#[derive(Parser, Debug)]
#[command(name = "redwrench", about = "MCP server for Fedora hardware and OS control")]
pub struct Cli {
    /// Path to the config file.
    #[arg(long, default_value = "/etc/redwrench/config.toml", global = true)]
    pub config: std::path::PathBuf,

    /// Allow binding to a blanket-public address (0.0.0.0 or ::). Dangerous.
    #[arg(long, default_value_t = false)]
    pub allow_public_bind: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Manage the active policy configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Set the active policy tier.
    SetTier {
        tier: TierName,
        /// Required to set the 'unrestricted' tier. Read the warning first.
        #[arg(long, default_value_t = false)]
        i_understand_the_risk: bool,
    },
}
```

`TierName` needs `clap::ValueEnum` derived to be usable as a CLI argument. Add it to Task 4's derive list in `src/policy/tiers.rs`:

```rust
// src/policy/tiers.rs, update the derive on TierName
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum TierName {
    Safe,
    Standard,
    Unrestricted,
}
```

Fix the test in Step 1 to match the actual shape (`Cli.command` is `Option<Command>`, and `Command::Config` has a nested `command` field, not a tuple variant), update it to:

```rust
#[test]
fn set_tier_unrestricted_requires_the_risk_flag() {
    let cli = Cli::try_parse_from(["redwrench", "config", "set-tier", "unrestricted"]).unwrap();
    match cli.command {
        Some(Command::Config { command: ConfigCommand::SetTier { tier, i_understand_the_risk } }) => {
            assert_eq!(tier, crate::policy::tiers::TierName::Unrestricted);
            assert!(!i_understand_the_risk);
        }
        _ => panic!("expected Config(SetTier) command"),
    }
}
```

- [ ] **Step 4: Wire the subcommand into `src/main.rs`**

```rust
// src/main.rs, replace the body of main() with a dispatch on cli.command
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        Some(cli::Command::Config { command: cli::ConfigCommand::SetTier { tier, i_understand_the_risk } }) => {
            if matches!(tier, policy::tiers::TierName::Unrestricted) && !i_understand_the_risk {
                eprintln!(
                    "WARNING: the 'unrestricted' tier allows every command with no \
                     filtering, including destructive ones. This is not reversible \
                     by redwrench itself once a destructive command has run. \
                     If you understand this, re-run with --i-understand-the-risk."
                );
                std::process::exit(1);
            }
            update_tier_in_config(&cli.config, &tier)?;
            println!("Active tier set to {tier:?}.");
            Ok(())
        }
        None => run_server(&cli).await,
    }
}

fn update_tier_in_config(path: &std::path::Path, tier: &policy::tiers::TierName) -> anyhow::Result<()> {
    // Minimal implementation: read the existing file as a TOML table,
    // replace the `tier` key, write it back. Using toml::Value here
    // rather than the strict Config/RawConfig structs from Task 5,
    // since this needs to preserve unrelated keys (bearer_token,
    // bind_address, custom_rules) without needing to know their shape.
    let contents = std::fs::read_to_string(path)?;
    let mut value: toml::Value = contents.parse()?;
    let tier_str = match tier {
        policy::tiers::TierName::Safe => "safe",
        policy::tiers::TierName::Standard => "standard",
        policy::tiers::TierName::Unrestricted => "unrestricted",
    };
    value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config file is not a TOML table"))?
        .insert("tier".to_string(), toml::Value::String(tier_str.to_string()));
    std::fs::write(path, toml::to_string_pretty(&value)?)?;
    Ok(())
}

async fn run_server(cli: &cli::Cli) -> anyhow::Result<()> {
    // The body from Task 9's main(), moved into this function unchanged,
    // reading cli.config and cli.allow_public_bind instead of parsing
    // its own Cli.
    if let Err(err) = audit::init_journal_logging() {
        eprintln!("warning: could not initialise journal logging: {err}");
    }

    let config = config::Config::load(&cli.config)?;
    auth::validate_bind_address(&config.bind_address, cli.allow_public_bind)?;

    let tier_name = format!("{:?}", config.tier).to_lowercase();
    let server = tools::RedWrenchServer {
        policy: std::sync::Arc::new(policy::PolicyEngine::new(config.effective_rules())),
        timeout: std::time::Duration::from_secs(30),
        tier_name,
    };

    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    let http_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        http_config,
    );

    let bearer_token = config.bearer_token.clone();
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn(move |req, next| {
            let token = bearer_token.clone();
            async move { auth::require_bearer_token(token, req, next).await }
        }),
    );

    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    tracing::info!(target: "redwrench::audit", bind_address = %config.bind_address, "redwrench starting");
    axum::serve(listener, router).await?;
    Ok(())
}
```

- [ ] **Step 5: Run the full test suite**

Run: `cargo test`
Expected: all tests pass, including the new `cli::tests`.

- [ ] **Step 6: Manual smoke test**

Run `redwrench config set-tier unrestricted` without the flag, confirm it prints the warning and exits non-zero without changing the config file. Run it again with `--i-understand-the-risk`, confirm the config file's `tier` key actually changes and the server picks it up on next start.

- [ ] **Step 7: Commit**

```bash
git add src/cli.rs src/main.rs src/policy/tiers.rs
git commit -m "Add config set-tier subcommand with unrestricted-tier warning gate"
```

---

### Task 15: Man page generation

**Files:**
- Create: `build.rs`
- Modify: `Cargo.toml` (already has `clap_mangen` as a build-dependency from Task 1)

**Interfaces:** none, this is a build-time artifact generator, not runtime code.

- [ ] **Step 1: Write `build.rs`**

```rust
// build.rs
include!("src/cli.rs");

fn main() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let cmd = <Cli as clap::CommandFactory>::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer = Vec::new();
    man.render(&mut buffer).unwrap();
    std::fs::write(out_dir.join("redwrench.1"), buffer).unwrap();
    println!("cargo:rerun-if-changed=src/cli.rs");
}
```

`include!("src/cli.rs")` pulls the CLI definitions into the build script directly rather than depending on the library crate from `build.rs` (Cargo build scripts can't easily depend on their own package's lib target). This does mean `src/cli.rs` must not reference anything outside what's available in that context, it currently only uses `clap` and `redwrench::policy::tiers::TierName`; since `build.rs` can't see the `redwrench` library crate this way, change the `use redwrench::policy::tiers::TierName;` line in `src/cli.rs` to a build-script-safe alternative:

```rust
// src/cli.rs, replace the TierName import
// Was: use redwrench::policy::tiers::TierName;
// The build script (build.rs) includes this file directly and can't
// see the redwrench library crate, so TierName is redeclared locally
// as a build-time-only mirror for the purposes of man page generation.
// The real TierName (src/policy/tiers.rs) still owns Deserialize and
// the actual policy logic; this local copy exists purely so build.rs
// can construct a clap Command without a circular crate dependency.
#[derive(Debug, Clone, PartialEq, clap::ValueEnum)]
pub enum TierName {
    Safe,
    Standard,
    Unrestricted,
}
```

And in `src/main.rs`, where `cli::Command::Config { command: cli::ConfigCommand::SetTier { tier, .. } }` is matched, convert the CLI-local `cli::TierName` to the policy crate's `policy::tiers::TierName` explicitly:

```rust
// src/main.rs, inside the Config/SetTier match arm, before calling update_tier_in_config
let tier = match tier {
    cli::TierName::Safe => policy::tiers::TierName::Safe,
    cli::TierName::Standard => policy::tiers::TierName::Standard,
    cli::TierName::Unrestricted => policy::tiers::TierName::Unrestricted,
};
```

This is a real seam worth flagging rather than hiding: it exists because `build.rs` can't depend on the crate it's building. If this friction becomes annoying in practice, an alternative for a future cleanup is generating man pages via a separate `xtask` binary crate instead of `build.rs`, which can depend on the library normally; that's a reasonable refactor to leave as a backlog item rather than solve now.

Task 14's test now needs updating: `Cli`'s `SetTier` variant holds the local `cli::TierName` mirror introduced above, not `policy::tiers::TierName`, so the assertion must compare against the local type:

```rust
// src/cli.rs, update the test added in Task 14 to match the type introduced in this task
#[test]
fn set_tier_unrestricted_requires_the_risk_flag() {
    let cli = Cli::try_parse_from(["redwrench", "config", "set-tier", "unrestricted"]).unwrap();
    match cli.command {
        Some(Command::Config { command: ConfigCommand::SetTier { tier, i_understand_the_risk } }) => {
            assert_eq!(tier, TierName::Unrestricted); // cli::TierName, not policy::tiers::TierName
            assert!(!i_understand_the_risk);
        }
        _ => panic!("expected Config(SetTier) command"),
    }
}
```

- [ ] **Step 2: Verify it builds and produces a man page**

Run: `cargo build`
Then: `find target -name "redwrench.1"`
Expected: a `redwrench.1` file exists somewhere under `target/`.

Run: `man ./target/debug/build/redwrench-*/out/redwrench.1` (path will vary, use the `find` result)
Expected: a readable man page describing the `redwrench` CLI, its flags, and the `config set-tier` subcommand.

- [ ] **Step 3: Run the full test suite**

Run: `cargo test`
Expected: no regressions.

- [ ] **Step 4: Commit**

```bash
git add build.rs src/cli.rs src/main.rs
git commit -m "Generate man pages from CLI definitions via clap_mangen"
```

---

### Task 16: Contributor documentation

**Files:**
- Create: `CONTRIBUTING.md`
- Create: `AGENTS.md`
- Create: `CLAUDE.md` (symlink to `AGENTS.md`)
- Create: `ARCHITECTURE.md`

**Interfaces:** none, documentation only.

- [ ] **Step 1: Write `ARCHITECTURE.md`**

```markdown
# Architecture

RedWrench is one Rust binary with four layers, described in detail in
the original design spec (`docs/superpowers/specs/2026-09-07-redwrench-design.md`).
This document is the living summary, update it when the architecture
changes; the spec stays frozen as a historical record of the v1.0
decision.

## Layers

1. **Transport** (`src/auth.rs`, wiring in `src/main.rs`): `rmcp` over
   Streamable HTTP via `axum`. Every request passes a bind-address
   safety check at startup and a bearer-token check per-request before
   anything else runs.
2. **Policy** (`src/policy/`): an ordered allow/deny rule list. Three
   built-in tiers (`safe`, `standard`, `unrestricted`) live in
   `src/policy/tiers.rs`. `PolicyEngine::evaluate` is the single
   function every tool call passes through, there is no bypass.
3. **Tools** (`src/tools/`): each file adds MCP tools to the shared
   `RedWrenchServer` type via `#[tool_router]`. Every tool, whatever it
   does, ultimately calls `RedWrenchServer::dispatch`, which is the only
   place that talks to the policy engine and the executor. Adding a new
   tool means adding a new file here and calling `dispatch`, not
   reimplementing policy checks or process spawning.
4. **Execution and audit** (`src/executor.rs`, `src/audit.rs`): the only
   place a process is actually spawned, and the only place a journal
   entry is written. Always argv-based (`tokio::process`), never a
   shell string.

## Adding a new tool

1. Create `src/tools/your_tool.rs`.
2. Define a params struct with `#[derive(Deserialize, schemars::JsonSchema)]`
   and doc comments on every field (these become the descriptions an
   agent sees).
3. Add an `impl RedWrenchServer` block with `#[tool_router(router = your_tool_router)]`
   and one or more `#[tool(description = "...")]` methods that build a
   command and call `self.dispatch(...)`.
4. Add `pub mod your_tool;` to `src/tools/mod.rs`.
5. If the tool should be reachable under `safe` or `standard`, add a
   corresponding rule in `src/policy/tiers.rs`, tools with no matching
   rule are denied by every tier except `unrestricted`.
6. Write a manual smoke test the same way Tasks 10-13 in the
   implementation plan did, and add it to `docs/uat/v1-uat-scenarios.md`.
```

- [ ] **Step 2: Write `CONTRIBUTING.md`**

```markdown
# Contributing to RedWrench

## Before you start

Read `ARCHITECTURE.md` first, it's short and explains the four layers
and where new code belongs.

## Development environment

RedWrench wraps Linux-specific facilities (`systemctl`, `dnf`,
`journalctl`, the systemd journal) that cannot be meaningfully built or
tested on a non-Linux machine. You need access to a real Fedora box to
run `cargo test` or `cargo run` meaningfully; editing on another
machine and running `cargo test` over SSH against that box is a
supported and expected workflow (see `justfile`'s `remote-test`
recipe).

## Testing expectations

- **Any change to `src/policy/`** must include unit tests. This is the
  security-critical core of the project; a policy engine change without
  a test covering the specific behaviour changed will not be merged.
  Include at least one test attempting to construct an argument that
  looks like it could smuggle a second command past a deny rule (see
  the existing tests in `src/policy/mod.rs` for the pattern), and
  confirm it's still denied.
- **Any new tool** (`src/tools/*.rs`) should have its manual smoke test
  documented in `docs/uat/v1-uat-scenarios.md`, in addition to whatever
  automated tests make sense for it.
- Run `cargo test` before opening a PR. CI runs the same suite inside a
  Fedora container.

## Commit style

Small, focused commits. One logical change per commit. Commit messages
describe what changed and, where it's not obvious, why.

## License

By contributing, you agree your contribution is licensed under both
MIT and Apache-2.0, matching the rest of the project (see `LICENSE-MIT`
and `LICENSE-APACHE`).
```

- [ ] **Step 3: Write `AGENTS.md`**

```markdown
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

## Before submitting a change

Run `cargo test`. If you changed `src/policy/`, make sure you added a
test, per `CONTRIBUTING.md`'s testing expectations, this is checked in
review, not just suggested.
```

- [ ] **Step 4: Symlink `CLAUDE.md` to `AGENTS.md`**

Run: `ln -s AGENTS.md CLAUDE.md`
Expected: `CLAUDE.md` is a symlink, not a duplicate file, so the two can never drift out of sync.

- [ ] **Step 5: Commit**

```bash
git add CONTRIBUTING.md AGENTS.md CLAUDE.md ARCHITECTURE.md
git commit -m "Add contributor and agent onboarding documentation"
```

---

### Task 17: UAT documentation

**Files:**
- Create: `docs/uat/v1-uat-scenarios.md`

**Interfaces:** none, documentation only.

- [ ] **Step 1: Write `docs/uat/v1-uat-scenarios.md`**

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add docs/uat/v1-uat-scenarios.md
git commit -m "Add v1.0 UAT scenarios"
```

---

### Task 18: Packaging and CI

**Files:**
- Create: `packaging/redwrench.spec`
- Create: `justfile`
- Create: `.github/workflows/ci.yml`

**Interfaces:** none, build/deployment tooling only.

- [ ] **Step 1: Write `justfile`**

```makefile
# justfile

fedora_host := env_var_or_default("REDWRENCH_FEDORA_HOST", "")

# Sync the working tree to the Fedora box and run the test suite there.
remote-test:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{fedora_host}}" ]; then
        echo "Set REDWRENCH_FEDORA_HOST to the Fedora box's address first." >&2
        exit 1
    fi
    rsync -az --exclude target --exclude .git ./ "{{fedora_host}}:~/redwrench/"
    ssh "{{fedora_host}}" "cd ~/redwrench && cargo test"

# Same as remote-test, but also runs the binary afterwards.
remote-run *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{fedora_host}}" ]; then
        echo "Set REDWRENCH_FEDORA_HOST to the Fedora box's address first." >&2
        exit 1
    fi
    rsync -az --exclude target --exclude .git ./ "{{fedora_host}}:~/redwrench/"
    ssh "{{fedora_host}}" "cd ~/redwrench && cargo run -- {{ARGS}}"
```

- [ ] **Step 2: Write `packaging/redwrench.spec`**

This is a starting point generated by hand following `rust2rpm`'s
conventions, since `rust2rpm` itself needs to be run on a Fedora
machine with the crate already published or vendored, not something to
fabricate output for here. Document that clearly in the file:

```spec
# This spec file follows rust2rpm conventions. Once the crate is ready
# for packaging, regenerate it properly on a Fedora machine with:
#   rust2rpm redwrench
# and reconcile any differences with this hand-written starting point,
# rather than trusting this file as final.

%global crate redwrench

Name:           %{crate}
Version:        0.1.0
Release:        1%{?dist}
Summary:        A security-conscious MCP server for Fedora hardware and OS control

License:        MIT OR Apache-2.0
URL:            https://github.com/simonives/redwrench
Source0:        %{crate}-%{version}.crate

BuildRequires:  rust-packaging >= 21

%description
%{summary}.

%prep
%autosetup -n %{crate}-%{version} -p1

%build
%cargo_build

%install
%cargo_install

%files
%license LICENSE-MIT LICENSE-APACHE
%{_bindir}/%{crate}
%{_mandir}/man1/%{crate}.1*

%changelog
* Sun Sep 07 2026 Simon Ives <redwrench@example.invalid> - 0.1.0-1
- Initial packaging
```

- [ ] **Step 3: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main, dev]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: fedora:latest
    steps:
      - name: Install build dependencies
        run: dnf install -y cargo rust systemd-devel gcc pkgconf-pkg-config

      - uses: actions/checkout@v4

      - name: Run tests
        run: cargo test --workspace

      - name: Check formatting
        run: cargo fmt --check

      - name: Lint
        run: cargo clippy -- -D warnings
```

Running in a `fedora:latest` container is the direct expression of the spec's own testing requirement ("tool handler integration tests against a real, sandboxed/containerised Fedora environment"), not a generic `ubuntu-latest` runner, since this project's whole reason for existing is Fedora-specific behaviour.

- [ ] **Step 4: Commit**

```bash
git add packaging/redwrench.spec justfile .github/workflows/ci.yml
git commit -m "Add RPM spec starting point, dev-loop justfile, and Fedora-container CI"
```

---

## Post-plan note

This plan delivers a working v1.0 per the spec's goals and non-goals.
It does not touch the spec's backlog items (streaming output, sysext
packaging, COPR submission, real-time approval, deeper Tailscale
integration), those remain future work, tracked as GitHub issues once
the repository is pushed, per the spec's own "Backlog / roadmap"
section.
