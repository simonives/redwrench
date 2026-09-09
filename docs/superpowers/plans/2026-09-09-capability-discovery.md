# RedWrench Capability and Policy Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a connected agent discover, from live policy/config state, what RedWrench can do right now, what a higher tier would additionally unlock, and whether a specific command would be allowed, without guessing from denials.

**Architecture:** Add a `description` field to every policy `Rule`; add a small `policy::introspection` module that computes tier-ordering, cross-tier rule diffs, and "which tier would allow this"; expose that through two new MCP tools (`list_capabilities`, `check_command`) always available regardless of tier; reuse the same cross-tier scan to make existing denial messages self-teaching; and expose README.md/ARCHITECTURE.md as MCP resources embedded at compile time.

**Tech Stack:** Rust, `rmcp` 3.2.0 (MCP SDK), `regex`, `serde`/`serde_json`.

**Spec:** `docs/superpowers/specs/2026-09-09-capability-discovery-design.md`

## Global Constraints

- `cargo build`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` must all be clean after every task.
- Per `CONTRIBUTING.md`: any change to `src/policy/` needs tests covering the specific behaviour changed.
- This branch (`add-capability-and-policy-discovery`) was forked from `main` before PR #31 (the #26 journalctl fix) merged. **Before starting Task 1**, run `git fetch origin && git log origin/main --oneline -3` and check whether PR #31 has merged. If it has, rebase this branch onto the latest `main` first (`git rebase origin/main`), since Task 1 rewrites every rule construction in `src/policy/tiers.rs` including the `journalctl` lines PR #31 also touches; rebasing first avoids a large manual merge conflict later. If it has not merged yet, proceed on the current base and flag the eventual merge to the user rather than guessing which version should win.
- No em dashes, no negation-correction ("not X, but Y"), Australian English, in any doc comment, tool description, or documentation file this plan touches (README/ARCHITECTURE untouched, `docs/uat/v1-uat-scenarios.md` additions must comply).
- Do not change what any tier actually allows. This plan only adds description text and introspection; the effective rule sets (before descriptions) must decide identically to how they decide today, for every existing test.

---

### Task 1: Add a description field to `Rule` and describe every existing rule

**Files:**
- Modify: `src/policy/mod.rs`
- Modify: `src/policy/tiers.rs`
- Modify: `src/config.rs`
- Modify: `src/tools/mod.rs` (test helpers only)
- Modify: `src/tools/systemctl.rs` (test helper only)

**Interfaces:**
- Produces: `Rule.description: String` (new field, always populated, never empty), `Effect` gains `PartialEq, serde::Serialize` derives (needed by Task 2's tests and Task 4's JSON output).
- Consumes: nothing from later tasks.

- [ ] **Step 1: Add `description` to `Rule`, and `PartialEq`/`Serialize` to `Effect`, in `src/policy/mod.rs`**

```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub command: String,
    pub arg_pattern: Option<Regex>,
    pub effect: Effect,
    pub description: String,
}
```

- [ ] **Step 2: Update the test-only `rule()` helper in `src/policy/mod.rs`'s test module**

No call sites need to change; the helper hardcodes a description since these are unit tests of the matching engine, not of rule content:

```rust
fn rule(command: &str, arg_pattern: Option<&str>, effect: Effect) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: arg_pattern.map(|p| Regex::new(p).unwrap()),
        effect,
        description: "test rule".to_string(),
    }
}
```

- [ ] **Step 3: Run `cargo build` and confirm it fails**

Expected: compile errors in `src/policy/tiers.rs`, `src/config.rs`, `src/tools/mod.rs`, and `src/tools/systemctl.rs`, every place still constructing a `Rule` without `description`. This is the checklist for the rest of this task: every one of these errors must be resolved by Step 8's build, none suppressed.

- [ ] **Step 4: Update `allow()`/`deny()` and every rule in `src/policy/tiers.rs`**

Replace the two helper functions:

```rust
fn allow(command: &str, arg_pattern: Option<&str>, description: &str) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: arg_pattern.map(|p| Regex::new(p).unwrap()),
        effect: Effect::Allow,
        description: description.to_string(),
    }
}

fn deny(command: &str, arg_pattern: &str, description: &str) -> Rule {
    Rule {
        command: command.to_string(),
        arg_pattern: Some(Regex::new(arg_pattern).unwrap()),
        effect: Effect::Deny,
        description: description.to_string(),
    }
}
```

Replace `safe_rules()`, `standard_rules()`, and `rules_for_tier()`'s `Unrestricted` arm with this exact content (every existing rule, in the same order, each gaining a description; nothing else about these functions changes):

```rust
fn safe_rules() -> Vec<Rule> {
    vec![
        deny(
            "systemctl",
            SYSTEMCTL_HOST_REDIRECT_FLAGS,
            "reject --host/--machine/--root/--image (redirects the operation off the local system)",
        ),
        allow("systemctl", Some("^status"), "read a unit's status"),
        allow(
            "systemctl",
            Some("^is-active"),
            "check whether a unit is active",
        ),
        allow(
            "systemctl",
            Some("^is-enabled"),
            "check whether a unit is enabled at boot",
        ),
        deny(
            "journalctl",
            JOURNALCTL_MUTATION_FLAGS,
            "reject mutation flags (--vacuum-*, --rotate, --flush, --sync, --relinquish-var, --setup-keys, --update-catalog)",
        ),
        allow("journalctl", None, "read the system journal"),
        deny(
            "ping",
            PING_ABUSE_FLAGS,
            "reject flood/zero-interval/adaptive/preload/oversized-packet flags",
        ),
        allow("ping", None, "send ICMP echo requests"),
        allow(
            "ip",
            Some(r"^(addr|route|link)(\s+(show|list|get)(\s.*)?)?$"),
            "read network addresses, routes, or link state",
        ),
        allow(
            "vmstat",
            None,
            "read virtual memory, disk, and CPU statistics",
        ),
        deny(
            "sar",
            SAR_FILE_OUTPUT_FLAG,
            "reject -o (writes raw sample data to an arbitrary path)",
        ),
        allow("sar", None, "read system activity statistics"),
        allow(
            "top",
            Some(r"^-b"),
            "read a one-shot batch-mode process snapshot",
        ),
    ]
}

fn standard_rules() -> Vec<Rule> {
    let mut rules = safe_rules();
    rules.extend(vec![
        allow(
            "systemctl",
            Some("^(start|stop|restart|enable|disable)"),
            "start, stop, restart, enable, or disable a unit",
        ),
        deny(
            "dnf",
            DNF_TRUST_BYPASS_FLAGS,
            "reject --nogpgcheck/--repofrompath/--setopt (bypasses package signature and repository trust)",
        ),
        allow(
            "dnf",
            Some("^(install|remove|upgrade)"),
            "install, remove, or upgrade a package via dnf",
        ),
        allow(
            "rpm-ostree",
            Some("^(install|upgrade|status|uninstall)"),
            "install, upgrade, check status, or uninstall a package via rpm-ostree",
        ),
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
            description: "every command, no restrictions".to_string(),
        }],
    }
}
```

- [ ] **Step 5: Add a display-name helper for `TierName` to `src/policy/tiers.rs`**

Used by Task 4's tools and Task 5's denial message, both need the same lowercase form `main.rs` already builds inline (`format!("{:?}", config.tier).to_lowercase()`):

```rust
pub fn tier_display_name(tier: &TierName) -> String {
    format!("{tier:?}").to_lowercase()
}
```

- [ ] **Step 6: Add a description-coverage test to `src/policy/tiers.rs`'s test module**

```rust
#[test]
fn no_tier_rule_has_an_empty_description() {
    for tier in [TierName::Safe, TierName::Standard, TierName::Unrestricted] {
        for rule in rules_for_tier(&tier) {
            assert!(
                !rule.description.trim().is_empty(),
                "rule for command '{}' under {:?} has an empty description",
                rule.command,
                tier
            );
        }
    }
}
```

- [ ] **Step 7: Update `src/config.rs`'s `RawRule` and `Config::load` to carry a description**

```rust
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    command: String,
    arg_pattern: Option<String>,
    effect: String,
    #[serde(default)]
    description: Option<String>,
}
```

In `Config::load`'s `custom_rules` mapping closure, build the description before moving `r.command` into the `Rule` literal:

```rust
Ok(Rule {
    arg_pattern: r.arg_pattern.map(|p| regex::Regex::new(&p)).transpose()?,
    effect: match r.effect.as_str() {
        "allow" => Effect::Allow,
        "deny" => Effect::Deny,
        other => anyhow::bail!("unknown effect '{other}', expected 'allow' or 'deny'"),
    },
    description: r
        .description
        .clone()
        .unwrap_or_else(|| format!("custom rule for '{}'", r.command)),
    command: r.command,
})
```

(Field-init order in the source doesn't need to match struct declaration order in Rust; `description` is computed from `r.description`/`r.command` before `command: r.command` consumes it.)

- [ ] **Step 8: Add a TOML round-trip test for the new field to `src/config.rs`'s test module**

Follow the existing `effective_rules_prepends_custom_rules_before_tier_defaults`-style test (a `[[custom_rules]]` TOML block, loaded via `Config::load`), adding two cases: one custom rule with an explicit `description = "..."` (asserted to load verbatim), one without it (asserted to load as `"custom rule for '<command>'"`).

- [ ] **Step 9: Fix the two remaining test-helper `Rule { .. }` literals**

`src/tools/mod.rs`'s `allow_all_server` and `src/tools/systemctl.rs`'s inline test literal both currently build:

```rust
Rule {
    command: String::new(),
    arg_pattern: None,
    effect: Effect::Allow,
}
```

Add `description: "allow everything".to_string(),` to both.

- [ ] **Step 10: Run all four cargo gates and commit**

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git add src/policy/mod.rs src/policy/tiers.rs src/config.rs src/tools/mod.rs src/tools/systemctl.rs
git commit -m "feat: add a description field to every policy rule (#23)"
```

---

### Task 2: `policy::introspection` module

**Files:**
- Create: `src/policy/introspection.rs`
- Modify: `src/policy/mod.rs` (add `pub mod introspection;`)

**Interfaces:**
- Consumes: `Rule`, `Effect`, `Decision`, `PolicyEngine` (`src/policy/mod.rs`, Task 1); `TierName`, `rules_for_tier`, `tier_display_name` (`src/policy/tiers.rs`, Task 1).
- Produces: `RuleDescription`, `describe_rules`, `tier_order`, `effective_rules_for`, `additional_rules`, `lowest_tier_that_would_allow`, all `pub` from `crate::policy::introspection`, consumed by Task 4 (tools) and Task 5 (denial message).

- [ ] **Step 1: Add the module declaration**

In `src/policy/mod.rs`, alongside `pub mod tiers;`:

```rust
pub mod introspection;
```

- [ ] **Step 2: Write the failing tests first, in a new `src/policy/introspection.rs`**

```rust
use super::tiers::{rules_for_tier, TierName};
use super::{Decision, Effect, PolicyEngine, Rule};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RuleDescription {
    pub command: String,
    pub effect: Effect,
    pub description: String,
}

pub fn describe_rules(rules: &[Rule]) -> Vec<RuleDescription> {
    rules
        .iter()
        .map(|r| RuleDescription {
            command: r.command.clone(),
            effect: r.effect.clone(),
            description: r.description.clone(),
        })
        .collect()
}

/// Tiers in strictly increasing capability order. Hand-maintained, same as
/// `rules_for_tier`'s match arm: both need updating together when a tier is
/// added (e.g. `Developer`, once PR #28 merges).
pub fn tier_order() -> &'static [TierName] {
    &[TierName::Safe, TierName::Standard, TierName::Unrestricted]
}

/// The full rule set a tier would evaluate against, including custom rules
/// from config (custom rules apply regardless of tier).
pub fn effective_rules_for(tier: &TierName, custom_rules: &[Rule]) -> Vec<Rule> {
    let mut rules = custom_rules.to_vec();
    rules.extend(rules_for_tier(tier));
    rules
}

/// Rules present in `higher`'s effective set whose description does not
/// already appear in `lower`'s.
pub fn additional_rules(lower: &[Rule], higher: &[Rule]) -> Vec<RuleDescription> {
    let lower_descriptions: std::collections::HashSet<&str> =
        lower.iter().map(|r| r.description.as_str()).collect();
    higher
        .iter()
        .filter(|r| !lower_descriptions.contains(r.description.as_str()))
        .map(|r| RuleDescription {
            command: r.command.clone(),
            effect: r.effect.clone(),
            description: r.description.clone(),
        })
        .collect()
}

/// The first (lowest) tier strictly above `from` whose effective rule set
/// (custom rules included) would allow `command`/`args`. `None` means no
/// tier above `from` would allow it either (e.g. a custom `deny` rule
/// blocking the command everywhere, including `unrestricted`).
pub fn lowest_tier_that_would_allow(
    command: &str,
    args: &[String],
    custom_rules: &[Rule],
    from: &TierName,
) -> Option<TierName> {
    let from_index = tier_order().iter().position(|t| t == from)?;
    tier_order()
        .iter()
        .skip(from_index + 1)
        .find(|tier| {
            let engine = PolicyEngine::new(effective_rules_for(tier, custom_rules));
            matches!(engine.evaluate(command, args), Decision::Allowed)
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::tiers::{safe_rules, standard_rules};

    #[test]
    fn tier_order_matches_rules_for_tier_variants() {
        assert_eq!(
            tier_order(),
            &[TierName::Safe, TierName::Standard, TierName::Unrestricted]
        );
    }

    #[test]
    fn effective_rules_for_layers_custom_rules_before_tier_rules() {
        let custom = vec![Rule {
            command: "rm".to_string(),
            arg_pattern: None,
            effect: Effect::Deny,
            description: "custom: never allow rm".to_string(),
        }];
        let rules = effective_rules_for(&TierName::Unrestricted, &custom);
        // The custom deny must be evaluated before unrestricted's
        // catch-all allow, first-match-wins.
        let engine = PolicyEngine::new(rules);
        assert!(matches!(
            engine.evaluate("rm", &["-rf".to_string(), "/".to_string()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn additional_rules_reports_exactly_what_standard_adds_over_safe() {
        let safe = safe_rules();
        let standard = standard_rules();
        let added = additional_rules(&safe, &standard);
        let added_descriptions: std::collections::HashSet<&str> =
            added.iter().map(|r| r.description.as_str()).collect();
        assert_eq!(added.len(), 4);
        assert!(added_descriptions.contains("start, stop, restart, enable, or disable a unit"));
        assert!(added_descriptions.contains(
            "reject --nogpgcheck/--repofrompath/--setopt (bypasses package signature and repository trust)"
        ));
        assert!(added_descriptions.contains("install, remove, or upgrade a package via dnf"));
        assert!(added_descriptions
            .contains("install, upgrade, check status, or uninstall a package via rpm-ostree"));
    }

    #[test]
    fn additional_rules_is_empty_between_identical_rule_sets() {
        let safe = safe_rules();
        assert!(additional_rules(&safe, &safe).is_empty());
    }

    #[test]
    fn lowest_tier_that_would_allow_finds_standard_when_safe_denies() {
        // dnf is not in safe_rules() at all.
        let result = lowest_tier_that_would_allow(
            "dnf",
            &["install".to_string(), "htop".to_string()],
            &[],
            &TierName::Safe,
        );
        assert_eq!(result, Some(TierName::Standard));
    }

    #[test]
    fn lowest_tier_that_would_allow_returns_none_when_a_custom_deny_blocks_every_tier() {
        let custom = vec![Rule {
            command: "rm".to_string(),
            arg_pattern: None,
            effect: Effect::Deny,
            description: "custom: never allow rm".to_string(),
        }];
        let result = lowest_tier_that_would_allow(
            "rm",
            &["-rf".to_string(), "/".to_string()],
            &custom,
            &TierName::Safe,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn lowest_tier_that_would_allow_returns_none_when_already_allowed_at_the_highest_tier() {
        // Nothing is above Unrestricted, so scanning "from" Unrestricted
        // finds no candidate tier regardless of what the command is.
        let result =
            lowest_tier_that_would_allow("anything", &[], &[], &TierName::Unrestricted);
        assert_eq!(result, None);
    }
}
```

- [ ] **Step 3: Run the tests, confirm they pass**

```bash
cargo test --lib policy::introspection
```

Expected: all 7 tests pass (this module has no prior implementation to diverge from, since it and its tests are written together here; if any fails, fix the implementation above, not the test, unless the test itself is wrong per the docstring it's checking).

- [ ] **Step 4: Run all four cargo gates and commit**

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git add src/policy/mod.rs src/policy/introspection.rs
git commit -m "feat: add cross-tier rule introspection module (#23)"
```

---

### Task 3: Give `RedWrenchServer` the tier and custom-rules it needs

**Files:**
- Modify: `src/tools/mod.rs`
- Modify: `src/tools/systemctl.rs` (test call site only)
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `TierName` (`src/policy/tiers.rs`, Task 1); `Rule` (`src/policy/mod.rs`, Task 1).
- Produces: `RedWrenchServer.tier: TierName`, `RedWrenchServer.custom_rules: Arc<Vec<Rule>>`, both new fields; `RedWrenchServer::new`'s signature gains two trailing parameters `tier: TierName, custom_rules: Vec<Rule>`. Task 4 and Task 5 read `self.tier` and `self.custom_rules`.

- [ ] **Step 1: Add the two fields and update the constructor in `src/tools/mod.rs`**

```rust
use crate::policy::tiers::TierName;
use crate::policy::{Decision, PolicyEngine, Rule};
```

(Extends the existing `use crate::policy::{Decision, PolicyEngine};` line with `Rule`, and adds the new `TierName` import.)

```rust
#[derive(Clone)]
pub struct RedWrenchServer {
    pub policy: std::sync::Arc<PolicyEngine>,
    pub timeout: Duration,
    pub max_stream_duration: Duration,
    pub tier_name: String,
    pub tier: TierName,
    pub custom_rules: std::sync::Arc<Vec<Rule>>,
    pub tool_router: ToolRouter<Self>,
}
```

```rust
impl RedWrenchServer {
    pub fn new(
        policy: std::sync::Arc<PolicyEngine>,
        timeout: Duration,
        tier_name: String,
        max_stream_duration: Duration,
        tier: TierName,
        custom_rules: Vec<Rule>,
    ) -> Self {
        Self {
            policy,
            timeout,
            max_stream_duration,
            tier_name,
            tier,
            custom_rules: std::sync::Arc::new(custom_rules),
            tool_router: Self::run_command_router()
                + Self::systemctl_router()
                + Self::dnf_router()
                + Self::journalctl_router()
                + Self::network_router(),
        }
    }
    // ... dispatch() unchanged in this task, see Task 5 ...
}
```

- [ ] **Step 2: Update the two test helpers in `src/tools/mod.rs`'s test module**

```rust
fn allow_all_server(timeout: Duration) -> RedWrenchServer {
    RedWrenchServer::new(
        std::sync::Arc::new(PolicyEngine::new(vec![Rule {
            command: String::new(),
            arg_pattern: None,
            effect: Effect::Allow,
            description: "allow everything".to_string(),
        }])),
        timeout,
        "unrestricted".to_string(),
        Duration::from_secs(1800),
        crate::policy::tiers::TierName::Unrestricted,
        vec![],
    )
}

fn deny_all_server(timeout: Duration) -> RedWrenchServer {
    RedWrenchServer::new(
        std::sync::Arc::new(PolicyEngine::new(vec![])),
        timeout,
        "safe".to_string(),
        Duration::from_secs(1800),
        crate::policy::tiers::TierName::Safe,
        vec![],
    )
}
```

- [ ] **Step 3: Update the test call site in `src/tools/systemctl.rs`**

```rust
let server = RedWrenchServer::new(
    std::sync::Arc::new(PolicyEngine::new(vec![Rule {
        command: String::new(),
        arg_pattern: None,
        effect: Effect::Allow,
        description: "allow everything".to_string(),
    }])),
    Duration::from_secs(5),
    "unrestricted".to_string(),
    Duration::from_secs(1800),
    crate::policy::tiers::TierName::Unrestricted,
    vec![],
);
```

- [ ] **Step 4: Update the real call site in `src/main.rs`**

```rust
let server = RedWrenchServer::new(
    Arc::new(policy::PolicyEngine::new(config.effective_rules())),
    Duration::from_secs(config.timeout_secs),
    tier_name,
    Duration::from_secs(config.max_stream_duration_secs),
    config.tier.clone(),
    config.custom_rules.clone(),
);
```

- [ ] **Step 5: Run all four cargo gates and commit**

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git add src/tools/mod.rs src/tools/systemctl.rs src/main.rs
git commit -m "feat: give RedWrenchServer its active tier and custom rules (#23)"
```

---

### Task 4: `list_capabilities` and `check_command` tools

**Files:**
- Create: `src/tools/introspection.rs`
- Modify: `src/tools/mod.rs` (module declaration, router registration)
- Modify: `Cargo.toml` (promote `serde_json` to a real dependency)
- Modify: `docs/uat/v1-uat-scenarios.md`

**Interfaces:**
- Consumes: `RedWrenchServer.tier`, `RedWrenchServer.custom_rules`, `RedWrenchServer.policy`, `RedWrenchServer.tier_name` (Task 3); `describe_rules`, `effective_rules_for`, `additional_rules`, `tier_order`, `lowest_tier_that_would_allow` (Task 2); `tier_display_name` (Task 1).
- Produces: two new MCP tools, `list_capabilities` and `check_command`, registered in `RedWrenchServer::new`'s merged `tool_router`.

- [ ] **Step 1: Promote `serde_json` to a real dependency in `Cargo.toml`**

Move it out of `[dev-dependencies]` into `[dependencies]` (both tools in this task serialize a real runtime response, not just a test's wire-format assertion):

```toml
[dependencies]
# ... existing entries unchanged ...
serde_json = "1"
```

Remove the now-redundant `[dev-dependencies]` entry and its comment (a regular dependency is already visible to test code, so keeping both is a duplicate):

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Write `src/tools/introspection.rs`**

```rust
use super::RedWrenchServer;
use crate::policy::introspection::{
    additional_rules, describe_rules, effective_rules_for, lowest_tier_that_would_allow,
    tier_order, RuleDescription,
};
use crate::policy::tiers::tier_display_name;
use crate::policy::Decision;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct TierUnlock {
    tier: String,
    additional_capabilities: Vec<RuleDescription>,
}

#[derive(Debug, Serialize)]
struct CapabilitiesResponse {
    active_tier: String,
    current_capabilities: Vec<RuleDescription>,
    unlocked_by_higher_tiers: Vec<TierUnlock>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CheckCommandParams {
    /// The command binary to evaluate, e.g. "journalctl" or "dnf".
    pub command: String,
    /// The arguments that would be passed to `command`, in order.
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CheckCommandResponse {
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    would_be_allowed_at: Option<String>,
}

#[tool_router(router = introspection_router, vis = "pub(crate)")]
impl RedWrenchServer {
    #[tool(
        description = "Describe what this RedWrench instance can do right now: the \
        active policy tier, every command/argument rule it currently evaluates \
        (allow or deny, in plain language), and what each higher tier would \
        additionally unlock. Safe to call at every tier, including 'safe': this \
        only inspects the policy engine's own rule list, it never executes anything."
    )]
    pub async fn list_capabilities(&self) -> CallToolResult {
        let current_rules = effective_rules_for(&self.tier, &self.custom_rules);
        let current_capabilities = describe_rules(&current_rules);

        let from_index = tier_order()
            .iter()
            .position(|t| t == &self.tier)
            .unwrap_or(0);
        let unlocked_by_higher_tiers = tier_order()[from_index + 1..]
            .iter()
            .map(|tier| {
                let higher_rules = effective_rules_for(tier, &self.custom_rules);
                TierUnlock {
                    tier: tier_display_name(tier),
                    additional_capabilities: additional_rules(&current_rules, &higher_rules),
                }
            })
            .collect();

        let response = CapabilitiesResponse {
            active_tier: self.tier_name.clone(),
            current_capabilities,
            unlocked_by_higher_tiers,
        };
        CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&response)
                .expect("CapabilitiesResponse is always serializable"),
        )])
    }

    #[tool(
        description = "Check whether a specific command and arguments would be \
        allowed right now, without running it. Returns the decision, the reason, \
        and (if denied) the lowest tier that would allow it, if any. Safe to call \
        at every tier, including 'safe': this only evaluates the policy engine, \
        it never executes anything."
    )]
    pub async fn check_command(
        &self,
        Parameters(CheckCommandParams { command, args }): Parameters<CheckCommandParams>,
    ) -> CallToolResult {
        let response = match self.policy.evaluate(&command, &args) {
            Decision::Allowed => CheckCommandResponse {
                decision: "allowed".to_string(),
                reason: None,
                would_be_allowed_at: None,
            },
            Decision::Denied(reason) => CheckCommandResponse {
                decision: "denied".to_string(),
                would_be_allowed_at: lowest_tier_that_would_allow(
                    &command,
                    &args,
                    &self.custom_rules,
                    &self.tier,
                )
                .map(|t| tier_display_name(&t)),
                reason: Some(reason),
            },
        };
        CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&response)
                .expect("CheckCommandResponse is always serializable"),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::tiers::{rules_for_tier, TierName};
    use crate::policy::PolicyEngine;
    use std::time::Duration;

    fn server_at(tier: TierName, tier_name: &str) -> RedWrenchServer {
        RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(rules_for_tier(&tier))),
            Duration::from_secs(5),
            tier_name.to_string(),
            Duration::from_secs(1800),
            tier,
            vec![],
        )
    }

    #[tokio::test]
    async fn list_capabilities_reports_the_active_tier_and_a_nonempty_rule_list() {
        let server = server_at(TierName::Safe, "safe");
        let result = server.list_capabilities().await;
        let text = super::super::tests::text_of(&result);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["active_tier"], "safe");
        assert!(parsed["current_capabilities"].as_array().unwrap().len() > 0);
        // Safe is not the highest tier, so it must report at least one
        // tier above it (standard, unrestricted) that would unlock more.
        assert!(parsed["unlocked_by_higher_tiers"]
            .as_array()
            .unwrap()
            .len()
            >= 2);
    }

    #[tokio::test]
    async fn list_capabilities_reports_no_higher_tiers_when_already_unrestricted() {
        let server = server_at(TierName::Unrestricted, "unrestricted");
        let result = server.list_capabilities().await;
        let text = super::super::tests::text_of(&result);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            parsed["unlocked_by_higher_tiers"].as_array().unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn check_command_reports_allowed_with_no_reason_or_suggestion() {
        let server = server_at(TierName::Safe, "safe");
        let result = server
            .check_command(Parameters(CheckCommandParams {
                command: "journalctl".to_string(),
                args: vec![],
            }))
            .await;
        let text = super::super::tests::text_of(&result);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["decision"], "allowed");
        assert!(parsed.get("reason").is_none());
        assert!(parsed.get("would_be_allowed_at").is_none());
    }

    #[tokio::test]
    async fn check_command_reports_denied_with_a_tier_suggestion() {
        let server = server_at(TierName::Safe, "safe");
        let result = server
            .check_command(Parameters(CheckCommandParams {
                command: "dnf".to_string(),
                args: vec!["install".to_string(), "htop".to_string()],
            }))
            .await;
        let text = super::super::tests::text_of(&result);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["decision"], "denied");
        assert!(parsed["reason"].as_str().unwrap().len() > 0);
        assert_eq!(parsed["would_be_allowed_at"], "standard");
    }
}
```

**Note:** `src/tools/mod.rs`'s test module already has a `text_of(&CallToolResult) -> String` helper (it filters `result.content` for `block.as_text()` blocks and joins their `.text`). `pub(crate)` it if it is not already, so `introspection.rs`'s test module can reach it via `super::super::tests::text_of`, rather than reimplementing text extraction here.

- [ ] **Step 3: Wire the new tools into `src/tools/mod.rs`**

Add the module declaration alongside the others:

```rust
pub mod introspection;
```

Add the new router into `RedWrenchServer::new`'s merged `tool_router` (from Task 3's constructor body):

```rust
tool_router: Self::run_command_router()
    + Self::systemctl_router()
    + Self::dnf_router()
    + Self::journalctl_router()
    + Self::network_router()
    + Self::introspection_router(),
```

- [ ] **Step 4: Add UAT scenarios to `docs/uat/v1-uat-scenarios.md`**

Append, following the existing numbering and format (the last scenario currently is 14):

```markdown
## Scenario 15: `list_capabilities` answers "what can you do right now"

1. With `tier = "safe"`, connect an MCP client and call `list_capabilities`
   with no arguments.
2. **Expected:** the response names the active tier (`safe`), lists real
   rules (not a placeholder), and reports what `standard` and
   `unrestricted` would additionally unlock.
3. From the same client, ask a plain-language question like "what can you
   do right now?" and confirm the agent can answer it by calling this
   tool, without needing to guess from a prior denial.

## Scenario 16: `check_command` answers a targeted "would this be allowed" question

1. With `tier = "safe"`, call `check_command` with
   `{"command": "dnf", "args": ["list", "installed"]}`.
2. **Expected:** `decision: "denied"`, a real reason, and
   `would_be_allowed_at: "standard"`.
3. Ask the connected agent "would `dnf list installed` be allowed?" and
   confirm it answers from this tool rather than attempting the real
   command to find out.
```

- [ ] **Step 5: Run all four cargo gates and commit**

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git add src/tools/introspection.rs src/tools/mod.rs Cargo.toml Cargo.lock docs/uat/v1-uat-scenarios.md
git commit -m "feat: add list_capabilities and check_command discovery tools (#23)"
```

---

### Task 5: Self-teaching denial messages

**Files:**
- Modify: `src/tools/mod.rs` (`dispatch()` only)
- Modify: `docs/uat/v1-uat-scenarios.md`

**Interfaces:**
- Consumes: `lowest_tier_that_would_allow` (Task 2); `tier_display_name` (Task 1); `RedWrenchServer.tier`, `.custom_rules` (Task 3).
- Produces: an enhanced denial message text, no new public interface.

- [ ] **Step 1: Update `dispatch()`'s `Decision::Denied` branch**

Current code (inside `pub async fn dispatch`, in the `match self.policy.evaluate(command, &args)` block):

```rust
Decision::Denied(reason) => {
    crate::audit::record_invocation(
        tool,
        command,
        &args,
        &self.tier_name,
        "denied",
        None,
        &request_id,
    );
    CallToolResult::error(vec![ContentBlock::text(format!(
        "Denied: {reason} (active tier: {})",
        self.tier_name
    ))])
}
```

Replace with:

```rust
Decision::Denied(reason) => {
    crate::audit::record_invocation(
        tool,
        command,
        &args,
        &self.tier_name,
        "denied",
        None,
        &request_id,
    );
    let suggestion = crate::policy::introspection::lowest_tier_that_would_allow(
        command,
        &args,
        &self.custom_rules,
        &self.tier,
    )
    .map(|t| {
        format!(
            "; would be allowed at: {}",
            crate::policy::tiers::tier_display_name(&t)
        )
    })
    .unwrap_or_default();
    CallToolResult::error(vec![ContentBlock::text(format!(
        "Denied: {reason} (active tier: {}{suggestion})",
        self.tier_name
    ))])
}
```

- [ ] **Step 2: Add two tests to `src/tools/mod.rs`'s test module**

Follow the existing style of `dispatch_returns_a_structured_error_result_when_the_policy_denies` (read it first for the exact `RedWrenchServer`/context-building pattern this test module already uses), but build the server with a real tier's rules instead of the synthetic `deny_all_server`, so the cross-tier scan has something real to find:

```rust
#[tokio::test]
async fn dispatch_denial_message_names_the_tier_that_would_allow_it() {
    let server = RedWrenchServer::new(
        std::sync::Arc::new(PolicyEngine::new(
            crate::policy::tiers::rules_for_tier(&crate::policy::tiers::TierName::Safe),
        )),
        Duration::from_secs(5),
        "safe".to_string(),
        Duration::from_secs(1800),
        crate::policy::tiers::TierName::Safe,
        vec![],
    );
    let (ctx, _guard) = test_request_context(&server);
    // dnf is not in safe_rules() at all, but standard_rules() adds it.
    let result = server
        .dispatch("dnf_install", "dnf", vec!["install".to_string(), "htop".to_string()], ctx, None)
        .await;
    let text = text_of(&result);
    assert!(text.contains("would be allowed at: standard"), "got: {text}");
}

#[tokio::test]
async fn dispatch_denial_message_has_no_suggestion_when_no_tier_would_allow_it() {
    let custom = vec![Rule {
        command: "dnf".to_string(),
        arg_pattern: None,
        effect: Effect::Deny,
        description: "custom: never allow dnf".to_string(),
    }];
    let mut rules = custom.clone();
    rules.extend(crate::policy::tiers::rules_for_tier(
        &crate::policy::tiers::TierName::Safe,
    ));
    let server = RedWrenchServer::new(
        std::sync::Arc::new(PolicyEngine::new(rules)),
        Duration::from_secs(5),
        "safe".to_string(),
        Duration::from_secs(1800),
        crate::policy::tiers::TierName::Safe,
        custom,
    );
    let (ctx, _guard) = test_request_context(&server);
    let result = server
        .dispatch("dnf_install", "dnf", vec!["install".to_string(), "htop".to_string()], ctx, None)
        .await;
    let text = text_of(&result);
    assert!(!text.contains("would be allowed at"), "got: {text}");
}
```

Both tests use `test_request_context` and `text_of`, the two helpers already defined in this exact test module (confirmed present at `src/tools/mod.rs`'s `pub(crate) mod tests`, lines 267 and 283 respectively as of this plan's writing).

- [ ] **Step 3: Add one UAT scenario to `docs/uat/v1-uat-scenarios.md`**

```markdown
## Scenario 17: a real denial names the tier that would allow it

1. With `tier = "safe"`, call `run_command` with
   `{"command": "dnf", "args": ["install", "htop"]}`.
2. **Expected:** the denial message includes `would be allowed at:
   standard`.
3. Switch to `standard` tier, restart, repeat the same call.
   **Expected:** it succeeds; no denial message to check.
```

- [ ] **Step 4: Run all four cargo gates and commit**

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git add src/tools/mod.rs docs/uat/v1-uat-scenarios.md
git commit -m "feat: make denial messages name a tier that would allow the command (#23)"
```

---

### Task 6: `readme` and `architecture` MCP resources

**Files:**
- Modify: `src/tools/mod.rs` (the `impl ServerHandler for RedWrenchServer` block)
- Modify: `docs/uat/v1-uat-scenarios.md`

**Interfaces:**
- Consumes: nothing from earlier tasks in this plan (independent of Tasks 1-5's policy/tier work).
- Produces: two MCP resources at `redwrench://docs/readme` and `redwrench://docs/architecture`.

- [ ] **Step 1: Replace the empty `ServerHandler` impl in `src/tools/mod.rs`**

Current code:

```rust
#[tool_handler(router = self.tool_router)]
impl ServerHandler for RedWrenchServer {}
```

Replace with (the `#[tool_handler]` macro only auto-generates `get_info()` when the impl block doesn't already define one, so providing it here also requires calling `.enable_tools()` ourselves, the macro no longer does it for us once we override):

```rust
const README: &str = include_str!("../../README.md");
const ARCHITECTURE: &str = include_str!("../../ARCHITECTURE.md");

const README_URI: &str = "redwrench://docs/readme";
const ARCHITECTURE_URI: &str = "redwrench://docs/architecture";

#[tool_handler(router = self.tool_router)]
impl ServerHandler for RedWrenchServer {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo {
            capabilities: rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
            ..Default::default()
        }
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, rmcp::ErrorData> {
        Ok(rmcp::model::ListResourcesResult::with_all_items(vec![
            rmcp::model::Resource::new(README_URI, "readme")
                .with_description(
                    "RedWrench's README: what it is, how to install and configure it, \
                     and its tool catalogue.",
                )
                .with_mime_type("text/markdown"),
            rmcp::model::Resource::new(ARCHITECTURE_URI, "architecture")
                .with_description(
                    "RedWrench's architecture document: the policy engine, executor, \
                     and tier model.",
                )
                .with_mime_type("text/markdown"),
        ]))
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, rmcp::ErrorData> {
        let contents = match request.uri.as_str() {
            README_URI => rmcp::model::ResourceContents::text(README, &request.uri)
                .with_mime_type("text/markdown"),
            ARCHITECTURE_URI => rmcp::model::ResourceContents::text(ARCHITECTURE, &request.uri)
                .with_mime_type("text/markdown"),
            other => {
                return Err(rmcp::ErrorData::resource_not_found(
                    format!("no such resource: {other}"),
                    None,
                ))
            }
        };
        Ok(rmcp::model::ReadResourceResponse::Complete(
            rmcp::model::ReadResourceResult::new(vec![contents]),
        ))
    }
}
```

**Note:** if `async fn` overrides of these trait methods do not satisfy the trait's `impl Future<...> + MaybeSendFuture + '_` return-type bound when you run `cargo build` (this was reasoned through during planning via `MaybeSendFuture`'s blanket `impl<T: Send> MaybeSendFuture for T {}`, which an ordinary `async fn`'s `Send` future satisfies automatically, but was not compiled during planning), fall back to the exact `impl Future<Output = ...> + MaybeSendFuture + '_` signature style the trait declares in `rmcp::handler::server::ServerHandler` (visible in the `rmcp` source under `~/.cargo/registry/src/*/rmcp-3.2.0/src/handler/server.rs`), returning `std::future::ready(Ok(...))`.

- [ ] **Step 2: Add tests confirming the embedded content matches the real files**

In `src/tools/mod.rs`'s test module:

```rust
#[tokio::test]
async fn readme_resource_matches_the_real_file_on_disk() {
    let server = allow_all_server(Duration::from_secs(5));
    let real = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"),
    )
    .unwrap();
    let (ctx, _guard) = test_request_context(&server);
    let response = server
        .read_resource(
            rmcp::model::ReadResourceRequestParams::new(super::README_URI),
            ctx,
        )
        .await
        .unwrap();
    let result = match response {
        rmcp::model::ReadResourceResponse::Complete(r) => r,
        other => panic!("expected a complete response, got {other:?}"),
    };
    match &result.contents[0] {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => {
            assert_eq!(text, &real)
        }
        other => panic!("expected text contents, got {other:?}"),
    }
}

#[tokio::test]
async fn read_resource_rejects_an_unknown_uri() {
    let server = allow_all_server(Duration::from_secs(5));
    let (ctx, _guard) = test_request_context(&server);
    let response = server
        .read_resource(
            rmcp::model::ReadResourceRequestParams::new("redwrench://docs/nonexistent"),
            ctx,
        )
        .await;
    assert!(response.is_err());
}
```

**Note:** confirm the exact name of the test-context helper (referenced above as `test_request_context`) against the real file, same caveat as Task 5.

- [ ] **Step 3: Add one UAT scenario to `docs/uat/v1-uat-scenarios.md`**

```markdown
## Scenario 18: README and ARCHITECTURE are reachable as MCP resources

1. Connect with an MCP client that supports the resources capability
   (e.g. Claude Desktop).
2. List available resources.
   **Expected:** `readme` and `architecture` both appear.
3. Read the `readme` resource.
   **Expected:** the real README content, matching the repository's
   `README.md` at the commit the running binary was built from.
```

- [ ] **Step 4: Run all four cargo gates and commit**

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git add src/tools/mod.rs docs/uat/v1-uat-scenarios.md
git commit -m "feat: expose README and ARCHITECTURE as MCP resources (#23)"
```

---

## Final Review

After Task 6, this plan is complete: `list_capabilities`, `check_command`, self-teaching denials, and the two documentation resources are all implemented and tested, sourced from live policy/config state per the spec's goals. Proceed to the whole-branch final review per `superpowers:subagent-driven-development`, then `superpowers:finishing-a-development-branch`.
