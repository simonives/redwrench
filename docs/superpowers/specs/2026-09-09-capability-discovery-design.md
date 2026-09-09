# RedWrench Capability and Policy Discovery, Design Spec

**Date:** 2026-09-09
**Status:** Approved for implementation planning
**Closes:** simonives/redwrench#23 ("RedWrench needs to be self-describing to a
connected agent"). Related: #22 (a concrete case this gap produced, an
agent had to discover by trial and error that neither `safe` nor `standard`
allow basic hardware-inventory commands).

## Summary

RedWrench's only documentation mechanism today is static, compile-time MCP
tool descriptions. They cannot reflect the active tier, any `custom_rules`
layered on top via `config.toml`, or answer a targeted question about a
specific command. A connected agent's only way to learn what is actually
permitted is trial and error against real denials.

This spec adds two new MCP tools that introspect the live `PolicyEngine`
and `Config` (never the executor, nothing here runs a command), two new
MCP resources exposing the project's real documentation, and a small
enhancement to existing denial messages that reuses the same introspection
machinery. Everything reads real, current state, nothing is a hand-written
doc string that can drift out of sync the way the thing it replaces already
has.

## Goals

- A connected agent can ask "what can you do right now" and get an answer
  sourced from the live active tier plus any `custom_rules`, not a guess
  built from denial messages.
- A connected agent can ask "would `<command> <args>` be allowed, and why"
  without actually running it.
- A connected agent (or human) can ask "what does `standard` unlock that
  `safe` doesn't" and get a real answer derived from the actual rule sets.
- A denial response teaches: when a denied command would be allowed at a
  higher tier, the denial says so.
- README.md and ARCHITECTURE.md are reachable by any MCP client that
  supports the resources capability, not just tool descriptions.

## Non-goals

- **Changing what any tier allows.** This is a discovery/introspection
  feature. It never grants new capability to a caller, it only describes
  capability that already exists.
- **Exposing a way to change the active tier.** Tier changes remain an
  operator/admin action requiring local shell access and a service
  restart (existing standing constraint, restart-required tier changes
  are a deliberate security feature, not a gap this spec touches).
- **A generic "ask anything about RedWrench" natural-language tool.** The
  two new tools answer the two concrete questions the issue names
  precisely; a free-text Q&A layer is a different, much larger feature not
  requested here.
- **Live-reloading documentation from disk at runtime.** See Architecture
  below, the resources are compiled in via `include_str!`, not read from a
  filesystem path at request time.

## Architecture

### Data model change: `Rule` gains a description

`Rule` (`src/policy/mod.rs`) currently has no human-readable text at all,
just `{command, arg_pattern: Option<Regex>, effect}`. Both new tools need
to describe rules in plain language, so `Rule` gains a fourth field:

```rust
pub struct Rule {
    pub command: String,
    pub arg_pattern: Option<Regex>,
    pub effect: Effect,
    pub description: String,
}
```

This touches every existing `allow()`/`deny()` call site in
`src/policy/tiers.rs` (helper functions gain a required `description: &str`
parameter) and `src/config.rs`'s custom-rule construction. `RawRule` gains
an optional `description: Option<String>` TOML field; when the operator
omits it, `Config::load` synthesizes `"custom rule for '<command>'"` so
every rule always has *some* description, never an empty string reaching
an introspection tool's output.

This is mechanical but deliberate: the description field is the actual
fix, not a table alongside it. A separate description table was considered
and rejected, since it is a second source of truth for the exact class of
problem (documentation drifting from reality) this issue exists to close.

### New module: `src/policy/introspection.rs`

Three pieces of shared logic, used by both new tools and the denial-message
enhancement:

```rust
pub struct RuleDescription {
    pub command: String,
    pub effect: Effect,
    pub description: String,
}

/// Human-readable form of a rule list, in evaluation order.
pub fn describe_rules(rules: &[Rule]) -> Vec<RuleDescription>;

/// Tiers in strictly increasing capability order. Hand-maintained, same
/// as `rules_for_tier`'s match arm, both need updating together when a
/// tier is added (e.g. `Developer`, once #28 merges). This is the fixed
/// order every "what would a higher tier unlock" and cross-tier scan
/// question assumes: each tier's `_rules()` function extends the one
/// before it in this list.
pub fn tier_order() -> &'static [TierName];

/// The full rule set a tier would evaluate against, INCLUDING custom
/// rules from config (custom rules apply regardless of tier, they are
/// operator-authored global overrides, so a hypothetical "what would tier
/// X do" question must layer them the same way the real engine does).
pub fn effective_rules_for(tier: &TierName, custom_rules: &[Rule]) -> Vec<Rule> {
    let mut rules = custom_rules.to_vec();
    rules.extend(crate::policy::tiers::rules_for_tier(tier));
    rules
}

/// Rules present in `higher`'s effective set whose description does not
/// already appear in `lower`'s. Powers "what does standard unlock that
/// safe doesn't" and the per-tier breakdown in `list_capabilities`.
pub fn additional_rules(lower: &[Rule], higher: &[Rule]) -> Vec<RuleDescription>;

/// Evaluates `command`/`args` against every tier in `tier_order()` that is
/// strictly above `from`, in order, and returns the first (lowest) tier
/// whose effective rule set (custom rules included) would allow it. `None`
/// means no tier above `from` would allow it either (e.g. a custom `deny`
/// rule blocking the command everywhere, including `unrestricted`).
pub fn lowest_tier_that_would_allow(
    command: &str,
    args: &[String],
    custom_rules: &[Rule],
    from: &TierName,
) -> Option<TierName>;
```

`lowest_tier_that_would_allow` builds a throwaway `PolicyEngine` per
candidate tier via `effective_rules_for` and calls the existing
`PolicyEngine::evaluate`, no policy-matching logic is duplicated.

### New tool: `list_capabilities`

`src/tools/introspection.rs`, no parameters. Reads `RedWrenchServer`'s
existing `policy: Arc<PolicyEngine>` and `tier_name: String` fields (both
already present), plus the config's custom rules (see Task breakdown for
how these reach the tool, `RedWrenchServer` currently does not retain
`custom_rules` separately; this needs a new field populated at
construction, since `PolicyEngine` only exposes matching, not its own
input list back out, see "Open implementation note" below).

Response shape (as MCP tool text content, JSON-formatted for structure):

```json
{
  "active_tier": "standard",
  "current_capabilities": [
    {"command": "systemctl", "effect": "allow", "description": "start, stop, restart, enable, or disable a unit"},
    {"command": "journalctl", "effect": "deny", "description": "reject mutation flags (--vacuum-*, --rotate, --flush, --sync)"}
  ],
  "unlocked_by_higher_tiers": [
    {
      "tier": "unrestricted",
      "additional_capabilities": [
        {"command": "", "effect": "allow", "description": "every command, no restrictions"}
      ]
    }
  ]
}
```

`current_capabilities` is `describe_rules(effective_rules_for(active_tier, custom_rules))`.
`unlocked_by_higher_tiers` iterates `tier_order()` for every tier strictly
above active, each entry's `additional_capabilities` computed via
`additional_rules(active_tier's rules, that tier's rules)`.

This tool is allowed at **every tier including `safe`**, it only
introspects data structures, never touches the executor. It must be added
to `safe_rules()`'s own rule list as a dispatch-level allow (not a
`run_command`-style shell allow, see Open implementation note).

### New tool: `check_command`

`src/tools/introspection.rs`, params `{command: String, args: Vec<String>}`.
Evaluates against the real active `PolicyEngine`, literally
`self.policy.evaluate(&command, &args)`, the exact call `dispatch()` makes,
so the answer this tool gives is never able to diverge from what actually
happens if the caller really ran it. Response:

```json
{"decision": "denied", "reason": "'journalctl -n 50 --no-pager' has no matching allow rule", "would_be_allowed_at": "standard"}
```

`would_be_allowed_at` is present only when the decision is `denied`,
computed via `lowest_tier_that_would_allow`; omitted (or `null`) when
already `allowed`, and omitted when no higher tier would allow it either.

Also allowed at **every tier including `safe`**, same reasoning as
`list_capabilities`: it evaluates, it never executes.

### Denial-message enhancement

`RedWrenchServer::dispatch()`'s existing `Decision::Denied(reason)` branch
(`src/tools/mod.rs`) gains one call to `lowest_tier_that_would_allow`. The
returned text becomes:

```
Denied: 'journalctl -n 50 --no-pager' has no matching allow rule (active tier: safe; would be allowed at: standard)
```

When no higher tier would allow it, the message is unchanged from today
(no "would be allowed at" clause). This reuses `check_command`'s exact
scan, no separate logic path to keep in sync.

### MCP resources: `readme` and `architecture`

Two resources, following whatever resource-registration pattern the pinned
`rmcp` 3.2.0 SDK exposes for static text resources (the implementer's task
should confirm the exact API against `rmcp`'s docs/examples, this was not
verified during design, see Global Constraints in the plan). Content is
embedded via `include_str!("../../README.md")` and
`include_str!("../../ARCHITECTURE.md")` at compile time, not read from a
filesystem path at request time.

**Why compile-time embedding, not a runtime file read:** RedWrench
typically runs as a deployed systemd service; the source checkout is not
guaranteed to sit alongside the running binary in every deployment. A
runtime path read risks a resource that 404s in production, which is a
worse failure mode than staying current only as of the last release (and
it will not even be stale in practice, since a doc change and the code
change it describes ship in the same build). This satisfies the "no drift"
principle at least as well as a runtime read, with no availability risk.

## Open implementation note (for the plan to resolve, not resolved here)

`RedWrenchServer` currently holds `policy: Arc<PolicyEngine>` and
`tier_name: String`, but not the tier's `TierName` enum value or the raw
`custom_rules: Vec<Rule>` list separately, `PolicyEngine` only exposes
`evaluate()`, not its input rules back out. `list_capabilities` and the
cross-tier scan both need: (a) the active `TierName` (not just its string
form) to know where it sits in `tier_order()`, and (b) the `custom_rules`
list on its own, to correctly layer it on top of *other* tiers'
hypothetical rule sets. The implementation plan must decide the concrete
shape: add both as new `RedWrenchServer` fields (`TierName` if `Clone`,
`custom_rules: Arc<Vec<Rule>>`), populated in `RedWrenchServer::new`'s
existing call sites (there are 4, per the developer-tier branch's own
audit of this constructor, grep `RedWrenchServer::new` before starting to
confirm the current count on `main`).

## Testing

Per `CONTRIBUTING.md`: any change to `src/policy/` needs tests covering the
specific behaviour changed.

- **Description field**: the compiler enforces every existing `Rule`
  construction gains a description (missed call sites fail to build,
  nothing silent). A test asserting no rule in any tier's `_rules()`
  output has an empty description string, guarding against a literal
  `""` placeholder slipping through review.
- **`tier_order()` / `effective_rules_for` / `additional_rules`**: unit
  tests confirming the fixed order matches `rules_for_tier`'s current
  variants, and that `additional_rules(safe, standard)` contains exactly
  the rules `standard_rules()` adds beyond `safe_rules()` (this is
  checkable directly against the extends-pattern already visible in
  `standard_rules()`'s source).
- **`lowest_tier_that_would_allow`**: denied-at-safe/allowed-at-standard
  case; denied-at-every-tier case via a custom `deny` rule that blocks a
  command even at `unrestricted` (must return `None`, not panic or
  incorrectly report `unrestricted`).
- **`check_command`**: matches `PolicyEngine::evaluate` output exactly for
  both allow and deny cases (delegation, not reimplementation); the
  `would_be_allowed_at` field's presence/absence in each case.
- **`list_capabilities`**: correct `current_capabilities` for a tier with
  `custom_rules` present (proves the tool reflects config, not just
  compiled-in tier defaults); correct `unlocked_by_higher_tiers` shape
  when active tier is the highest tier (empty list, not an error).
- **`dispatch()` denial-message integration test**: a known-denied command
  under `safe` produces a message containing "would be allowed at:
  standard"; a command denied at every tier (custom deny) produces a
  message with no such clause.
- **Resource tests**: reading each resource returns non-empty content
  matching the real `README.md`/`ARCHITECTURE.md` file content at the
  time of the test run (a content equality assertion against
  `std::fs::read_to_string` of the real file, which will only ever
  diverge from the embedded content if the docs and binary are built from
  different commits, an already-accepted class of build/deploy skew this
  test does not need to solve).

Per the issue's own testing note: this feature's entire purpose is being
read by a human or agent, not just passing unit tests. Add UAT scenarios
to `docs/uat/v1-uat-scenarios.md`: (1) ask a connected agent "what can you
do right now" and confirm it can answer from `list_capabilities` without
guessing; (2) ask "would `dnf list installed` be allowed?" and confirm
`check_command` gives a real answer without the agent needing to try it;
(3) trigger a real denial at `safe` tier for something `standard` allows
and confirm the denial message itself now says so; (4) confirm a client
with resources support can read the readme resource (whatever URI scheme
the implementation settles on) and get real README content.
