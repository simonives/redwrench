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
3. Add an `impl RedWrenchServer` block with
   `#[tool_router(router = your_tool_router, vis = "pub(crate)")]` and
   one or more `#[tool(description = "...")]` methods that build a
   command and call `self.dispatch(...)`. The `vis = "pub(crate)"` is
   required against the pinned rmcp 3.2.0 API, every tool-handler file
   in this codebase (`dnf.rs`, `journalctl.rs`, `network.rs`,
   `systemctl.rs`) uses it; omitting it does not compile.
4. Add `pub mod your_tool;` to `src/tools/mod.rs`.
5. If the tool should be reachable under `safe` or `standard`, add a
   corresponding rule in `src/policy/tiers.rs`, tools with no matching
   rule are denied by every tier except `unrestricted`.
6. Write a manual smoke test the same way Tasks 10-13 in the
   implementation plan did, and add it to `docs/uat/v1-uat-scenarios.md`.
