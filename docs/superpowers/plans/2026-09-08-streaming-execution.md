# Streaming Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let RedWrench stream a running command's output live to the calling agent, let the agent cancel a command mid-flight, and let commands with no natural end (indefinite `ping`, `journalctl -f`) run under a server-enforced safety-net duration instead of relying on the caller to eventually stop them.

**Architecture:** `executor::execute()` gains an optional chunk sink and a cancellation token, both layered onto its existing timeout-based `tokio::select!`. `dispatch()` extracts each request's `RequestContext` (which `rmcp` already populates with a per-request `CancellationToken` and a `Peer` handle) and wires them through, forwarding output chunks as MCP `notifications/progress` messages only when the caller attached a progress token. No tool file needs to know or care whether a given caller wants streaming.

**Tech Stack:** Rust, `rmcp` 3.2.0 (already pinned), `tokio`, `tokio-util` (new dependency, for `CancellationToken`, already a transitive dependency of `rmcp` so this adds no new supply-chain surface).

**Spec:** `docs/superpowers/specs/2026-09-08-streaming-execution-design.md`

## Global Constraints

- Any caller that does **not** attach a progress token to a `tools/call` request must see byte-identical behaviour to today: one buffered result, once. This is the plan's most important regression guard.
- Cancellation kills the child process via the executor's existing `kill_on_drop`/explicit `.kill()` path, the same as a timeout. It must never leave the process running.
- `timeout_secs` (existing, default 30s) keeps its current meaning for ordinary calls. A new `max_stream_duration_secs` (default 1800s / 30 minutes) is the absolute ceiling for calls that opt into indefinite execution, enforced by the server regardless of client behaviour.
- Tier gating does not change for duration. `ping` and `journalctl` stay read-only regardless of how long they run; only the safety-net duration bounds resource cost.
- No job/polling abstraction, no dedicated resource-monitoring tool file. `run_command` plus new `safe`-tier allow-rules covers monitoring binaries.
- A streaming/indefinite call gets a "started" audit entry in addition to today's completion entry, so an operator has a record of it before it eventually ends.

---

## File Structure

```
redwrench/
├── Cargo.toml                    (add tokio-util dependency)
├── src/
│   ├── audit.rs                  (add record_start)
│   ├── config.rs                 (add max_stream_duration_secs)
│   ├── executor.rs                (add streaming + cancellation to execute())
│   ├── main.rs                   (thread max_stream_duration into RedWrenchServer::new)
│   ├── policy/
│   │   └── tiers.rs               (add safe-tier monitoring allow-rules)
│   └── tools/
│       ├── mod.rs                 (RedWrenchServer gains max_stream_duration field;
│       │                           dispatch() gains RequestContext + duration-override
│       │                           params, wires streaming/cancellation)
│       ├── run_command.rs         (thread ctx through, no behaviour change)
│       ├── systemctl.rs           (thread ctx through, no behaviour change)
│       ├── dnf.rs                 (thread ctx through, no behaviour change)
│       ├── network.rs             (ping gains optional count -> indefinite mode;
│       │                           ip_addr threads ctx through)
│       └── journalctl.rs          (journalctl_tail gains follow: bool)
├── ARCHITECTURE.md                (document the streaming/cancellation contract)
├── AGENTS.md                      (add a fourth rule: don't build bespoke
│                                    timeout/streaming logic in a tool file)
└── docs/uat/v1-uat-scenarios.md   (new scenarios for streaming/cancellation/
                                     indefinite ping/journalctl follow)
```

Rationale: `executor.rs` stays the only place that spawns a process and now the
only place that owns "how a running process's lifecycle ends" (exit,
safety-net timeout, or cancellation). It deliberately has no `rmcp`
dependency, it works with plain channels and tokens, so `dispatch()` (which
does depend on `rmcp`) is the seam that connects the two. This mirrors the
existing layering: `executor.rs` doesn't know about MCP, `tools/mod.rs`'s
`dispatch()` is the only place that does.

---

### Task 1: Executor gains streaming output and cancellation

**Files:**
- Modify: `src/executor.rs`

**Interfaces:**
- Produces:
  - `pub type ChunkSink = tokio::sync::mpsc::UnboundedSender<String>`
  - `pub async fn execute(command: &str, args: &[String], timeout: std::time::Duration, cancellation: Option<tokio_util::sync::CancellationToken>, chunk_sink: Option<ChunkSink>) -> ExecutionResult` (signature change: two new trailing parameters)
  - `ExecutionResult` gains `pub cancelled: bool` (alongside the existing `timed_out: bool`), so callers can distinguish "the safety net elapsed" from "the caller cancelled it" for audit purposes.

This task is entirely self-contained and independently testable: no other
file changes are needed to write and pass these tests, since `execute()`'s
new parameters are both `Option`, existing call sites (which don't exist
yet with the new signature, since Task 3 updates the one call site) don't
need to change here.

- [ ] **Step 1: Write the failing tests**

Add to `src/executor.rs`'s existing `#[cfg(test)] mod tests` block:

```rust
#[tokio::test]
async fn each_output_chunk_is_forwarded_to_the_sink_as_it_arrives() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let result = execute(
        "echo",
        &["hello".to_string()],
        Duration::from_secs(5),
        None,
        Some(tx),
    )
    .await;
    assert_eq!(result.exit_code, Some(0));
    assert!(!result.cancelled);

    let mut forwarded = String::new();
    while let Ok(chunk) = rx.try_recv() {
        forwarded.push_str(&chunk);
    }
    assert!(
        forwarded.contains("hello"),
        "expected forwarded output to contain 'hello', got: {forwarded:?}"
    );
}

#[tokio::test]
async fn no_sink_means_no_behavioural_change_from_the_buffered_path() {
    // Regression guard: a caller that doesn't opt into streaming must see
    // exactly today's behaviour, nothing sent anywhere, one buffered result.
    let result = execute(
        "echo",
        &["hello".to_string()],
        Duration::from_secs(5),
        None,
        None,
    )
    .await;
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout.trim(), "hello");
    assert!(!result.cancelled);
    assert!(!result.timed_out);
}

#[tokio::test]
async fn cancellation_kills_the_process_and_marks_the_result_cancelled() {
    let cancellation = tokio_util::sync::CancellationToken::new();
    let ct = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        ct.cancel();
    });

    let started = std::time::Instant::now();
    let result = execute(
        "sleep",
        &["30".to_string()],
        Duration::from_secs(60),
        Some(cancellation),
        None,
    )
    .await;

    assert!(
        started.elapsed() < Duration::from_secs(5),
        "expected cancellation to end the call quickly, took {:?}",
        started.elapsed()
    );
    assert!(result.cancelled);
    assert!(!result.timed_out);
    assert_eq!(result.exit_code, None);
}

#[tokio::test]
async fn an_uncancelled_indefinite_command_is_still_bounded_by_the_timeout() {
    // The existing timeout still applies even when a cancellation token is
    // supplied but never fires: the safety net is not optional.
    let cancellation = tokio_util::sync::CancellationToken::new();
    let result = execute(
        "sleep",
        &["30".to_string()],
        Duration::from_millis(100),
        Some(cancellation),
        None,
    )
    .await;
    assert!(result.timed_out);
    assert!(!result.cancelled);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib executor::tests`
Expected: FAIL to compile, `execute` doesn't accept 5 arguments yet, `ExecutionResult` has no `cancelled` field, `ChunkSink` doesn't exist.

- [ ] **Step 3: Add `tokio-util` as a dependency**

```toml
# Cargo.toml, in [dependencies], alongside the existing tokio line
tokio-util = { version = "0.7", features = ["rt"] }
```

`tokio-util` is already pulled in transitively by `rmcp` (it depends on
`CancellationToken` internally, confirmed by reading `rmcp`'s own source
at `~/.cargo/registry/src/*/rmcp-3.2.0/src/service.rs`), so this adds no
new supply-chain surface, only a direct dependency on something already
in the tree.

- [ ] **Step 4: Rewrite `execute()`**

Replace the existing `execute()` function (and add `cancelled` to
`ExecutionResult`) with:

```rust
// src/executor.rs, replace the ExecutionResult struct and execute() function
#[derive(Debug)]
pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub cancelled: bool,
}

/// A channel for forwarding output chunks as they arrive, used to power
/// live streaming via MCP progress notifications. `dispatch()` (the only
/// caller that knows about `rmcp`) owns the receiving end; this module
/// stays free of any MCP-specific types, the same separation `dispatch()`
/// already draws between "run a process" (this file) and "speak MCP"
/// (`tools/mod.rs`).
pub type ChunkSink = tokio::sync::mpsc::UnboundedSender<String>;

pub async fn execute(
    command: &str,
    args: &[String],
    timeout: Duration,
    cancellation: Option<tokio_util::sync::CancellationToken>,
    chunk_sink: Option<ChunkSink>,
) -> ExecutionResult {
    let mut child = match Command::new(command)
        .args(args)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
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

    let stdout = child.stdout.take().expect("stdout not configured as piped");
    let stderr = child.stderr.take().expect("stderr not configured as piped");

    // Drain both pipes concurrently, forwarding each chunk to chunk_sink as
    // it arrives (if present) while still accumulating into a bounded
    // buffer for the eventual result, same truncation guarantee as before.
    // Reads stay bounded via `.take()` regardless of whether streaming is
    // active, a firehose command cannot exhaust memory either way.
    let stdout_sink = chunk_sink.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut reader = stdout.take(READ_LIMIT_BYTES);
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(sink) = &stdout_sink {
                        let _ = sink.send(String::from_utf8_lossy(&chunk[..n]).into_owned());
                    }
                }
                Err(_) => break,
            }
        }
        buf
    });
    let stderr_sink = chunk_sink;
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut reader = stderr.take(READ_LIMIT_BYTES);
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(sink) = &stderr_sink {
                        let _ = sink.send(String::from_utf8_lossy(&chunk[..n]).into_owned());
                    }
                }
                Err(_) => break,
            }
        }
        buf
    });

    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    let cancelled_fut = async {
        match &cancellation {
            Some(token) => token.cancelled().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(cancelled_fut);

    tokio::select! {
        status = child.wait() => {
            let stdout_data = tokio::time::timeout(POST_EXIT_READ_TIMEOUT, stdout_task)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default();
            let stderr_data = tokio::time::timeout(POST_EXIT_READ_TIMEOUT, stderr_task)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default();
            match status {
                Ok(status) => ExecutionResult {
                    exit_code: status.code(),
                    stdout: truncate_output(stdout_data),
                    stderr: truncate_output(stderr_data),
                    timed_out: false,
                    cancelled: false,
                },
                Err(err) => ExecutionResult {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: format!("command failed: {err}"),
                    timed_out: false,
                    cancelled: false,
                },
            }
        },
        _ = &mut sleep => {
            let _ = child.kill().await;
            stdout_task.abort();
            stderr_task.abort();
            ExecutionResult {
                exit_code: None,
                stdout: String::new(),
                stderr: format!("command timed out after {timeout:?}"),
                timed_out: true,
                cancelled: false,
            }
        },
        _ = &mut cancelled_fut => {
            let _ = child.kill().await;
            stdout_task.abort();
            stderr_task.abort();
            ExecutionResult {
                exit_code: None,
                stdout: String::new(),
                stderr: "command cancelled by caller".to_string(),
                timed_out: false,
                cancelled: true,
            }
        }
    }
}
```

Note the existing `truncate_output` function, `MAX_OUTPUT_BYTES`,
`POST_EXIT_READ_TIMEOUT`, and `READ_LIMIT_BYTES` constants stay exactly
as they are (confirmed present under those exact names in the current
file), this rewrite only touches `ExecutionResult` and `execute()`, and
reuses `READ_LIMIT_BYTES` rather than redefining it. `AsyncReadExt`
(already imported at the top of the file) provides both `.take()` and
`.read()`; the plain `.read()` method (not `.read_to_end()`) is needed
here since chunks must be forwarded as they arrive rather than
accumulated silently until EOF. `.take()` consumes its receiver by
value (`fn take(self, limit: u64) -> Take<Self>`), so the outer
`stdout`/`stderr` bindings stay non-`mut` exactly as they are today,
only the `reader` produced by `.take()` and the accumulating `buf` need
`mut`, since they're the ones actually mutated in the read loop.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib executor::tests`
Expected: all executor tests pass, including the 4 new ones and the
existing ones (their call sites need the two new trailing `None, None`
arguments added, update them now: `captures_stdout_and_exit_code_of_a_successful_command`,
`captures_stderr_and_nonzero_exit_code_of_a_failing_command`,
`a_shell_metacharacter_in_an_argument_is_never_interpreted`,
`a_command_exceeding_the_timeout_is_killed_and_marked_timed_out`,
`very_large_output_is_truncated_with_a_note`,
`the_read_itself_is_bounded_so_a_firehose_command_cannot_exhaust_memory`,
`a_grandchild_holding_the_pipe_open_cannot_hang_execute`, each existing
call becomes `execute(command, args, timeout, None, None)`).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/executor.rs
git commit -m "Add streaming output and cancellation support to the executor"
```

---

### Task 2: Config gains a safety-net duration for streaming calls

**Files:**
- Modify: `src/config.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `pub const DEFAULT_MAX_STREAM_DURATION_SECS: u64 = 1800;`
  - `Config.max_stream_duration_secs: u64` (new public field, already-defaulted)

- [ ] **Step 1: Write the failing tests**

Add to `src/config.rs`'s existing `#[cfg(test)] mod tests` block (follow
the exact pattern of the existing `timeout_secs_defaults_to_30_when_absent`
and `timeout_secs_is_read_from_the_config_when_present` tests):

```rust
#[test]
fn max_stream_duration_secs_defaults_to_1800_when_absent() {
    let file = write_temp_config(
        r#"
        bind_address = "100.64.0.1:8443"
        bearer_token = "test-token"
        tier = "safe"
        "#,
    );
    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.max_stream_duration_secs, DEFAULT_MAX_STREAM_DURATION_SECS);
    assert_eq!(config.max_stream_duration_secs, 1800);
}

#[test]
fn max_stream_duration_secs_is_read_from_the_config_when_present() {
    let file = write_temp_config(
        r#"
        bind_address = "100.64.0.1:8443"
        bearer_token = "test-token"
        tier = "safe"
        max_stream_duration_secs = 300
        "#,
    );
    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.max_stream_duration_secs, 300);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib config::tests`
Expected: FAIL to compile, `max_stream_duration_secs` doesn't exist on `Config`.

- [ ] **Step 3: Add the field**

```rust
// src/config.rs, alongside the existing DEFAULT_TIMEOUT_SECS constant
/// Default safety-net ceiling, in seconds, for a call using streaming or
/// indefinite execution (e.g. `journalctl_tail` with `follow: true`, or
/// `ping` with no `count`). Applies regardless of whether the caller ever
/// cancels; a client that disconnects without cancelling must not be able
/// to keep a process running forever.
pub const DEFAULT_MAX_STREAM_DURATION_SECS: u64 = 1800;
```

Add to `RawConfig` (alongside the existing `timeout_secs` field):

```rust
    /// Safety-net maximum duration, in seconds, for streaming/indefinite
    /// calls. Optional; defaults to [`DEFAULT_MAX_STREAM_DURATION_SECS`].
    #[serde(default)]
    max_stream_duration_secs: Option<u64>,
```

Add to `Config` (alongside the existing `timeout_secs` field):

```rust
    /// Resolved safety-net duration in seconds, already defaulted.
    pub max_stream_duration_secs: u64,
```

Add to `Config::load`'s final `Ok(Config { ... })` construction (alongside
the existing `timeout_secs: raw.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),`
line):

```rust
            max_stream_duration_secs: raw
                .max_stream_duration_secs
                .unwrap_or(DEFAULT_MAX_STREAM_DURATION_SECS),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib config::tests`
Expected: all config tests pass, including the 2 new ones.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "Add max_stream_duration_secs as the safety net for streaming calls"
```

---

### Task 3: `dispatch()` wires cancellation and streaming through `RequestContext`

**Files:**
- Modify: `src/audit.rs`
- Modify: `src/tools/mod.rs`

**Interfaces:**
- Consumes: `execute()`'s new signature (Task 1), `Config.max_stream_duration_secs` (Task 2).
- Produces:
  - `pub fn record_start(tool: &str, command: &str, args: &[String], tier: &str)` (new, in `audit.rs`)
  - `RedWrenchServer` gains `pub max_stream_duration: std::time::Duration` field.
  - `RedWrenchServer::new(policy, timeout, tier_name, max_stream_duration) -> Self` (signature change: one new trailing parameter)
  - `RedWrenchServer::dispatch(&self, tool: &str, command: &str, args: Vec<String>, ctx: rmcp::service::RequestContext<rmcp::RoleServer>, max_duration_override: Option<std::time::Duration>) -> CallToolResult` (signature change: two new trailing parameters)

This is the task most likely to need adaptation against the pinned `rmcp`
API, in exactly the same way Task 9 of the original v1.0 plan needed
adaptation for the tool router pattern. The extractor mechanism below
(`RequestContext<RoleServer>` as a plain extra parameter on a `#[tool]`
method) is confirmed present in the SDK's own source
(`rmcp::handler::server::common::FromContextPart` is implemented for
`RequestContext<RoleServer>`, `tokio_util::sync::CancellationToken`, and
`Peer<RoleServer>`), but this task's own tool methods aren't touched until
Task 4, so verify the extractor pattern compiles here first, on
`dispatch()`'s test fixtures, before Task 4 threads it through every tool
file. If the exact macro syntax for combining `Parameters<T>` with a
second extractor differs from what's shown here, adapt to the real
compiler error and note the adaptation in your task report, the same way
Task 9's report documented its own three `rmcp` adaptations.

- [ ] **Step 1: Write the failing tests**

`dispatch()`'s three existing tests need a real `RequestContext` fixture.
Add a helper and update the existing tests in `src/tools/mod.rs`'s
`#[cfg(test)] mod tests` block:

```rust
// src/tools/mod.rs, inside #[cfg(test)] mod tests, add this helper
fn test_request_context() -> rmcp::service::RequestContext<rmcp::RoleServer> {
    use std::sync::Arc;
    let id_provider: Arc<dyn rmcp::service::RequestIdProvider> =
        Arc::new(rmcp::service::AtomicU32RequestIdProvider::default());
    let (peer, _rx) = rmcp::service::Peer::<rmcp::RoleServer>::new(id_provider, None);
    rmcp::service::RequestContext::new(rmcp::model::NumberOrString::Number(1), peer)
}
```

Update the three existing tests' `dispatch(...)` calls to pass the two new
arguments, e.g.:

```rust
    #[tokio::test]
    async fn dispatch_returns_a_structured_error_result_when_the_policy_denies() {
        let server = deny_all_server(Duration::from_secs(5));
        let result = server
            .dispatch(
                "run_command",
                "rm",
                vec!["-rf".to_string(), "/".to_string()],
                test_request_context(),
                None,
            )
            .await;

        assert_eq!(result.is_error, Some(true));
        let text = text_of(&result);
        assert!(text.starts_with("Denied:"), "unexpected text: {text}");
        assert!(
            text.contains("active tier: safe"),
            "unexpected text: {text}"
        );
    }
```

(apply the same two-argument addition to
`dispatch_returns_a_successful_result_with_real_output_when_the_policy_allows`
and `dispatch_reports_a_timeout_as_a_structured_error_result`)

Update `allow_all_server`/`deny_all_server` to also take and store a
`max_stream_duration`, or hardcode a generous value in
`RedWrenchServer::new`'s test call sites, e.g.:

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
        )
    }

    fn deny_all_server(timeout: Duration) -> RedWrenchServer {
        RedWrenchServer::new(
            std::sync::Arc::new(PolicyEngine::new(vec![])),
            timeout,
            "safe".to_string(),
            Duration::from_secs(1800),
        )
    }
```

Add two new tests proving the new behaviour:

```rust
    #[tokio::test]
    async fn dispatch_reports_cancellation_as_a_structured_error_result() {
        let server = allow_all_server(Duration::from_secs(60));
        let ctx = test_request_context();
        ctx.ct.cancel();
        let result = server
            .dispatch("run_command", "sleep", vec!["30".to_string()], ctx, None)
            .await;

        assert_eq!(result.is_error, Some(true));
        let text = text_of(&result);
        assert!(text.contains("cancelled"), "unexpected text: {text}");
    }

    #[tokio::test]
    async fn a_duration_override_is_used_instead_of_the_default_timeout() {
        // A short default timeout would normally kill this in 100ms; the
        // override lets a streaming/follow call run for up to 5s instead.
        let server = allow_all_server(Duration::from_millis(100));
        let result = server
            .dispatch(
                "ping",
                "sleep",
                vec!["1".to_string()],
                test_request_context(),
                Some(Duration::from_secs(5)),
            )
            .await;
        assert_eq!(result.is_error, Some(false));
        assert!(!text_of(&result).is_empty());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib tools::tests`
Expected: FAIL to compile, `dispatch()` and `RedWrenchServer::new()` don't
accept the new arguments yet.

- [ ] **Step 3: Add `record_start` to `audit.rs`**

```rust
// src/audit.rs, alongside record_invocation
/// Writes an audit entry when a streaming or indefinite call begins.
///
/// A call using streaming or the safety-net duration (rather than the
/// ordinary default timeout) may run for a long time before
/// `record_invocation` ever logs its completion. Without a "started"
/// entry, an operator has no record such a call was even in flight until
/// it eventually ends, possibly tens of minutes later.
pub fn record_start(tool: &str, command: &str, args: &[String], tier: &str) {
    tracing::info!(
        target: "redwrench::audit",
        tool,
        command,
        args = %args.join(" "),
        tier,
        "streaming invocation started"
    );
}
```

- [ ] **Step 4: Update `RedWrenchServer` and `dispatch()`**

```rust
// src/tools/mod.rs, replace the RedWrenchServer struct definition
#[derive(Clone)]
pub struct RedWrenchServer {
    pub policy: std::sync::Arc<PolicyEngine>,
    pub timeout: Duration,
    pub max_stream_duration: Duration,
    pub tier_name: String,
    pub tool_router: ToolRouter<Self>,
}
```

```rust
// src/tools/mod.rs, replace RedWrenchServer::new
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

```rust
// src/tools/mod.rs, replace the dispatch() method
    pub async fn dispatch(
        &self,
        tool: &str,
        command: &str,
        args: Vec<String>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
        max_duration_override: Option<Duration>,
    ) -> CallToolResult {
        match self.policy.evaluate(command, &args) {
            Decision::Denied(reason) => {
                crate::audit::record_invocation(
                    tool,
                    command,
                    &args,
                    &self.tier_name,
                    "denied",
                    None,
                );
                CallToolResult::error(vec![ContentBlock::text(format!(
                    "Denied: {reason} (active tier: {})",
                    self.tier_name
                ))])
            }
            Decision::Allowed => {
                let effective_timeout = max_duration_override.unwrap_or(self.timeout);
                let is_streaming_call = max_duration_override.is_some();
                if is_streaming_call {
                    crate::audit::record_start(tool, command, &args, &self.tier_name);
                }

                let progress_token = ctx.meta.get_progress_token();
                let chunk_sink = progress_token.as_ref().map(|token| {
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
                    let peer = ctx.peer.clone();
                    let token = token.clone();
                    let mut progress_count: f64 = 0.0;
                    tokio::spawn(async move {
                        while let Some(chunk) = rx.recv().await {
                            progress_count += 1.0;
                            let notification = rmcp::model::ProgressNotification::new(
                                rmcp::model::ProgressNotificationParam {
                                    progress_token: token.clone(),
                                    progress: progress_count,
                                    total: None,
                                    message: Some(chunk),
                                },
                            );
                            let _ = peer.send_notification(notification.into()).await;
                        }
                    });
                    tx
                });

                let result = crate::executor::execute(
                    command,
                    &args,
                    effective_timeout,
                    Some(ctx.ct.clone()),
                    chunk_sink,
                )
                .await;
                crate::audit::record_invocation(
                    tool,
                    command,
                    &args,
                    &self.tier_name,
                    "allowed",
                    result.exit_code,
                );
                if result.cancelled {
                    CallToolResult::error(vec![ContentBlock::text(
                        "Command cancelled by caller".to_string(),
                    )])
                } else if result.timed_out {
                    CallToolResult::error(vec![ContentBlock::text(format!(
                        "Command timed out after {effective_timeout:?}"
                    ))])
                } else {
                    CallToolResult::success(vec![ContentBlock::text(format!(
                        "exit code: {:?}\nstdout:\n{}\nstderr:\n{}",
                        result.exit_code, result.stdout, result.stderr
                    ))])
                }
            }
        }
    }
```

If `RequestMetaObject::get_progress_token` (used above as
`ctx.meta.get_progress_token()`) is not directly callable this way once
you check the actual `RequestContext.meta` field's type in the pinned
SDK, adapt to whatever the real accessor path is, the underlying method
is confirmed to exist in `rmcp::model::meta` (`fn get_progress_token(&self)
-> Option<ProgressToken>`), only its exact receiver path may need
adjusting.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib tools::tests`
Expected: all `dispatch()` tests pass, including the 2 new ones, and the
3 existing ones updated in Step 1.

- [ ] **Step 6: Update `main.rs`'s `RedWrenchServer::new` call site**

```rust
// src/main.rs, replace the RedWrenchServer::new(...) call in run_server()
    let server = RedWrenchServer::new(
        Arc::new(policy::PolicyEngine::new(config.effective_rules())),
        Duration::from_secs(config.timeout_secs),
        tier_name,
        Duration::from_secs(config.max_stream_duration_secs),
    );
```

- [ ] **Step 7: Run the full test suite**

Run: `cargo test`
Expected: this will currently FAIL to compile, since Task 4 hasn't yet
updated the 5 tool files that call `dispatch()` with the old 3-argument
signature (`systemctl.rs`, `dnf.rs`, `network.rs`, `journalctl.rs`,
`run_command.rs`). This is expected and acceptable at this checkpoint,
confirm the compile errors are specifically about `dispatch()`'s argument
count in those files and nowhere else, then proceed to Task 4
immediately, do not attempt to work around this by reverting Task 3's
signature change.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock src/audit.rs src/tools/mod.rs src/main.rs
git commit -m "Wire cancellation and streaming into dispatch() via RequestContext"
```

---

### Task 4: Thread `RequestContext` through the existing tool call sites

**Files:**
- Modify: `src/tools/run_command.rs`
- Modify: `src/tools/systemctl.rs`
- Modify: `src/tools/dnf.rs`
- Modify: `src/tools/network.rs` (only `ip_addr`, `ping` is Task 5)

**Interfaces:**
- Consumes: `dispatch()`'s new signature (Task 3).
- Produces: no new public types, this task is purely mechanical, threading
  one new parameter through five existing `#[tool]` methods with no
  behaviour change (each passes `None` for `max_duration_override`, so
  every one of these tools keeps using the ordinary `timeout_secs`
  default exactly as today, they simply also now support cancellation and
  progress-token-triggered streaming for free, since `dispatch()` handles
  both uniformly).

- [ ] **Step 1: Update `run_command.rs`**

```rust
// src/tools/run_command.rs, replace the run_command method
    pub async fn run_command(
        &self,
        Parameters(RunCommandParams { command, args }): Parameters<RunCommandParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        self.dispatch("run_command", &command, args, ctx, None).await
    }
```

- [ ] **Step 2: Update `systemctl.rs`**

```rust
// src/tools/systemctl.rs, replace both tool methods
    pub async fn systemctl_status(
        &self,
        Parameters(SystemctlStatusParams { unit }): Parameters<SystemctlStatusParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        self.dispatch("systemctl_status", "systemctl", status_argv(unit), ctx, None)
            .await
    }

    pub async fn systemctl_control(
        &self,
        Parameters(SystemctlControlParams { action, unit }): Parameters<SystemctlControlParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        if !is_allowed_action(&action) {
            return CallToolResult::error(vec![rmcp::model::ContentBlock::text(format!(
                "Invalid action '{action}'. Must be one of: {}.",
                ALLOWED_ACTIONS.join(", ")
            ))]);
        }
        self.dispatch(
            "systemctl_control",
            "systemctl",
            control_argv(action, unit),
            ctx,
            None,
        )
        .await
    }
```

(keep every other line in the file, including the `#[tool(...)]`
attributes above each method, unchanged, only the method signatures and
their `dispatch(...)` calls change)

- [ ] **Step 3: Update `dnf.rs`**

```rust
// src/tools/dnf.rs, replace both tool methods (keep the existing
// #[tool(...)] attributes above each unchanged)
    pub async fn dnf_install(
        &self,
        Parameters(DnfPackageParams { package }): Parameters<DnfPackageParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        self.dispatch("dnf_install", "dnf", install_argv(package), ctx, None)
            .await
    }

    pub async fn dnf_remove(
        &self,
        Parameters(DnfPackageParams { package }): Parameters<DnfPackageParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        self.dispatch("dnf_remove", "dnf", remove_argv(package), ctx, None)
            .await
    }
```

- [ ] **Step 4: Update `network.rs`'s `ip_addr`**

```rust
// src/tools/network.rs, replace only the ip_addr method (ping is Task 5)
    pub async fn ip_addr(
        &self,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        self.dispatch("ip_addr", "ip", vec!["addr".into()], ctx, None)
            .await
    }
```

- [ ] **Step 5: Run the full test suite**

Run: `cargo test`
Expected: compiles now. `journalctl_tail` (in `journalctl.rs`) still has
the old 3-argument `dispatch()` call and will still fail to compile,
that's Task 6's job, not this one, confirm the remaining compile error
(if any) is isolated to `journalctl.rs` before proceeding, since Task 5
(network.rs's `ping`) is next and touches the same file this task already
updated for `ip_addr`.

Run: `cargo test --lib tools::run_command::tests tools::systemctl::tests tools::dnf::tests tools::network::tests`
Expected: all pass (the tests in these files exercise pure argv-building
functions and policy matching, not `dispatch()` directly, so they are
unaffected by this task's signature threading).

- [ ] **Step 6: Commit**

```bash
git add src/tools/run_command.rs src/tools/systemctl.rs src/tools/dnf.rs src/tools/network.rs
git commit -m "Thread RequestContext through run_command, systemctl, dnf, and ip_addr"
```

---

### Task 5: `ping` gains indefinite mode

**Files:**
- Modify: `src/tools/network.rs`

**Interfaces:**
- Consumes: `dispatch()`'s new signature (Task 3), `RedWrenchServer.max_stream_duration` (Task 3).
- Produces: `PingParams.count` changes type from `u32` to `Option<u32>`
  (interface change visible to MCP clients: `count` becomes an optional
  parameter instead of one with a server-side default).

- [ ] **Step 1: Write the failing tests**

Add to `src/tools/network.rs`'s existing `#[cfg(test)] mod tests` block:

```rust
#[test]
fn omitting_count_produces_an_indefinite_ping_with_no_dash_c_flag() {
    let args = ping_argv("8.8.8.8".to_string(), None);
    assert_eq!(args, vec!["--", "8.8.8.8"]);
    assert!(
        !args.iter().any(|a| a == "-c"),
        "an indefinite ping must never include -c: {args:?}"
    );
}

#[test]
fn a_present_count_still_produces_a_bounded_ping() {
    let args = ping_argv("8.8.8.8".to_string(), Some(4));
    assert_eq!(args, vec!["-c", "4", "--", "8.8.8.8"]);
}
```

Update the existing tests in the same file that call `ping_argv(host,
count)` with a bare `u32` (`ping_argv_places_a_literal_double_dash_separator_before_the_host`,
`a_flood_flag_like_host_value_is_safely_treated_as_positional`,
`an_interval_flooding_host_value_is_safely_treated_as_positional`,
`ordinary_host_values_are_unaffected`) to wrap their existing count
arguments in `Some(...)`, e.g. `ping_argv("-f".to_string(), Some(4))`
instead of `ping_argv("-f".to_string(), 4)`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib tools::network::tests`
Expected: FAIL to compile, `ping_argv` still takes a bare `u32`.

- [ ] **Step 3: Update `PingParams` and `ping_argv`**

```rust
// src/tools/network.rs, replace PingParams and default_count
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PingParams {
    /// Hostname or IP address to ping.
    pub host: String,
    /// Number of echo requests to send. Omit to ping indefinitely (no
    /// packet count) until the caller cancels the call or the server's
    /// safety-net duration elapses.
    #[serde(default)]
    pub count: Option<u32>,
}
```

(remove the now-unused `default_count` function entirely, `count`'s
default is `None` via `#[serde(default)]` on an `Option`, matching the
pattern already used for `journalctl_tail`'s `unit: Option<String>`)

```rust
// src/tools/network.rs, replace ping_argv
fn ping_argv(host: String, count: Option<u32>) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(count) = count {
        args.push("-c".to_string());
        args.push(count.to_string());
    }
    args.push("--".to_string());
    args.push(host);
    args
}
```

- [ ] **Step 4: Update the `ping` tool method**

```rust
// src/tools/network.rs, replace the ping method
    pub async fn ping(
        &self,
        Parameters(PingParams { host, count }): Parameters<PingParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        // An indefinite ping (no count) is exactly the case this whole
        // feature exists for: something that never exits on its own,
        // bounded only by the safety-net duration or a caller cancelling
        // it. A bounded ping (count given) keeps the ordinary timeout.
        let max_duration_override = if count.is_none() {
            Some(self.max_stream_duration)
        } else {
            None
        };
        self.dispatch(
            "ping",
            "ping",
            ping_argv(host, count),
            ctx,
            max_duration_override,
        )
        .await
    }
```

Also update the tool description to mention the new capability:

```rust
    #[tool(
        description = "Ping a host to check basic network reachability. Omit \
        'count' to ping indefinitely (bounded by the server's safety-net \
        duration or cancellation). Allowed under every tier."
    )]
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib tools::network::tests`
Expected: all pass, including the 2 new ones.

- [ ] **Step 6: Commit**

```bash
git add src/tools/network.rs
git commit -m "Add indefinite ping mode (omit count to ping until cancelled)"
```

---

### Task 6: `journalctl_tail` gains follow mode

**Files:**
- Modify: `src/tools/journalctl.rs`

**Interfaces:**
- Consumes: `dispatch()`'s new signature (Task 3), `RedWrenchServer.max_stream_duration` (Task 3).
- Produces: `JournalctlTailParams` gains `follow: bool` (default `false`).

- [ ] **Step 1: Write the failing tests**

Add to `src/tools/journalctl.rs`'s existing `#[cfg(test)] mod tests` block:

```rust
#[test]
fn follow_mode_appends_the_follow_flag() {
    let args = journalctl_args(None, 50, true).unwrap();
    assert_eq!(args, vec!["-n", "50", "--no-pager", "-f"]);
}

#[test]
fn follow_mode_with_a_unit_still_filters_by_unit() {
    let args = journalctl_args(Some("sshd.service".to_string()), 50, true).unwrap();
    assert_eq!(
        args,
        vec!["-n", "50", "--no-pager", "-u", "sshd.service", "-f"]
    );
}

#[test]
fn non_follow_mode_is_unchanged() {
    let args = journalctl_args(None, 50, false).unwrap();
    assert_eq!(args, vec!["-n", "50", "--no-pager"]);
}
```

Update every existing call to `journalctl_args(unit, lines)` in this
file's test module (`plain_lines_only_when_no_unit_is_given`,
`ordinary_unit_names_are_unaffected`,
`a_unit_value_that_looks_like_a_file_redirect_flag_is_rejected`,
`a_unit_value_that_looks_like_a_directory_redirect_flag_is_rejected`,
`a_bare_double_dash_unit_value_is_rejected`,
`a_single_dash_escaped_unit_name_is_accepted`,
`other_single_dash_prefixed_unit_names_are_accepted`,
`lines_is_a_plain_integer_and_is_never_treated_as_a_flag`) to add a
trailing `false` argument, e.g. `journalctl_args(None, 50, false)`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib tools::journalctl::tests`
Expected: FAIL to compile, `journalctl_args` still takes 2 arguments.

- [ ] **Step 3: Update `journalctl_args` and `JournalctlTailParams`**

```rust
// src/tools/journalctl.rs, replace JournalctlTailParams
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JournalctlTailParams {
    /// Optional unit to filter by, e.g. "sshd.service". If omitted, tails
    /// the whole system journal.
    pub unit: Option<String>,
    /// How many of the most recent lines to return. Defaults to 50.
    #[serde(default = "default_lines")]
    pub lines: u32,
    /// If true, keep following the journal after the initial `lines` are
    /// shown, until the caller cancels the call or the server's
    /// safety-net duration elapses. Defaults to false.
    #[serde(default)]
    pub follow: bool,
}
```

```rust
// src/tools/journalctl.rs, replace the journalctl_args function signature
// and body's final return, keep the existing validation logic (the
// starts_with("--") check and its surrounding comment) unchanged
fn journalctl_args(unit: Option<String>, lines: u32, follow: bool) -> Result<Vec<String>, String> {
    let mut args = vec![
        "-n".to_string(),
        lines.to_string(),
        "--no-pager".to_string(),
    ];
    if let Some(unit) = unit {
        if unit.starts_with("--") {
            return Err(format!(
                "Invalid unit \"{unit}\": unit names cannot start with \"--\" \
                (this would be interpreted as a journalctl long-option flag \
                rather than a unit name)"
            ));
        }
        args.push("-u".to_string());
        args.push(unit);
    }
    if follow {
        args.push("-f".to_string());
    }
    Ok(args)
}
```

- [ ] **Step 4: Update the `journalctl_tail` tool method**

```rust
// src/tools/journalctl.rs, replace the journalctl_tail method
    pub async fn journalctl_tail(
        &self,
        Parameters(JournalctlTailParams { unit, lines, follow }): Parameters<JournalctlTailParams>,
        ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> CallToolResult {
        match journalctl_args(unit, lines, follow) {
            Ok(args) => {
                let max_duration_override = if follow {
                    Some(self.max_stream_duration)
                } else {
                    None
                };
                self.dispatch(
                    "journalctl_tail",
                    "journalctl",
                    args,
                    ctx,
                    max_duration_override,
                )
                .await
            }
            Err(reason) => CallToolResult::error(vec![ContentBlock::text(reason)]),
        }
    }
```

Update the tool description, since it currently states live-following is
explicitly not supported:

```rust
    #[tool(
        description = "Return the most recent lines from the systemd journal, \
        optionally filtered to a single unit. Set follow: true to keep \
        streaming new lines after the initial output, until cancelled or \
        the server's safety-net duration elapses. Allowed under every tier."
    )]
```

- [ ] **Step 5: Run the full test suite**

Run: `cargo test`
Expected: all tests pass, this is the last tool file, the whole crate
should compile and every test should pass now.

- [ ] **Step 6: Commit**

```bash
git add src/tools/journalctl.rs
git commit -m "Add journalctl_tail follow mode"
```

---

### Task 7: Safe-tier allow-rules for read-only monitoring binaries

**Files:**
- Modify: `src/policy/tiers.rs`

**Interfaces:**
- Consumes: `allow`/`deny` helper functions (already exist in this file).
- Produces: no new public types, three new rules in `safe_rules()`.

- [ ] **Step 1: Write the failing tests**

Add to `src/policy/tiers.rs`'s existing `#[cfg(test)] mod tests` block:

```rust
#[test]
fn safe_tier_allows_vmstat_for_monitoring() {
    let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
    assert!(matches!(
        engine.evaluate("vmstat", &["1".into()]),
        Decision::Allowed
    ));
}

#[test]
fn safe_tier_allows_batch_mode_top_but_not_interactive_top() {
    let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
    assert!(matches!(
        engine.evaluate("top", &["-b".into(), "-n".into(), "1".into()]),
        Decision::Allowed
    ));
    assert!(matches!(
        engine.evaluate("top", &[]),
        Decision::Denied(_)
    ));
}

#[test]
fn safe_tier_allows_sar_but_denies_its_file_output_flag() {
    let engine = PolicyEngine::new(rules_for_tier(&TierName::Safe));
    assert!(matches!(
        engine.evaluate("sar", &["1".into(), "10".into()]),
        Decision::Allowed
    ));
    assert!(matches!(
        engine.evaluate("sar", &["-o".into(), "/tmp/evil.dat".into(), "1".into()]),
        Decision::Denied(_)
    ));
}

#[test]
fn the_monitoring_allow_rules_are_inherited_by_the_standard_tier() {
    let engine = PolicyEngine::new(rules_for_tier(&TierName::Standard));
    assert!(matches!(
        engine.evaluate("vmstat", &["1".into()]),
        Decision::Allowed
    ));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib policy::tiers::tests`
Expected: FAIL, `vmstat`/`top`/`sar` calls are denied (no matching rule
exists yet), the test asserting `Decision::Allowed` for them fails.

- [ ] **Step 3: Add the monitoring allow-rules**

Add to `safe_rules()`, alongside the existing `deny`/`allow` pairs
(placement within the vec doesn't matter relative to the ping/dnf/
systemctl rules, since these are different commands with no overlap, but
follow the file's existing deny-then-allow-for-the-same-command ordering
for `sar`):

```rust
/// `sar`'s `-o <file>` writes its binary sample data to an arbitrary
/// path, an arbitrary-file-write primitive wrapped in a monitoring tool
/// that is otherwise entirely read-only. Denied before the broad allow,
/// same first-match-wins pattern as the other tier-level hardening in
/// this file.
const SAR_FILE_OUTPUT_FLAG: &str = r"(?:^|\s)-o\b";
```

```rust
        // Read-only resource monitoring, safe to run indefinitely under
        // the `safe` tier: none of these mutate system state. `top`
        // requires `-b` (batch mode), interactive top would hang as a
        // non-interactive tool call rather than behave sensibly. `sar`'s
        // `-o` (write raw sample data to an arbitrary path) is denied
        // before the broad allow, the same deny-before-allow pattern
        // used for ping/dnf/journalctl elsewhere in this file.
        allow("vmstat", None),
        deny("sar", SAR_FILE_OUTPUT_FLAG),
        allow("sar", None),
        allow("top", Some(r"^-b")),
```

Add these lines inside the `vec![...]` returned by `safe_rules()`,
alongside the existing entries (`allow("systemctl", ...)`,
`deny("journalctl", ...)`, etc.), the exact position among existing
entries doesn't affect correctness since none of these commands overlap
with existing rules, but keep related rules grouped for readability, i.e.
place the three new lines together.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib policy::tiers::tests`
Expected: all pass, including the 4 new tests.

- [ ] **Step 5: Run the full test suite, build, lint, and format checks**

Run: `cargo test && cargo build && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all clean. This is the last code-touching task in this plan,
confirm the whole crate is green before moving to documentation.

- [ ] **Step 6: Commit**

```bash
git add src/policy/tiers.rs
git commit -m "Allow read-only monitoring binaries (vmstat, sar, batch-mode top) under the safe tier"
```

---

### Task 8: Documentation and UAT scenarios

**Files:**
- Modify: `ARCHITECTURE.md`
- Modify: `AGENTS.md`
- Modify: `docs/uat/v1-uat-scenarios.md`

**Interfaces:** none, documentation only.

- [ ] **Step 1: Update `ARCHITECTURE.md`**

Find the existing paragraph documenting `dispatch()`'s `CallToolResult`/
`is_error` contract (added post-v1.0-review) and add a new paragraph
immediately after it:

```markdown
`dispatch()` also owns streaming and cancellation. It extracts each
request's `RequestContext` (which `rmcp` populates with a per-request
`CancellationToken` that fires automatically on a client's
`notifications/cancelled`, and a `Peer` handle for sending
`notifications/progress`). If the incoming request carried a progress
token, `dispatch()` forwards each output chunk from the executor as a
progress message while the command runs; if it didn't, behaviour is
unchanged from a plain buffered call. Cancellation always applies
regardless of whether streaming was requested, `execute()` selects on it
alongside its timeout. A tool wanting genuinely indefinite execution
(no natural exit, bounded only by the safety-net `max_stream_duration`
config value or cancellation) passes that duration to `dispatch()` as an
override, see `ping`'s optional `count` and `journalctl_tail`'s `follow`
for the pattern.
```

- [ ] **Step 2: Update `AGENTS.md`**

Find the existing "third rule" section (the argument-injection lesson)
and add a fourth rule immediately after it, before "Before submitting a
change":

```markdown
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
```

- [ ] **Step 3: Add new UAT scenarios**

Add to `docs/uat/v1-uat-scenarios.md`, after the existing scenarios
(follow the file's existing numbered-scenario format with numbered steps
and **Expected:** callouts):

```markdown
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
3. **Expected:** the call ends quickly (well under 30 seconds), the
   response indicates cancellation (not a timeout, not a success), and
   `ps`/`pgrep` on the Fedora host confirms the `sleep` process is
   actually gone, not orphaned.

## Scenario 12: indefinite ping runs until cancelled or the safety net trips

1. Call `ping` with `host` set but `count` omitted.
2. **Expected:** the ping runs continuously; confirm via the streamed
   output (Scenario 10) that successive replies are visible over time,
   not just a final result.
3. Cancel the call (as in Scenario 11).
4. **Expected:** ping stops immediately, confirmed via `ps`/`pgrep`.
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
   confirmed via `ps`/`pgrep` to no longer be running.

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
```

- [ ] **Step 4: Commit**

```bash
git add ARCHITECTURE.md AGENTS.md docs/uat/v1-uat-scenarios.md
git commit -m "Document streaming/cancellation contract and add UAT scenarios"
```

---

## Post-plan note

This plan implements the streaming-execution design spec in full. It does
not touch the other backlog items scoped separately during brainstorming:
`systemd-sysext` packaging, COPR submission, deeper Tailscale integration,
or the real-time interactive approval workflow (a genuinely different
mechanism, a human-in-the-loop approval gate, not covered by anything in
this plan despite superficial thematic overlap with cancellation). Those
remain separate specs and plans.
