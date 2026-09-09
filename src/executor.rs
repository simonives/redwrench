use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[derive(Debug)]
pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub cancelled: bool,
}

const MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB

/// How long to keep draining the stdout/stderr pipes *after* the direct
/// child has already exited. See the note at the `child.wait()` arm of the
/// select below: a grandchild holding the inherited pipe open would
/// otherwise block the read indefinitely, past the caller's own timeout.
/// Short, because by this point the process is gone and anything still
/// arriving is a straggler, not the command's real output.
const POST_EXIT_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// How much each pipe reader is allowed to buffer.
///
/// NOTE (post-review fix, unbounded allocation): the pipe readers used to
/// call `read_to_end` with no bound and rely on [`truncate_output`] to cap
/// the result afterwards. Truncating after the fact caps what the *agent*
/// sees, not what the *server* allocates: a command such as
/// `dd if=/dev/zero bs=1M count=5000` or a runaway `yes` would be buffered
/// in full first, so the server could be OOM-killed long before the
/// execution timeout ever fired. Bounding the read itself makes the peak
/// allocation a small constant (1 MiB + 1 byte per pipe) no matter how much
/// the command tries to produce.
///
/// The extra byte is what preserves the truncation signal: reading exactly
/// `MAX_OUTPUT_BYTES` cannot be distinguished from a command whose output
/// happened to be exactly that size, whereas reading one byte more proves
/// there was more to come. Once the reader stops, the pipe's read end is
/// dropped, the writer gets `EPIPE`/`SIGPIPE`, and the command dies rather
/// than blocking forever on a full pipe.
const READ_LIMIT_BYTES: u64 = MAX_OUTPUT_BYTES as u64 + 1;

fn truncate_output(data: Vec<u8>) -> String {
    if data.len() > MAX_OUTPUT_BYTES {
        let truncated = &data[..MAX_OUTPUT_BYTES];
        let mut s = String::from_utf8_lossy(truncated).into_owned();
        // The total is deliberately not reported: the read is bounded, so
        // the full length of the command's output is not known here and
        // claiming one would be a lie.
        s.push_str(&format!(
            "\n... [output truncated, only the first {MAX_OUTPUT_BYTES} bytes are shown]"
        ));
        s
    } else {
        String::from_utf8_lossy(&data).into_owned()
    }
}

/// A channel for forwarding output chunks as they arrive, used to power
/// live streaming via MCP progress notifications. `dispatch()` (the only
/// caller that knows about `rmcp`) owns the receiving end; this module
/// stays free of any MCP-specific types, the same separation `dispatch()`
/// already draws between "run a process" (this file) and "speak MCP"
/// (`tools/mod.rs`).
pub type ChunkSink = tokio::sync::mpsc::UnboundedSender<String>;

/// Appends the "why this ended" note to whatever stderr the command had
/// already produced, rather than replacing it.
///
/// The timeout and cancellation arms both owe the caller two things now: the
/// real stderr captured before the kill, and the reason the call ended. The
/// note goes last so it reads as the terminating line.
fn with_note(captured: String, note: &str) -> String {
    if captured.is_empty() {
        note.to_string()
    } else if captured.ends_with('\n') {
        format!("{captured}{note}")
    } else {
        format!("{captured}\n{note}")
    }
}

/// The buffer a pipe reader accumulates into, shared with `execute` so its
/// contents survive the reader being aborted.
///
/// A `std::sync::Mutex` rather than a `tokio` one on purpose: the guard is
/// never held across an `.await`, so it cannot block the runtime and cannot
/// be poisoned by an abort landing mid-critical-section.
type SharedBuf = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;

fn take_buf(buf: &SharedBuf) -> Vec<u8> {
    let mut guard = buf.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    std::mem::take(&mut guard)
}

/// Reads one pipe to EOF (or to [`READ_LIMIT_BYTES`]), appending into `buf`
/// and forwarding each chunk to `sink` as it arrives.
async fn read_pipe<R: tokio::io::AsyncRead + Unpin>(
    pipe: R,
    buf: SharedBuf,
    sink: Option<ChunkSink>,
) {
    let mut reader = pipe.take(READ_LIMIT_BYTES);
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buf.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .extend_from_slice(&chunk[..n]);
                if let Some(sink) = &sink {
                    let _ = sink.send(String::from_utf8_lossy(&chunk[..n]).into_owned());
                }
            }
            Err(_) => break,
        }
    }
}

/// Awaits one pipe-reader task under [`POST_EXIT_READ_TIMEOUT`], aborting it
/// if that window elapses, then returns whatever it accumulated either way.
///
/// NOTE (post-review fix, detached reader tasks): the elapsed branch used to
/// let `.ok()` simply drop the `JoinHandle`. Dropping a `JoinHandle` in Tokio
/// *detaches* the task, it does not cancel it, so in the grandchild case
/// (`sh -c 'sleep 30 & exit 0'`) both readers stayed alive for as long as the
/// grandchild held the pipe. That was an invisible leak before streaming;
/// now those tasks still hold a live [`ChunkSink`] clone, so a leaked reader
/// keeps feeding `notifications/progress` frames for a request whose response
/// has already been sent. The explicit `.abort()` is what stops that.
async fn drain_one(mut task: tokio::task::JoinHandle<()>, buf: SharedBuf) -> Vec<u8> {
    if tokio::time::timeout(POST_EXIT_READ_TIMEOUT, &mut task)
        .await
        .is_err()
    {
        task.abort();
    }
    take_buf(&buf)
}

/// Collects whatever both readers captured, once the child is known to be
/// gone (exited, killed on timeout, or killed on cancellation).
///
/// With the child dead its pipes close and the readers hit EOF almost
/// immediately, so this is normally instant. The bound exists only for the
/// grandchild case described on [`drain_one`]. The two drains run
/// concurrently under `tokio::join!` so they share one
/// [`POST_EXIT_READ_TIMEOUT`] window rather than stacking two of them.
///
/// All three `select!` arms use this, which is what makes a timed-out or
/// cancelled call return the output it produced before it ended. Discarding
/// that output was defensible when every call was bounded and short; for a
/// genuinely indefinite call, cancellation is the *only* way it ever ends, so
/// discarding on cancel would mean such a call could never return anything.
async fn drain_after_kill(
    stdout_task: tokio::task::JoinHandle<()>,
    stdout_buf: SharedBuf,
    stderr_task: tokio::task::JoinHandle<()>,
    stderr_buf: SharedBuf,
) -> (String, String) {
    let (stdout_data, stderr_data) = tokio::join!(
        drain_one(stdout_task, stdout_buf),
        drain_one(stderr_task, stderr_buf)
    );
    (truncate_output(stdout_data), truncate_output(stderr_data))
}

/// The OS identity a developer-tier command runs under, instead of
/// RedWrench's own (root) identity. Resolved once at startup from
/// `config.developer_user` and carried unchanged from there to the
/// `Command` builder.
///
/// It carries more than `(uid, gid)` deliberately. A process running under
/// a different uid but still inheriting root's `HOME`, `USER`, `LOGNAME`
/// and working directory is not a usable development environment: `~`
/// expands to an unwritable `/root`, `npm` targets `/root/.npm`, `cargo`
/// targets `/root/.cargo`, and relative paths resolve against whatever
/// directory the service happened to start in. The design spec puts a
/// natural development experience (existing dotfiles and tooling config
/// reachable, package installation in scope) explicitly in scope, so the
/// account's own name and home directory travel with its uid/gid rather
/// than being discarded at resolution time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeveloperIdentity {
    pub uid: u32,
    pub gid: u32,
    /// The account's login name, used for the child's `USER` and `LOGNAME`.
    pub name: String,
    /// The account's home directory, used for the child's `HOME` and its
    /// working directory.
    pub home: std::path::PathBuf,
}

/// Runs `command` with `args` as an argv vector (never through a shell),
/// bounded by `timeout`, optionally cancellable, optionally streaming each
/// output chunk to `chunk_sink` as it arrives, optionally spawned under a
/// different identity than RedWrench's own (the `developer` tier's
/// privilege-drop mechanism, see `policy::tiers::DEVELOPER_TOOLS`).
///
/// Kills the spawned process on timeout via `kill_on_drop` plus an
/// explicit `.kill()` call. This guarantees the directly-spawned
/// process is terminated; it does not guarantee termination of any
/// further descendants a shell-wrapped command might have spawned
/// (e.g. `sh -c "sleep 5 && ..."` has `sleep` as a grandchild, not a
/// direct child). Every RedWrench tool handler invokes commands
/// directly (no wrapping shell), so this limitation only applies if a
/// caller deliberately runs a shell as the target command itself.
///
/// Such a grandchild also inherits the stdout/stderr pipe file descriptors,
/// which is why the post-exit drain is separately bounded by
/// `POST_EXIT_READ_TIMEOUT`: without it, `execute` could return long after
/// its own `timeout` had passed, holding a server task open for as long as
/// the grandchild chose to live.
pub async fn execute(
    command: &str,
    args: &[String],
    timeout: Duration,
    cancellation: Option<tokio_util::sync::CancellationToken>,
    chunk_sink: Option<ChunkSink>,
    run_as: Option<DeveloperIdentity>,
) -> ExecutionResult {
    let mut cmd = Command::new(command);
    cmd.args(args)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(DeveloperIdentity {
        uid,
        gid,
        ref name,
        ref home,
    }) = run_as
    {
        // Environment and working directory, so the dropped process gets
        // the account's own context rather than root's. Without this the
        // child runs under the developer_user's uid while `$HOME` still
        // says `/root`, which breaks `~` expansion and sends every tool
        // that caches under `$HOME` (npm, cargo) at a directory the child
        // cannot write.
        //
        // std applies `current_dir` in the forked child *after* the
        // uid/gid it was configured with but *before* any `pre_exec`
        // closure, and the drop below happens entirely inside that closure,
        // so the `chdir` still runs as root and cannot fail on a home
        // directory the account itself could not traverse.
        cmd.current_dir(home)
            .env("HOME", home)
            .env("USER", name)
            .env("LOGNAME", name);

        // The whole privilege drop happens here in one `pre_exec` closure
        // rather than through `Command::uid`/`Command::gid`, because the
        // supplementary group list has to be cleared *first* and the
        // builder cannot express that ordering.
        //
        // `setgid`/`setuid` alone leave the child carrying every
        // supplementary group RedWrench (root) belonged to, which is
        // residual privilege the developer tier exists to remove. Clearing
        // them needs CAP_SETGID, so it must happen while the child is still
        // effectively root, i.e. before `setuid`. std runs `pre_exec`
        // closures *after* it applies `.uid()`/`.gid()`, so pairing
        // `.uid()`/`.gid()` with a `setgroups` closure fails at spawn with
        // EPERM (verified empirically on Fedora, not assumed). Doing all
        // three calls ourselves, in order, is the only way to get it right,
        // and it also makes each step's failure loud rather than ignored.
        // (`pre_exec` is an inherent method on `tokio::process::Command`
        // here, so no `CommandExt` import is needed.)
        //
        // SAFETY: `pre_exec` runs in the forked child between `fork()` and
        // `exec()`, where only async-signal-safe work is sound. The closure
        // does nothing but issue three syscalls (`setgroups`, `setgid`,
        // `setuid`) through nix's thin wrappers and, on failure, build an
        // `io::Error` from a raw errno. It allocates nothing, takes no
        // locks, touches no shared state, and captures only two `u32`s by
        // copy, so it is safe to run in that context.
        // The crate denies `unsafe_code` at the manifest level
        // (`[lints.rust]` in Cargo.toml). This is its sole intentional
        // exception: there is no safe API for the ordering this drop
        // requires, and the SAFETY note above states why this particular
        // closure is sound in a forked child. Any second `unsafe` block
        // added to this crate should have to justify itself the same way.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(move || {
                nix::unistd::setgroups(&[]).map_err(std::io::Error::from)?;
                nix::unistd::setgid(nix::unistd::Gid::from_raw(gid))
                    .map_err(std::io::Error::from)?;
                nix::unistd::setuid(nix::unistd::Uid::from_raw(uid))
                    .map_err(std::io::Error::from)?;
                Ok(())
            });
        }
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

    let stdout = child.stdout.take().expect("stdout not configured as piped");
    let stderr = child.stderr.take().expect("stderr not configured as piped");

    // Drain both pipes concurrently, starting now, regardless of
    // whether the process finishes or the timeout fires first. This
    // avoids the pipe backpressure deadlock: if nobody reads until
    // after wait() resolves, a process producing more output than the
    // OS pipe buffer holds can block on write() forever, and wait()
    // then never resolves either.
    //
    // Each read is bounded by `READ_LIMIT_BYTES` (see the note there): the
    // `.take()` adapter caps the reader itself, so the peak allocation is a
    // small constant regardless of how much the command emits. Each chunk
    // read is also forwarded to `chunk_sink` as it arrives (if present),
    // so streaming adds no additional buffering of its own and cannot
    // reopen the unbounded-memory hole `READ_LIMIT_BYTES` closed: a
    // firehose command is still capped at a small constant allocation
    // whether or not a caller is listening for chunks.
    //
    // Each reader accumulates into a shared buffer rather than returning one
    // from the task. NOTE (post-review fix): a task's own local `Vec` is only
    // observable if the task is joined, so aborting a reader that a
    // grandchild is holding open would throw away everything it had already
    // captured. Sharing the buffer means the abort path is now "stop reading
    // and take what you have", which is what makes a cancelled indefinite
    // call return real output.
    let stdout_buf: SharedBuf = SharedBuf::default();
    let stderr_buf: SharedBuf = SharedBuf::default();

    let stdout_sink = chunk_sink.clone();
    let stdout_task = tokio::spawn(read_pipe(stdout, stdout_buf.clone(), stdout_sink));
    let stderr_sink = chunk_sink;
    let stderr_task = tokio::spawn(read_pipe(stderr, stderr_buf.clone(), stderr_sink));

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
            // NOTE (post-review fix): once `wait()` wins this select, the
            // outer timeout no longer bounds anything, so awaiting the two
            // pipe-reader tasks unbounded reintroduced exactly the hang the
            // timeout exists to prevent. A grandchild that inherited the
            // stdio file descriptors and outlives the direct child (the
            // classic `sh -c 'sleep 30 & exit 0'` shape) keeps the write
            // end of both pipes open, so the read loop blocks until the
            // grandchild exits, long after the child's exit status has
            // already been reported. The spec is explicit that a hung
            // process must not be able to wedge the server, so bound the
            // post-exit drain with a short secondary timeout and fall back
            // to whatever was captured (or nothing) if it elapses.
            let (stdout_data, stderr_data) = drain_after_kill(stdout_task, stdout_buf, stderr_task, stderr_buf).await;
            match status {
                Ok(status) => ExecutionResult {
                    exit_code: status.code(),
                    stdout: stdout_data,
                    stderr: stderr_data,
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
            // NOTE (post-review fix, discarded output): the readers used to be
            // `.abort()`ed here and both streams returned empty. Kill the
            // child first, then drain: with the process gone the pipes close
            // and the readers finish at once, so the caller gets everything
            // captured up to the moment the ceiling was reached.
            let _ = child.kill().await;
            let (stdout_data, stderr_data) = drain_after_kill(stdout_task, stdout_buf, stderr_task, stderr_buf).await;
            ExecutionResult {
                exit_code: None,
                stdout: stdout_data,
                stderr: with_note(stderr_data, &format!("command timed out after {timeout:?}")),
                timed_out: true,
                cancelled: false,
            }
        },
        _ = &mut cancelled_fut => {
            // Same as the timeout arm, and it matters more here: for a
            // genuinely indefinite call (`ping` with no count,
            // `journalctl_tail` with follow) cancellation is the only way the
            // call ever ends, so discarding the buffer meant such a call
            // could never return anything at all.
            let _ = child.kill().await;
            let (stdout_data, stderr_data) = drain_after_kill(stdout_task, stdout_buf, stderr_task, stderr_buf).await;
            ExecutionResult {
                exit_code: None,
                stdout: stdout_data,
                stderr: with_note(stderr_data, "command cancelled by caller"),
                timed_out: false,
                cancelled: true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Resolves a real account from the test machine's passwd database into
    /// a `DeveloperIdentity`, mirroring what `main.rs`'s `resolve_user` does
    /// at startup. Resolved dynamically rather than hardcoding numbers or
    /// paths, since those are conventions, not guarantees.
    fn identity_for(username: &str) -> DeveloperIdentity {
        let user = nix::unistd::User::from_name(username)
            .unwrap()
            .unwrap_or_else(|| {
                panic!(
                    "'{username}' must exist on the Fedora test environment this project requires"
                )
            });
        DeveloperIdentity {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            name: user.name,
            home: user.dir,
        }
    }

    #[tokio::test]
    async fn run_as_drops_privilege_to_the_given_uid_and_gid() {
        // "nobody" exists on every Fedora system (this project's own
        // documented test environment, see CONTRIBUTING.md) and is never
        // uid/gid 0, which is exactly what this test needs to distinguish
        // "dropped" from "still root". Resolved dynamically rather than
        // hardcoding a numeric uid, since that number is a convention, not a
        // guarantee.
        let identity = identity_for("nobody");
        let (uid, gid) = (identity.uid, identity.gid);
        assert_ne!(uid, 0, "test is meaningless if 'nobody' resolved to root");

        let result = execute(
            "id",
            &["-u".to_string()],
            Duration::from_secs(5),
            None,
            None,
            Some(identity.clone()),
        )
        .await;

        assert_eq!(result.exit_code, Some(0));
        assert_eq!(
            result.stdout.trim(),
            uid.to_string(),
            "the spawned process's own reported uid must match the dropped identity, \
             not RedWrench's (root's) uid"
        );

        // The gid is the other half of the permissions guarantee: an
        // implementation that got the uid right and the gid wrong (or
        // omitted it) would still pass the assertion above.
        let result = execute(
            "id",
            &["-g".to_string()],
            Duration::from_secs(5),
            None,
            None,
            Some(identity.clone()),
        )
        .await;

        assert_eq!(result.exit_code, Some(0));
        assert_eq!(
            result.stdout.trim(),
            gid.to_string(),
            "the spawned process's own reported gid must match the dropped identity, \
             not RedWrench's (root's) gid"
        );

        // `id -G` lists the effective gid plus every supplementary group.
        // Asserting it is *exactly* the dropped gid and nothing else proves
        // the supplementary group list was cleared, so the child carries no
        // residual membership inherited from root.
        let result = execute(
            "id",
            &["-G".to_string()],
            Duration::from_secs(5),
            None,
            None,
            Some(identity.clone()),
        )
        .await;

        assert_eq!(result.exit_code, Some(0));
        assert_eq!(
            result
                .stdout
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>(),
            vec![gid.to_string()],
            "the spawned process must belong to exactly the dropped gid, with no \
             supplementary groups inherited from RedWrench (root)"
        );
    }

    #[tokio::test]
    async fn run_as_gives_the_child_the_account_s_own_home_environment_and_cwd() {
        // "daemon" is used rather than "nobody" because its home (`/sbin`)
        // is a distinctive real path: "nobody"'s home is `/` on Fedora,
        // which is also a plausible accidental default, so it could not
        // tell a working implementation from a broken one.
        let identity = identity_for("daemon");
        assert_ne!(identity.uid, 0, "test is meaningless if 'daemon' is root");
        let home = identity.home.display().to_string();
        assert_ne!(
            home, "/root",
            "test is meaningless if the fixture account shares root's home"
        );

        let result = execute(
            "sh",
            &[
                "-c".to_string(),
                "echo \"$HOME\"; echo \"$USER\"; echo \"$LOGNAME\"; pwd".to_string(),
            ],
            Duration::from_secs(5),
            None,
            None,
            Some(identity.clone()),
        )
        .await;

        assert_eq!(result.exit_code, Some(0));
        let lines: Vec<&str> = result.stdout.lines().collect();
        assert_eq!(
            lines[..3],
            [
                home.as_str(),
                identity.name.as_str(),
                identity.name.as_str()
            ],
            "the dropped child must see the account's own HOME/USER/LOGNAME, not \
             inherit root's while running under a different uid: {:?}",
            result.stdout
        );

        // `pwd` reports the physical path, and Fedora's usrmerge makes several
        // conventional home directories symlinks (`/sbin` -> `/usr/bin`), so
        // both sides are canonicalised before comparison rather than asserting
        // the literal passwd string.
        let expected_cwd = std::fs::canonicalize(&identity.home).unwrap();
        assert_eq!(
            std::fs::canonicalize(lines[3]).unwrap(),
            expected_cwd,
            "the dropped child must start in the account's home directory, not \
             whatever directory RedWrench itself was started in: {:?}",
            result.stdout
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

    #[tokio::test]
    async fn captures_stdout_and_exit_code_of_a_successful_command() {
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
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn captures_stderr_and_nonzero_exit_code_of_a_failing_command() {
        let result = execute(
            "ls",
            &["/nonexistent-path-xyz".to_string()],
            Duration::from_secs(5),
            None,
            None,
            None,
        )
        .await;
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
            None,
            None,
            None,
        )
        .await;
        assert_eq!(result.stdout.trim(), "hello; echo pwned");
    }

    #[tokio::test]
    async fn a_command_exceeding_the_timeout_is_killed_and_marked_timed_out() {
        let result = execute(
            "sleep",
            &["5".to_string()],
            Duration::from_millis(100),
            None,
            None,
            None,
        )
        .await;
        assert!(result.timed_out);
        assert_eq!(result.exit_code, None);
    }

    #[tokio::test]
    async fn very_large_output_is_truncated_with_a_note() {
        let result = execute(
            "seq",
            &["1".to_string(), "1000000".to_string()],
            Duration::from_secs(10),
            None,
            None,
            None,
        )
        .await;
        assert!(result.stdout.len() <= MAX_OUTPUT_BYTES + 200);
        assert!(result.stdout.contains("truncated"));
    }

    #[tokio::test]
    async fn the_read_itself_is_bounded_so_a_firehose_command_cannot_exhaust_memory() {
        // `seq 1 500000000` is roughly 5 GiB of output, ~5000x the
        // truncation limit. Before the read was bounded, every one of those
        // bytes was buffered in a `Vec` before `truncate_output` ever ran,
        // so a command like this (or `yes`, or `dd if=/dev/zero`) could
        // OOM-kill the server well inside the execution timeout.
        //
        // Elapsed time is the *sole* discriminator here. Neither of the
        // other assertions distinguishes the bounded path from the buggy
        // unbounded one: the length check would also hold if the full 5 GiB
        // had been buffered and then trimmed, and `!timed_out` would also
        // hold because an unbounded read still finishes inside the
        // command's own 60s timeout, just far more slowly. What only the
        // bounded read can do is return in a small fraction of the time
        // draining 5 GiB through a pipe takes: once the bounded reader is
        // satisfied it drops the pipe's read end, `seq` takes `SIGPIPE` and
        // dies, and the whole call returns almost immediately. The 4s bound
        // below leaves generous headroom over that near-instant return
        // while staying far under what any real `seq`/shell implementation
        // needs to produce 5 GiB.
        let started = std::time::Instant::now();
        let result = execute(
            "seq",
            &["1".to_string(), "500000000".to_string()],
            Duration::from_secs(60),
            None,
            None,
            None,
        )
        .await;

        assert!(
            result.stdout.len() <= MAX_OUTPUT_BYTES + 200,
            "captured {} bytes, the read is not bounded",
            result.stdout.len()
        );
        assert!(result.stdout.contains("truncated"));
        assert!(
            !result.timed_out,
            "the command should be cut short by the bounded read, not by the timeout"
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "took {:?}; a bounded read should stop long before the command finishes",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn the_truncation_note_does_not_claim_a_total_output_size() {
        // The read stops one byte past the limit, so the command's real
        // total output length is unknown here. The note must say what was
        // shown without inventing a denominator.
        let result = execute(
            "seq",
            &["1".to_string(), "1000000".to_string()],
            Duration::from_secs(30),
            None,
            None,
            None,
        )
        .await;
        assert!(result.stdout.contains(&format!(
            "[output truncated, only the first {MAX_OUTPUT_BYTES} bytes are shown]"
        )));
    }

    #[tokio::test]
    async fn each_output_chunk_is_forwarded_to_the_sink_as_it_arrives() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let result = execute(
            "echo",
            &["hello".to_string()],
            Duration::from_secs(5),
            None,
            Some(tx),
            None,
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
    async fn a_cancelled_command_returns_the_output_it_produced_before_cancellation() {
        // Regression guard: the cancel arm used to abort both readers and
        // return empty strings. For an indefinite call, cancellation is the
        // only way the call ever ends, so that meant an operator who ran
        // `ping` for 25 minutes and then stopped it got nothing back.
        let cancellation = tokio_util::sync::CancellationToken::new();
        let ct = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            ct.cancel();
        });

        let result = execute(
            "sh",
            &["-c".to_string(), "echo before-cancel; sleep 30".to_string()],
            Duration::from_secs(60),
            Some(cancellation),
            None,
            None,
        )
        .await;

        assert!(result.cancelled);
        assert!(!result.timed_out);
        assert!(
            result.stdout.contains("before-cancel"),
            "cancellation discarded the buffered output, got: {:?}",
            result.stdout
        );
    }

    #[tokio::test]
    async fn a_timed_out_command_returns_the_output_it_produced_before_the_timeout() {
        // The same guarantee on the timeout arm, which shared the discarding
        // behaviour. The "timed out" note is appended to the captured stderr
        // rather than replacing it.
        let result = execute(
            "sh",
            &[
                "-c".to_string(),
                "echo before-timeout; sleep 30".to_string(),
            ],
            Duration::from_millis(150),
            None,
            None,
            None,
        )
        .await;

        assert!(result.timed_out);
        assert!(
            result.stdout.contains("before-timeout"),
            "the timeout discarded the buffered output, got: {:?}",
            result.stdout
        );
        assert!(result.stderr.contains("command timed out after"));
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
            None,
        )
        .await;
        assert!(result.timed_out);
        assert!(!result.cancelled);
    }

    #[tokio::test]
    async fn a_grandchild_holding_the_pipe_open_cannot_hang_execute() {
        // `sh` exits immediately, but the backgrounded `sleep` inherits
        // both pipe write ends and lives for 30 seconds. Before the
        // post-exit read timeout, `read_to_end` blocked for that whole 30
        // seconds even though the direct child was already reaped, so
        // `execute` ignored its own timeout entirely.
        //
        // The bound is POST_EXIT_READ_TIMEOUT (2s), so this asserts
        // completion well inside that 30s while still proving the read is
        // bounded rather than waiting on the grandchild.
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            execute(
                "sh",
                &["-c".to_string(), "sleep 30 & exit 0".to_string()],
                Duration::from_secs(20),
                None,
                None,
                None,
            ),
        )
        .await
        .expect("execute() hung past the grandchild-safe bound");

        assert!(
            started.elapsed() < Duration::from_secs(8),
            "execute() took {:?}, the post-exit drain is not bounded",
            started.elapsed()
        );
        // The direct child really did exit successfully; the timeout is on
        // the drain, not on the command.
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.timed_out);
    }
}
