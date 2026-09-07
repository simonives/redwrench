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
/// [`POST_EXIT_READ_TIMEOUT`]: without it, `execute` could return long after
/// its own `timeout` had passed, holding a server task open for as long as
/// the grandchild chose to live.
pub async fn execute(command: &str, args: &[String], timeout: Duration) -> ExecutionResult {
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
    // small constant regardless of how much the command emits.
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout.take(READ_LIMIT_BYTES).read_to_end(&mut buf).await;
        buf
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr.take(READ_LIMIT_BYTES).read_to_end(&mut buf).await;
        buf
    });

    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);

    tokio::select! {
        status = child.wait() => {
            // NOTE (post-review fix): once `wait()` wins this select, the
            // outer timeout no longer bounds anything, so awaiting the two
            // pipe-reader tasks unbounded reintroduced exactly the hang the
            // timeout exists to prevent. A grandchild that inherited the
            // stdio file descriptors and outlives the direct child (the
            // classic `sh -c 'sleep 30 & exit 0'` shape) keeps the write
            // end of both pipes open, so `read_to_end` blocks until the
            // grandchild exits, long after the child's exit status has
            // already been reported. The spec is explicit that a hung
            // process must not be able to wedge the server, so bound the
            // post-exit drain with a short secondary timeout and fall back
            // to whatever was captured (or nothing) if it elapses.
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
                },
                Err(err) => ExecutionResult {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: format!("command failed: {err}"),
                    timed_out: false,
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
            }
        }
    }
}

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
        let result = execute(
            "ls",
            &["/nonexistent-path-xyz".to_string()],
            Duration::from_secs(5),
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

    #[tokio::test]
    async fn very_large_output_is_truncated_with_a_note() {
        let result = execute(
            "seq",
            &["1".to_string(), "1000000".to_string()],
            Duration::from_secs(10),
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
        )
        .await;
        assert!(result.stdout.contains(&format!(
            "[output truncated, only the first {MAX_OUTPUT_BYTES} bytes are shown]"
        )));
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
