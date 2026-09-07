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

fn truncate_output(data: Vec<u8>) -> String {
    if data.len() > MAX_OUTPUT_BYTES {
        let truncated = &data[..MAX_OUTPUT_BYTES];
        let mut s = String::from_utf8_lossy(truncated).into_owned();
        s.push_str(&format!(
            "\n... [output truncated, {} of {} bytes shown]",
            MAX_OUTPUT_BYTES,
            data.len()
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

    let mut stdout = child.stdout.take().expect("stdout not configured as piped");
    let mut stderr = child.stderr.take().expect("stderr not configured as piped");

    // Drain both pipes concurrently, starting now, regardless of
    // whether the process finishes or the timeout fires first. This
    // avoids the pipe backpressure deadlock: if nobody reads until
    // after wait() resolves, a process producing more output than the
    // OS pipe buffer holds can block on write() forever, and wait()
    // then never resolves either.
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf).await;
        buf
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        buf
    });

    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);

    tokio::select! {
        status = child.wait() => {
            let stdout_data = stdout_task.await.unwrap_or_default();
            let stderr_data = stderr_task.await.unwrap_or_default();
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
}
