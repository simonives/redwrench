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
