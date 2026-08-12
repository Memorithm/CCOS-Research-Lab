//! All generated-code execution goes through the shared fail-closed runner.
use crate::error::{ForgeError, Result};
use ccos_sandbox::{run, SandboxSpec};
use std::process::Command;
use std::time::Duration;

fn execute(
    cmd: Command,
    timeout: Duration,
    max_output: u64,
    max_memory_bytes: Option<u64>,
    max_file_size_bytes: Option<u64>,
) -> Result<String> {
    let cwd = cmd
        .get_current_dir()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| "/".into()));
    if !cwd.is_dir() {
        return Err(ForgeError::Evaluation(
            "sandbox cwd is not a directory".into(),
        ));
    }
    let environment = cmd
        .get_envs()
        .filter_map(|(k, v)| v.map(|v| (k.to_os_string(), v.to_os_string())))
        .collect();
    let spec = SandboxSpec {
        program: cmd.get_program().to_os_string().into(),
        args: cmd.get_args().map(|a| a.to_os_string()).collect(),
        cwd: cwd.clone(),
        writable_paths: vec![cwd],
        environment,
        timeout,
        termination_grace: Duration::from_millis(250),
        max_output_bytes: max_output,
        max_memory_bytes,
        max_file_size_bytes,
        max_processes: None,
        cpu_time_limit: Some(timeout),
        network: ccos_sandbox::NetworkPolicy::Deny,
    };
    let out = run(&spec).map_err(|e| ForgeError::Evaluation(format!("sandbox refused: {e}")))?;
    if out.timed_out {
        return Err(ForgeError::Evaluation(
            "sandbox timeout; descendants terminated".into(),
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status != ccos_sandbox::SandboxExit::Success {
        return Err(ForgeError::Evaluation(format!(
            "sandbox command failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(text)
}

pub fn run_with_timeout(cmd: Command, timeout: Duration) -> Result<String> {
    execute(cmd, timeout, 4 * 1024 * 1024, None, None)
}

pub fn run_with_secure_limits(
    cmd: Command,
    timeout: Duration,
    max_memory_bytes: u64,
    max_file_size_bytes: u64,
) -> Result<String> {
    execute(
        cmd,
        timeout,
        4 * 1024 * 1024,
        Some(max_memory_bytes),
        Some(max_file_size_bytes),
    )
}
