//! Unified fail-closed Linux execution boundary for generated code.
//!
//! The runner deliberately has no direct-execution fallback: if Bubblewrap is
//! unavailable, evaluation is refused.  Callers supply an executable and
//! structured arguments; shell parsing is never involved.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkPolicy {
    Deny,
    LoopbackOnly,
}

#[derive(Clone, Debug)]
pub struct SandboxSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub writable_paths: Vec<PathBuf>,
    pub environment: BTreeMap<OsString, OsString>,
    pub timeout: Duration,
    pub termination_grace: Duration,
    pub max_output_bytes: u64,
    pub max_memory_bytes: Option<u64>,
    pub max_file_size_bytes: Option<u64>,
    pub max_processes: Option<u64>,
    pub cpu_time_limit: Option<Duration>,
    pub network: NetworkPolicy,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SandboxExit {
    Success,
    Failure,
    Signalled,
}

#[derive(Debug)]
pub struct SandboxOutput {
    pub status: SandboxExit,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub output_truncated: bool,
}

#[derive(Debug)]
pub enum SandboxError {
    Unavailable,
    PolicyViolation(String),
    Spawn(String),
    Timeout,
}
impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SandboxError {}

pub trait SandboxRunner {
    fn run(&self, spec: &SandboxSpec) -> Result<SandboxOutput, SandboxError>;
}

#[derive(Default)]
pub struct LinuxBubblewrap;

impl LinuxBubblewrap {
    fn executable() -> Result<PathBuf, SandboxError> {
        ["/usr/bin/bwrap", "/bin/bwrap"]
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .map(Path::to_path_buf)
            .ok_or(SandboxError::Unavailable)
    }
}

impl SandboxRunner for LinuxBubblewrap {
    fn run(&self, spec: &SandboxSpec) -> Result<SandboxOutput, SandboxError> {
        if !spec.cwd.is_dir() || spec.writable_paths.iter().any(|p| !p.is_dir()) {
            return Err(SandboxError::PolicyViolation(
                "workspace paths must be directories".into(),
            ));
        }
        let bwrap = Self::executable()?;
        let mut cmd = Command::new(bwrap);
        cmd.env_clear().args([
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-net",
            "--clearenv",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind-try",
            "/bin",
            "/bin",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--tmpfs",
            "/dev",
            "--dev-bind",
            "/dev/null",
            "/dev/null",
            "--dev-bind",
            "/dev/urandom",
            "/dev/urandom",
            "--dir",
            "/workspace",
        ]);
        for path in &spec.writable_paths {
            cmd.args(["--bind"]).arg(path).args(["/workspace"]);
        }
        cmd.args([
            "--chdir",
            "/workspace",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "LANG",
            "C",
        ]);
        for (k, v) in &spec.environment {
            cmd.arg("--setenv").arg(k).arg(v);
        }
        cmd.arg("--")
            .arg(&spec.program)
            .args(&spec.args)
            .current_dir(&spec.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| SandboxError::Spawn(e.to_string()))?;
        let out = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::Spawn("stdout".into()))?;
        let err = child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::Spawn("stderr".into()))?;
        let cap = (spec.max_output_bytes / 2).max(1) as usize;
        let (tx, rx) = std::sync::mpsc::channel();
        let tx2 = tx.clone();
        thread::spawn(move || {
            let mut b = Vec::new();
            let _ = out.take((cap + 1) as u64).read_to_end(&mut b);
            let _ = tx.send(b);
        });
        thread::spawn(move || {
            let mut b = Vec::new();
            let _ = err.take((cap + 1) as u64).read_to_end(&mut b);
            let _ = tx2.send(b);
        });
        let deadline = Instant::now() + spec.timeout;
        let mut timed = false;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() >= deadline => {
                    timed = true;
                    #[cfg(unix)]
                    {
                        let _ = Command::new("/bin/kill")
                            .args(["-KILL", &format!("-{}", child.id())])
                            .status();
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(SandboxError::Spawn(e.to_string())),
            }
        }
        let a = rx
            .recv_timeout(spec.termination_grace + Duration::from_secs(1))
            .unwrap_or_default();
        let b = rx
            .recv_timeout(spec.termination_grace + Duration::from_secs(1))
            .unwrap_or_default();
        let truncated = a.len() > cap || b.len() > cap;
        let status = if timed {
            SandboxExit::Signalled
        } else if child
            .try_wait()
            .ok()
            .flatten()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            SandboxExit::Success
        } else {
            SandboxExit::Failure
        };
        Ok(SandboxOutput {
            status,
            stdout: a.into_iter().take(cap).collect(),
            stderr: b.into_iter().take(cap).collect(),
            timed_out: timed,
            output_truncated: truncated,
        })
    }
}

pub fn run(spec: &SandboxSpec) -> Result<SandboxOutput, SandboxError> {
    LinuxBubblewrap.run(spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_is_fail_closed() {
        let cwd = std::env::temp_dir();
        let spec = SandboxSpec {
            program: "/bin/echo".into(),
            args: vec!["ok".into()],
            cwd: cwd.clone(),
            writable_paths: vec![cwd],
            environment: BTreeMap::new(),
            timeout: Duration::from_secs(2),
            termination_grace: Duration::from_millis(50),
            max_output_bytes: 128,
            max_memory_bytes: None,
            max_file_size_bytes: None,
            max_processes: None,
            cpu_time_limit: None,
            network: NetworkPolicy::Deny,
        };
        match run(&spec) {
            Ok(out) => assert_eq!(out.status, SandboxExit::Success),
            Err(SandboxError::Unavailable) => {}
            Err(e) => panic!("unexpected sandbox error: {e:?}"),
        }
    }
}
