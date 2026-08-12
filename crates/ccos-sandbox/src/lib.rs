//! Unified fail-closed Linux execution boundary for generated code.
//!
//! The runner deliberately has no direct-execution fallback: if Bubblewrap is
//! unavailable, evaluation is refused. Callers supply an executable and
//! structured arguments; shell parsing is never involved. Declared POSIX
//! resource ceilings are applied with `prlimit(1)` *inside* the Bubblewrap
//! boundary; requesting a ceiling when `prlimit` is unavailable fails closed.
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

/// Trusted immutable host input exposed by the *runner policy*, never by the
/// candidate harness itself.
///
/// `target` is restricted to one top-level sandbox path such as
/// `/rust-toolchain` or `/cargo-vendor`, preventing a mount from shadowing
/// `/workspace` or one of the base system/security mounts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyMount {
    pub source: PathBuf,
    pub target: PathBuf,
}

impl ReadOnlyMount {
    pub fn new(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SandboxSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    /// Exactly one writable host workspace is exposed as `/workspace`.
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

#[derive(Clone, Debug, Default)]
pub struct LinuxBubblewrap {
    read_only_mounts: Vec<ReadOnlyMount>,
}

impl LinuxBubblewrap {
    /// Construct an infrastructure runner with explicit immutable host inputs.
    /// Candidate code and candidate harnesses cannot alter this list.
    pub fn with_read_only_mounts(
        read_only_mounts: Vec<ReadOnlyMount>,
    ) -> Result<Self, SandboxError> {
        for mount in &read_only_mounts {
            Self::validate_mount(mount)?;
        }
        Ok(Self { read_only_mounts })
    }

    pub fn read_only_mounts(&self) -> &[ReadOnlyMount] {
        &self.read_only_mounts
    }

    fn executable() -> Result<PathBuf, SandboxError> {
        ["/usr/bin/bwrap", "/bin/bwrap"]
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .map(Path::to_path_buf)
            .ok_or(SandboxError::Unavailable)
    }

    fn prlimit_executable() -> Option<PathBuf> {
        ["/usr/bin/prlimit", "/bin/prlimit"]
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .map(Path::to_path_buf)
    }

    fn resource_limit_args(
        spec: &SandboxSpec,
    ) -> Result<Option<(PathBuf, Vec<OsString>)>, SandboxError> {
        let requested = spec.max_memory_bytes.is_some()
            || spec.max_file_size_bytes.is_some()
            || spec.max_processes.is_some()
            || spec.cpu_time_limit.is_some();
        if !requested {
            return Ok(None);
        }

        let prlimit = Self::prlimit_executable().ok_or_else(|| {
            SandboxError::PolicyViolation(
                "resource limits requested but prlimit is unavailable".into(),
            )
        })?;
        let mut args = Vec::new();
        if let Some(bytes) = spec.max_memory_bytes {
            args.push(format!("--as={bytes}:{bytes}").into());
        }
        if let Some(bytes) = spec.max_file_size_bytes {
            args.push(format!("--fsize={bytes}:{bytes}").into());
        }
        if let Some(processes) = spec.max_processes {
            args.push(format!("--nproc={processes}:{processes}").into());
        }
        if let Some(duration) = spec.cpu_time_limit {
            let seconds = duration
                .as_secs()
                .saturating_add(u64::from(duration.subsec_nanos() != 0))
                .max(1);
            args.push(format!("--cpu={seconds}:{seconds}").into());
        }
        Ok(Some((prlimit, args)))
    }

    fn validate_mount(mount: &ReadOnlyMount) -> Result<(), SandboxError> {
        if !mount.source.exists() {
            return Err(SandboxError::PolicyViolation(format!(
                "read-only mount source does not exist: {}",
                mount.source.display()
            )));
        }
        if !mount.target.is_absolute() {
            return Err(SandboxError::PolicyViolation(
                "read-only mount target must be absolute".into(),
            ));
        }
        let mut components = mount.target.components();
        if components.next() != Some(std::path::Component::RootDir)
            || !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(SandboxError::PolicyViolation(
                "read-only mount target must be one top-level sandbox path".into(),
            ));
        }
        let forbidden = [
            "/workspace",
            "/usr",
            "/bin",
            "/lib",
            "/lib64",
            "/proc",
            "/dev",
            "/tmp",
        ];
        if forbidden.iter().any(|path| mount.target == Path::new(path)) {
            return Err(SandboxError::PolicyViolation(format!(
                "read-only mount target is reserved: {}",
                mount.target.display()
            )));
        }
        Ok(())
    }
}

impl SandboxRunner for LinuxBubblewrap {
    fn run(&self, spec: &SandboxSpec) -> Result<SandboxOutput, SandboxError> {
        if spec.network != NetworkPolicy::Deny {
            return Err(SandboxError::PolicyViolation(
                "LoopbackOnly is not implemented; only NetworkPolicy::Deny is supported".into(),
            ));
        }
        if !spec.cwd.is_dir() || spec.writable_paths.iter().any(|p| !p.is_dir()) {
            return Err(SandboxError::PolicyViolation(
                "workspace paths must be directories".into(),
            ));
        }
        if spec.writable_paths.len() != 1 {
            return Err(SandboxError::PolicyViolation(
                "exactly one writable workspace path is required".into(),
            ));
        }
        let workspace = &spec.writable_paths[0];
        let canonical_cwd = spec.cwd.canonicalize().map_err(|error| {
            SandboxError::PolicyViolation(format!("cannot canonicalize cwd: {error}"))
        })?;
        let canonical_workspace = workspace.canonicalize().map_err(|error| {
            SandboxError::PolicyViolation(format!("cannot canonicalize workspace: {error}"))
        })?;
        if canonical_cwd != canonical_workspace {
            return Err(SandboxError::PolicyViolation(
                "sandbox cwd must equal the single writable workspace".into(),
            ));
        }
        for mount in &self.read_only_mounts {
            Self::validate_mount(mount)?;
        }

        let bwrap = Self::executable()?;
        let resource_limits = Self::resource_limit_args(spec)?;
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
        cmd.args(["--bind"])
            .arg(workspace)
            .args(["/workspace"]);
        for mount in &self.read_only_mounts {
            cmd.arg("--ro-bind").arg(&mount.source).arg(&mount.target);
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
        cmd.arg("--");
        if let Some((prlimit, limit_args)) = resource_limits {
            cmd.arg(prlimit).args(limit_args).arg("--");
        }
        cmd.arg(&spec.program)
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
        let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
        let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = out.take((cap + 1) as u64).read_to_end(&mut bytes);
            let _ = stdout_tx.send(bytes);
        });
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = err.take((cap + 1) as u64).read_to_end(&mut bytes);
            let _ = stderr_tx.send(bytes);
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
        let capture_deadline = spec.termination_grace + Duration::from_secs(1);
        let stdout = stdout_rx.recv_timeout(capture_deadline).unwrap_or_default();
        let stderr = stderr_rx.recv_timeout(capture_deadline).unwrap_or_default();
        let truncated = stdout.len() > cap || stderr.len() > cap;
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
            stdout: stdout.into_iter().take(cap).collect(),
            stderr: stderr.into_iter().take(cap).collect(),
            timed_out: timed,
            output_truncated: truncated,
        })
    }
}

pub fn run(spec: &SandboxSpec) -> Result<SandboxOutput, SandboxError> {
    LinuxBubblewrap::default().run(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_spec(cwd: PathBuf) -> SandboxSpec {
        SandboxSpec {
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
        }
    }

    #[test]
    fn unavailable_is_fail_closed() {
        let spec = base_spec(std::env::temp_dir());
        match run(&spec) {
            Ok(out) => assert_eq!(out.status, SandboxExit::Success),
            Err(SandboxError::Unavailable) => {}
            Err(e) => panic!("unexpected sandbox error: {e:?}"),
        }
    }

    #[test]
    fn loopback_policy_is_not_silently_treated_as_deny() {
        let mut spec = base_spec(std::env::temp_dir());
        spec.network = NetworkPolicy::LoopbackOnly;
        assert!(matches!(
            LinuxBubblewrap::default().run(&spec),
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[test]
    fn writable_workspace_is_unambiguous() {
        let mut spec = base_spec(std::env::temp_dir());
        spec.writable_paths.clear();
        assert!(matches!(
            LinuxBubblewrap::default().run(&spec),
            Err(SandboxError::PolicyViolation(_))
        ));
        spec.writable_paths = vec![std::env::temp_dir(), std::env::temp_dir()];
        assert!(matches!(
            LinuxBubblewrap::default().run(&spec),
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[test]
    fn reserved_readonly_mount_target_is_rejected() {
        let mount = ReadOnlyMount::new(std::env::temp_dir(), "/workspace");
        assert!(matches!(
            LinuxBubblewrap::with_read_only_mounts(vec![mount]),
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[test]
    fn top_level_readonly_mount_is_runner_owned() {
        let mount = ReadOnlyMount::new(std::env::temp_dir(), "/rust-toolchain");
        let runner = LinuxBubblewrap::with_read_only_mounts(vec![mount.clone()]).unwrap();
        assert_eq!(runner.read_only_mounts(), &[mount]);
    }

    #[test]
    fn requested_limits_are_translated_without_shell_parsing() {
        let mut spec = base_spec(std::env::temp_dir());
        spec.max_memory_bytes = Some(64 * 1024 * 1024);
        spec.max_file_size_bytes = Some(1024 * 1024);
        spec.max_processes = Some(8);
        spec.cpu_time_limit = Some(Duration::from_millis(1500));

        match LinuxBubblewrap::resource_limit_args(&spec) {
            Ok(Some((_program, args))) => {
                let args: Vec<String> = args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect();
                assert!(args.contains(&"--as=67108864:67108864".to_string()));
                assert!(args.contains(&"--fsize=1048576:1048576".to_string()));
                assert!(args.contains(&"--nproc=8:8".to_string()));
                assert!(args.contains(&"--cpu=2:2".to_string()));
            }
            Ok(None) => panic!("limits unexpectedly omitted"),
            Err(SandboxError::PolicyViolation(_)) => {
                // Minimal platforms may legitimately lack prlimit. The runtime
                // behavior is fail-closed in that case.
            }
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }
}