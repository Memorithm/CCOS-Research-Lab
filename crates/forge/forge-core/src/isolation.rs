//! All generated-code execution goes through the shared fail-closed runner.
//!
//! The legacy helpers keep existing domains on the common Bubblewrap boundary.
//! New candidate-code paths should use [`HermeticRustInputs`] for compilation
//! and [`run_frozen_artifact`] for execution: trusted source/verifier/toolchain
//! inputs are read-only, build outputs are isolated in `/workspace`, and the
//! executed artifact is mounted read-only in a fresh sandbox.

use crate::error::{ForgeError, Result};
use ccos_sandbox::{
    run, HermeticRustPolicy, LinuxBubblewrap, NetworkPolicy, ReadOnlyMount, SandboxExit,
    SandboxRunner, SandboxSpec, HERMETIC_SOURCE_ROOT,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const MAX_CAPTURE_BYTES: u64 = 4 * 1024 * 1024;

fn output_to_text(out: ccos_sandbox::SandboxOutput) -> Result<String> {
    if out.timed_out {
        return Err(ForgeError::Evaluation(
            "sandbox timeout; descendants terminated".into(),
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status != SandboxExit::Success {
        return Err(ForgeError::Evaluation(format!(
            "sandbox command failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(text)
}

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
        network: NetworkPolicy::Deny,
    };
    let out = run(&spec).map_err(|e| ForgeError::Evaluation(format!("sandbox refused: {e}")))?;
    output_to_text(out)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermeticRustInputs {
    pub source_root: PathBuf,
    pub rust_toolchain_root: PathBuf,
    pub cargo_vendor_root: PathBuf,
    pub cargo_home_root: PathBuf,
}

impl HermeticRustInputs {
    pub fn new(
        source_root: impl Into<PathBuf>,
        rust_toolchain_root: impl Into<PathBuf>,
        cargo_vendor_root: impl Into<PathBuf>,
        cargo_home_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            source_root: source_root.into(),
            rust_toolchain_root: rust_toolchain_root.into(),
            cargo_vendor_root: cargo_vendor_root.into(),
            cargo_home_root: cargo_home_root.into(),
        }
    }

    fn policy(&self) -> HermeticRustPolicy {
        HermeticRustPolicy::new(
            &self.source_root,
            &self.rust_toolchain_root,
            &self.cargo_vendor_root,
            &self.cargo_home_root,
        )
    }
}

/// Compile/test/bench a trusted candidate snapshot with Cargo while all source,
/// verifier, toolchain, vendor and Cargo configuration inputs are immutable.
///
/// `cargo_args` are appended after the mandatory `--manifest-path`, `--offline`
/// and `--frozen` flags. Cargo's target directory is runner-pinned to
/// `/workspace/target`; callers cannot override it through the environment.
pub fn run_hermetic_cargo<I, S>(
    inputs: &HermeticRustInputs,
    build_workspace: &Path,
    cargo_args: I,
    timeout: Duration,
    max_memory_bytes: u64,
    max_file_size_bytes: u64,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    if !build_workspace.is_dir() {
        return Err(ForgeError::Evaluation(
            "hermetic build workspace is not a directory".into(),
        ));
    }
    let runner = inputs
        .policy()
        .runner()
        .map_err(|error| ForgeError::Evaluation(format!("sandbox policy refused: {error}")))?;
    let mut args = vec![
        "--manifest-path".into(),
        format!("{HERMETIC_SOURCE_ROOT}/Cargo.toml").into(),
        "--offline".into(),
        "--frozen".into(),
    ];
    args.extend(cargo_args.into_iter().map(Into::into));
    let spec = SandboxSpec {
        program: HermeticRustPolicy::cargo_program(),
        args,
        cwd: build_workspace.to_path_buf(),
        writable_paths: vec![build_workspace.to_path_buf()],
        environment: BTreeMap::new(),
        timeout,
        termination_grace: Duration::from_millis(250),
        max_output_bytes: MAX_CAPTURE_BYTES,
        max_memory_bytes: Some(max_memory_bytes),
        max_file_size_bytes: Some(max_file_size_bytes),
        max_processes: Some(64),
        cpu_time_limit: Some(timeout),
        network: NetworkPolicy::Deny,
    };
    let out = runner
        .run(&spec)
        .map_err(|error| ForgeError::Evaluation(format!("sandbox refused: {error}")))?;
    output_to_text(out)
}

/// Execute one already-built artifact from a read-only mount in a fresh sandbox.
///
/// The artifact's parent directory is mounted as `/artifact`; the writable
/// workspace is a distinct scratch directory. This means candidate code cannot
/// rewrite its source/verifier or replace the executable that was selected by
/// the trusted host before the process starts.
pub fn run_frozen_artifact(
    artifact: &Path,
    scratch_workspace: &Path,
    timeout: Duration,
    max_memory_bytes: u64,
    max_file_size_bytes: u64,
) -> Result<String> {
    if !artifact.is_file() {
        return Err(ForgeError::Evaluation(format!(
            "frozen artifact does not exist: {}",
            artifact.display()
        )));
    }
    if !scratch_workspace.is_dir() {
        return Err(ForgeError::Evaluation(
            "artifact scratch workspace is not a directory".into(),
        ));
    }
    let artifact_parent = artifact.parent().ok_or_else(|| {
        ForgeError::Evaluation("frozen artifact has no parent directory".into())
    })?;
    let file_name = artifact.file_name().ok_or_else(|| {
        ForgeError::Evaluation("frozen artifact has no file name".into())
    })?;
    let runner = LinuxBubblewrap::with_read_only_mounts(vec![ReadOnlyMount::new(
        artifact_parent,
        "/artifact",
    )])
    .map_err(|error| ForgeError::Evaluation(format!("artifact policy refused: {error}")))?;
    let spec = SandboxSpec {
        program: PathBuf::from("/artifact").join(file_name),
        args: Vec::new(),
        cwd: scratch_workspace.to_path_buf(),
        writable_paths: vec![scratch_workspace.to_path_buf()],
        environment: BTreeMap::new(),
        timeout,
        termination_grace: Duration::from_millis(250),
        max_output_bytes: MAX_CAPTURE_BYTES,
        max_memory_bytes: Some(max_memory_bytes),
        max_file_size_bytes: Some(max_file_size_bytes),
        max_processes: Some(16),
        cpu_time_limit: Some(timeout),
        network: NetworkPolicy::Deny,
    };
    let out = runner
        .run(&spec)
        .map_err(|error| ForgeError::Evaluation(format!("sandbox refused: {error}")))?;
    output_to_text(out)
}

pub fn run_with_timeout(cmd: Command, timeout: Duration) -> Result<String> {
    execute(cmd, timeout, MAX_CAPTURE_BYTES, None, None)
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
        MAX_CAPTURE_BYTES,
        Some(max_memory_bytes),
        Some(max_file_size_bytes),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermetic_inputs_preserve_four_distinct_trusted_roots() {
        let inputs = HermeticRustInputs::new("/src", "/toolchain", "/vendor", "/cargo-home");
        assert_eq!(inputs.source_root, PathBuf::from("/src"));
        assert_eq!(inputs.rust_toolchain_root, PathBuf::from("/toolchain"));
        assert_eq!(inputs.cargo_vendor_root, PathBuf::from("/vendor"));
        assert_eq!(inputs.cargo_home_root, PathBuf::from("/cargo-home"));
    }

    #[test]
    fn missing_frozen_artifact_fails_before_sandbox_spawn() {
        let scratch = std::env::temp_dir();
        let error = run_frozen_artifact(
            Path::new("/definitely/not/a/forge/artifact"),
            &scratch,
            Duration::from_secs(1),
            1024 * 1024,
            1024 * 1024,
        )
        .unwrap_err();
        assert!(format!("{error}").contains("frozen artifact does not exist"));
    }
}
