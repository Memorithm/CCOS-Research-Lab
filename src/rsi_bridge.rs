//! **RSI bridge** (CCOS_EXTENDED, plan P3) — the CCOS-side half of the RSI
//! circular-dependency inversion, plus the hard-sandboxed Darwin–Gödel (DGM)
//! self-improvement loop.
//!
//! Before P3, the `rsi` crate had an optional git dependency on CCOS and a
//! `ccos_audit::CcosAudit` adapter (rsi's `AuditLog` over CCOS's hash-chained
//! `EventLog`). That edge pointed `rsi → ccos`, circular once `rsi` became a
//! workspace member of the `ccos` workspace. P3 **inverts** it: the adapter now
//! lives here, on the CCOS side, so CCOS depends on `rsi` and `rsi` no longer
//! depends on CCOS at all (`cargo tree -p rsi | grep ccos` is empty).
//!
//! What this module exposes (behind the `rsi` cargo feature, runtime-gated by the
//! offline license):
//!
//! - [`CcosAudit`] — the moved adapter: rsi's [`AuditLog`] over
//!   CCOS's hash-chained [`EventLog`]. Every RSI step
//!   the agent records becomes a tamper-evident CCOS event.
//! - [`RsiAccess`] — the Pro gate for running an RSI agent with CCOS audit
//!   ([`Feature::RsiSelfImprovement`]).
//! - [`DgmAccess`] — the Pro gate for the DGM self-improvement loop
//!   ([`Feature::RsiDgm`]).
//! - [`GuardedDgm`] — a **hard-sandbox** wrapper around `rsi::dgm::DgmEngine`:
//!   an editable-file allowlist enforced at the proposer (a patch to a
//!   non-allowlisted target is refused before any evaluation), every evaluated
//!   step recorded in CCOS's hash-chain `EventLog`, and every accepted patch
//!   *promoted to the live tree* only through a re-checked allowlist + a recorded
//!   `GraphMutation` event. The evaluation itself runs in rsi's `WorkspaceSnapshot`
//!   (an isolated temp copy, `Drop`-cleaned) with bounded time + output; the
//!   bridge's [`GuardedCargoEvaluator`] additionally pins cargo to `--offline
//!   --frozen` (`CARGO_NET_OFFLINE=true`) so the air-gap posture holds — no
//!   network egress during a build/test cycle.
//!
//! ## Security posture (sécurité absolue)
//!
//! - **No execution of non-allowlisted code.** The editable-file allowlist is the
//!   primary control: a patch whose `target` is not on the list never reaches the
//!   evaluator, never reaches the live tree.
//! - **No silent mutation.** `promote_to_live` is the single live-tree writer; the
//!   bridge calls it only for accepted, allowlisted patches and records a
//!   `GraphMutation` event for each.
//! - **Air-gap.** `GuardedCargoEvaluator` runs cargo `--offline --frozen` with
//!   `CARGO_NET_OFFLINE=true`; the proposer/evaluator never make network calls.
//! - **Replay boundary.** The deterministic RSI core (`RSIAgent::demo`,
//!   `DgmEngine` with a deterministic proposer/evaluator and a fixed seed) is
//!   bit-replayable; an LLM proposer or a neural embedder is the documented
//!   relax, visible in the type and never the default. The default CCOS build
//!   compiles none of this (`rsi` feature off).

#![cfg(feature = "rsi")]

use std::path::{Path, PathBuf};

use crate::event_log::{EventLog, EventPayload, EventType};
use crate::guard::{GuardLayer, GuardResult};
use crate::license::{Feature, LicenseError, Licensing};
use rsi::audit::{AuditEvent, AuditLog};
use rsi::dgm::{
    promote_to_live, Archive, DgmConfig, DgmEngine, Evaluator, Fitness, ImprovementContext,
    Proposal, Proposer, StepOutcome,
};
use rsi::Rng;

// ── CcosAudit — the moved adapter (rsi AuditLog → CCOS EventLog) ─────────────

/// rsi's [`AuditLog`] backed by CCOS's hash-chained
/// [`EventLog`]. Each `record` appends a
/// `Custom { key: "rsi_step", value: <canonical payload> }` event of type
/// `AgentAction`; the returned string is the chain head after the append (the
/// tamper-evident link hash). This is the CCOS-side replacement for rsi's former
/// `ccos_audit::CcosAudit` (the P3 circular-dep inversion).
pub struct CcosAudit {
    log: EventLog,
}

impl CcosAudit {
    /// New audit sink rooted at a fresh `EventLog` with the given session id.
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            log: EventLog::new(session_id.into()),
        }
    }

    /// Borrow the underlying CCOS event log (e.g. to `verify_integrity` or dump).
    pub fn event_log(&self) -> &EventLog {
        &self.log
    }
}

impl AuditLog for CcosAudit {
    fn record(&mut self, event: &AuditEvent) -> String {
        // `EventLog::append` returns the random event *id* (a UUID), but the
        // `AuditLog::record` contract is "renvoie le nouveau hash de tête" — the
        // tamper-evident chain head. Append (which links the event into the hash
        // chain), then return the resulting chain head.
        self.log.append(
            EventType::AgentAction,
            EventPayload::Custom {
                key: "rsi_step".to_string(),
                value: event.payload(),
            },
        );
        self.log.chain_head()
    }

    fn len(&self) -> usize {
        self.log.event_count()
    }

    fn head(&self) -> String {
        self.log.chain_head()
    }

    fn verify(&self) -> bool {
        self.log.verify_integrity().valid
    }
}

impl std::fmt::Debug for CcosAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CcosAudit")
            .field("events", &self.log.event_count())
            .field("head", &self.log.chain_head())
            .finish()
    }
}

// ── License gates ────────────────────────────────────────────────────────────

/// Premium construction token for the RSI agent tier (running an `RSIAgent` with
/// CCOS audit). Only [`RsiAccess::unlock`] produces it, and only on the Pro tier.
pub struct RsiAccess {
    _gated: (),
}

impl std::fmt::Debug for RsiAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsiAccess").finish()
    }
}

impl RsiAccess {
    /// Unlock the RSI agent tier from CCOS's `licensing` at `now`. `Ok` only on
    /// the Pro tier; otherwise the standard [`Feature::RsiSelfImprovement`]
    /// refusal (the core is unaffected). Pure, no I/O.
    pub fn unlock(licensing: &Licensing, now: u64) -> Result<Self, LicenseError> {
        licensing.require(Feature::RsiSelfImprovement, now)?;
        Ok(Self { _gated: () })
    }

    /// Build a [`CcosAudit`] reachable only behind [`Self::unlock`]. The returned
    /// sink is `Box<dyn AuditLog>` so it plugs straight into
    /// `RSIAgent::with_audit`.
    pub fn audit(&self, session_id: impl Into<String>) -> Box<dyn AuditLog> {
        Box::new(CcosAudit::new(session_id))
    }
}

/// Premium construction token for the DGM self-improvement loop tier. Only
/// [`DgmAccess::unlock`] produces it, and only on the Pro tier.
pub struct DgmAccess {
    _gated: (),
}

impl std::fmt::Debug for DgmAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DgmAccess").finish()
    }
}

impl DgmAccess {
    /// Unlock the DGM tier from CCOS's `licensing` at `now`. `Ok` only on the
    /// Pro tier; otherwise the standard [`Feature::RsiDgm`] refusal. Pure, no I/O.
    pub fn unlock(licensing: &Licensing, now: u64) -> Result<Self, LicenseError> {
        licensing.require(Feature::RsiDgm, now)?;
        Ok(Self { _gated: () })
    }

    /// Assemble a [`GuardedDgm`] over a proposer + evaluator, sized for the given
    /// config. Reachable only behind [`Self::unlock`]. The editable-file
    /// allowlist is the primary security control; `guard` sanitizes LLM proposer
    /// output when the proposer is LLM-backed (see [`GuardedProposer`]).
    // Deliberately takes every sandbox ingredient explicitly (no builder): the
    // caller must SEE the allowlist, the guard and the seed at the call site —
    // that visibility is part of the DGM security contract.
    #[allow(clippy::too_many_arguments)]
    pub fn guarded_dgm<P: Proposer, E: Evaluator>(
        &self,
        archive: Archive,
        proposer: P,
        evaluator: E,
        config: DgmConfig,
        seed: u64,
        sandbox: GuardedDgmConfig,
        guard: GuardLayer,
    ) -> GuardedDgm<P, E> {
        GuardedDgm::new(archive, proposer, evaluator, config, seed, sandbox, guard)
    }
}

// ── Hard-sandbox DGM wrapper ─────────────────────────────────────────────────

/// Configuration for the [`GuardedDgm`] hard sandbox.
#[derive(Debug, Clone)]
pub struct GuardedDgmConfig {
    /// Editable-file allowlist: a patch whose `target` (relative path) is not in
    /// this set is refused before evaluation and never reaches the live tree.
    /// This is the primary security control.
    pub editable_allowlist: Vec<String>,
    /// Directory for `promote_to_live`'s `.rsi_backups` (originals before patch).
    /// Defaults to `<workspace_root>/.rsi_backups`.
    pub backup_dir: Option<PathBuf>,
}

impl GuardedDgmConfig {
    /// Whether `target` (a relative patch target) is on the editable allowlist.
    /// Normalised: a leading `./` is stripped; the comparison is exact.
    pub fn is_editable(&self, target: &str) -> bool {
        let t = target.trim_start_matches("./");
        self.editable_allowlist
            .iter()
            .any(|a| a.trim_start_matches("./") == t)
    }

    pub fn backup_dir_or(&self, workspace_root: &Path) -> PathBuf {
        self.backup_dir
            .clone()
            .unwrap_or_else(|| workspace_root.join(".rsi_backups"))
    }
}

/// A [`Proposer`] wrapper that refuses proposals whose `target` is not on the
/// editable-file allowlist, and routes the inner proposer's raw `rationale`
/// through a CCOS [`GuardLayer`] (so an LLM proposer's output is sanitized before
/// it is logged). The patch itself is structurally carried through unchanged —
/// the allowlist is the control, not a content rewrite.
pub struct GuardedProposer<P: Proposer> {
    inner: P,
    sandbox: GuardedDgmConfig,
    guard: GuardLayer,
}

impl<P: Proposer> GuardedProposer<P> {
    pub fn new(inner: P, sandbox: GuardedDgmConfig, guard: GuardLayer) -> Self {
        Self {
            inner,
            sandbox,
            guard,
        }
    }
}

impl<P: Proposer> Proposer for GuardedProposer<P> {
    fn propose(
        &self,
        ctx: &ImprovementContext<'_>,
        rng: &mut Rng,
    ) -> rsi::dgm::Result<Option<Proposal>> {
        match self.inner.propose(ctx, rng)? {
            Some(mut p) => {
                if !self.sandbox.is_editable(&p.patch.target) {
                    // Refused: a patch to a non-allowlisted target must never be
                    // evaluated or promoted. Surface as a proposer error so the
                    // engine treats this step as a no-op rather than a crash.
                    return Err(rsi::dgm::DgmError::PathNotAllowed(p.patch.target.clone()));
                }
                // Sanitize the rationale (LLM output) through the GuardLayer; the
                // patch body is carried unchanged (the allowlist + unique-match
                // requirement are the structural controls).
                let gr: GuardResult = self.guard.validate_and_sanitize(&p.rationale);
                p.rationale = gr.sanitized_output;
                Ok(Some(p))
            }
            None => Ok(None),
        }
    }
}

/// A hard-sandboxed Darwin–Gödel Machine loop. Wraps a `DgmEngine` whose proposer
/// is [`GuardedProposer`] (editable allowlist + GuardLayer) and records every
/// evaluated step in a CCOS [`EventLog`]. Accepted patches are promoted to the
/// live tree only through a re-checked allowlist + a recorded `GraphMutation`
/// event.
pub struct GuardedDgm<P: Proposer, E: Evaluator> {
    engine: DgmEngine<GuardedProposer<P>, E>,
    sandbox: GuardedDgmConfig,
    guard: GuardLayer,
    /// The live workspace root, captured at construction from
    /// `DgmConfig.workspace_root` (pub, `dgm.rs`). `DgmEngine` keeps its own
    /// `config` private with no accessor, so the wrapper holds the root it needs
    /// for `promote_to_live` and the backup dir — this is the applied fix for the
    /// `unreachable!()` stub the bridge shipped with pre-wiring.
    live_root: PathBuf,
}

/// The audited outcome of a guarded step.
#[derive(Debug, Clone)]
pub struct GuardedStepOutcome {
    /// The underlying DGM step outcome.
    pub outcome: StepOutcome,
    /// Whether the accepted patch was promoted to the live tree.
    pub promoted: bool,
    /// The CCOS event-log head after recording this step (tamper-evident link).
    pub audit_head: String,
}

impl<P: Proposer, E: Evaluator> GuardedDgm<P, E> {
    /// Assemble a guarded DGM. The `proposer` is wrapped in a [`GuardedProposer`]
    /// enforcing `sandbox.editable_allowlist`; the `evaluator` runs in rsi's
    /// isolated `WorkspaceSnapshot` (use [`GuardedCargoEvaluator`] for the
    /// air-gapped real cargo path, or `ClosureEvaluator` for tests).
    pub fn new(
        archive: Archive,
        proposer: P,
        evaluator: E,
        config: DgmConfig,
        seed: u64,
        sandbox: GuardedDgmConfig,
        guard: GuardLayer,
    ) -> Self {
        let gp = GuardedProposer::new(proposer, sandbox.clone(), guard.clone());
        let live_root = config.workspace_root.clone();
        let engine = DgmEngine::new(archive, gp, evaluator, config, seed);
        Self {
            engine,
            sandbox,
            guard,
            live_root,
        }
    }

    /// Read-only access to the underlying engine's archive.
    pub fn archive(&self) -> &Archive {
        self.engine.archive()
    }

    /// Run one guarded DGM step, recording it in `audit` (a CCOS `EventLog`).
    /// On an accepted, allowlisted patch, promote it to the live tree and record
    /// the live-tree `GraphMutation`. Every step — accepted or not, promoted or
    /// not — is then recorded as a canonical `SelfModify` / `RsiMutation` event
    /// in the tamper-evident timeline. Returns the audited outcome.
    pub fn run_step(&mut self, audit: &mut EventLog) -> rsi::dgm::Result<GuardedStepOutcome> {
        let live_root = self.live_root.clone();
        let outcome = self.engine.step()?;
        let mut promoted = false;

        if let StepOutcome::Evaluated {
            accepted: true,
            variant_id,
            ..
        } = &outcome
        {
            if let Some(variant) = self.engine.archive().get(variant_id) {
                let patch = &variant.patch;
                // Re-check the allowlist before the live-tree mutation (defence
                // in depth: the proposer already refused non-allowlisted targets,
                // but a promote path must never bypass it).
                if self.sandbox.is_editable(&patch.target) && !patch.is_noop() {
                    let backup_dir = self.sandbox.backup_dir_or(&live_root);
                    match promote_to_live(&live_root, patch, &backup_dir) {
                        Ok(backup_id) => {
                            promoted = true;
                            // The live-tree write is a graph mutation; the backup id
                            // rides in `operation` so the promote is fully traceable.
                            audit.append(
                                EventType::GraphMutation,
                                EventPayload::GraphMutation {
                                    node_id: variant_id.clone(),
                                    operation: format!("rsi_dgm_promote:{backup_id}"),
                                    nodes_before: 0,
                                    nodes_after: 1,
                                    edges_before: 0,
                                    edges_after: 0,
                                },
                            );
                        }
                        Err(e) => {
                            // Record the refused promote as a Custom event — never silent.
                            audit.append(
                                EventType::AgentAction,
                                EventPayload::Custom {
                                    key: "rsi_dgm_promote_refused".to_string(),
                                    value: format!("target={};err={}", patch.target, e),
                                },
                            );
                        }
                    }
                } else if !patch.is_noop() {
                    audit.append(
                        EventType::AgentAction,
                        EventPayload::Custom {
                            key: "rsi_dgm_promote_blocked_allowlist".to_string(),
                            value: patch.target.clone(),
                        },
                    );
                }
            }
        }

        // The canonical tamper-evident record of this DGM step: a SelfModify
        // event carrying the structured RsiMutation payload (patch hashes +
        // fitness primitives + accepted/promoted flags). Fitness is captured as
        // primitives so `event_log` (default build) never depends on `ccos-rsi`.
        let (
            variant_id,
            parent_id,
            patch_target,
            patch_find_hash,
            patch_replace_hash,
            compiles,
            tests_passed,
            tests_failed,
            score,
            accepted,
        ) = match &outcome {
            StepOutcome::Evaluated {
                variant_id,
                parent_id,
                accepted,
                fitness,
            } => {
                let (target, find_h, repl_h) = self
                    .engine
                    .archive()
                    .get(variant_id)
                    .map(|v| {
                        let p = &v.patch;
                        (
                            p.target.clone(),
                            crate::util::sha256_hex(&p.find),
                            crate::util::sha256_hex(&p.replace),
                        )
                    })
                    .unwrap_or_else(|| (String::new(), String::new(), String::new()));
                (
                    variant_id.clone(),
                    parent_id.clone().unwrap_or_default(),
                    target,
                    find_h,
                    repl_h,
                    fitness.compiles,
                    fitness.tests_passed,
                    fitness.tests_failed,
                    fitness.score,
                    *accepted,
                )
            }
            StepOutcome::NoProposal => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                false,
                0,
                0,
                f64::NEG_INFINITY,
                false,
            ),
        };
        let audit_head = audit.append(
            EventType::SelfModify,
            EventPayload::RsiMutation {
                variant_id,
                parent_id,
                patch_target,
                patch_find_hash,
                patch_replace_hash,
                compiles,
                tests_passed,
                tests_failed,
                score,
                accepted,
                promoted,
            },
        );

        Ok(GuardedStepOutcome {
            outcome,
            promoted,
            audit_head,
        })
    }

    /// Borrow the guard (for inspection / tests).
    pub fn guard(&self) -> &GuardLayer {
        &self.guard
    }

    /// Borrow the sandbox config.
    pub fn sandbox(&self) -> &GuardedDgmConfig {
        &self.sandbox
    }
}

// ── Air-gapped cargo evaluator ──────────────────────────────────────────────

/// An [`Evaluator`] that runs `cargo build --offline --frozen --quiet` then
/// `cargo test --offline --quiet [test_args]` in the isolated snapshot, with
/// `CARGO_NET_OFFLINE=true` set so the air-gap posture holds (no registry fetch,
/// no network egress during the build/test cycle). Bounded by `timeout` and
/// `max_output` bytes per stream (mirrors rsi's `CargoEvaluator::run_bounded`).
///
/// This is the real-system evaluator for the guarded DGM. For deterministic
/// offline tests, use `rsi::dgm::ClosureEvaluator` instead (no cargo, no network).
pub struct GuardedCargoEvaluator {
    pub package_subdir: PathBuf,
    pub test_args: Vec<String>,
    pub timeout: std::time::Duration,
    pub max_output: u64,
}

impl Default for GuardedCargoEvaluator {
    fn default() -> Self {
        Self {
            package_subdir: PathBuf::new(),
            test_args: Vec::new(),
            timeout: std::time::Duration::from_secs(300),
            max_output: 4 * 1024 * 1024,
        }
    }
}

impl Evaluator for GuardedCargoEvaluator {
    fn evaluate(&self, workspace: &Path) -> rsi::dgm::Result<Fitness> {
        let cwd = workspace.join(&self.package_subdir);
        // Build: --offline --frozen ⇒ no registry fetch, no network egress.
        let mut build = std::process::Command::new("cargo");
        build
            .args(["build", "--offline", "--frozen", "--quiet"])
            .current_dir(&cwd)
            .env("CARGO_NET_OFFLINE", "true")
            .stdin(std::process::Stdio::null());
        let (build_ok, _build_out) = run_bounded(build, self.timeout, self.max_output)?;
        if !build_ok {
            return Ok(Fitness::broken("cargo build failed (offline/frozen)"));
        }

        // Test: --offline --frozen ⇒ air-gapped test run.
        let mut test = std::process::Command::new("cargo");
        test.args(["test", "--offline", "--frozen", "--quiet"])
            .args(&self.test_args)
            .current_dir(&cwd)
            .env("CARGO_NET_OFFLINE", "true")
            .stdin(std::process::Stdio::null());
        let (test_ok, test_out) = run_bounded(test, self.timeout, self.max_output)?;
        let (passed, failed) = parse_test_counts(&test_out);
        let compiles = build_ok && test_ok;
        Ok(Fitness {
            compiles,
            tests_passed: passed,
            tests_failed: failed,
            score: if passed + failed == 0 {
                0.0
            } else {
                passed as f64 / (passed + failed) as f64
            },
            notes: if test_ok {
                String::new()
            } else {
                "cargo test failed (offline/frozen)".to_string()
            },
        })
    }
}

/// Run `cmd` with a deadline + per-stream byte cap, mirroring rsi's
/// `run_bounded`. Returns `(success, combined_output)`. `success` is false on
/// timeout or non-zero exit. No CPU/RSS cap (the snapshot isolation + time/output
/// bounds are the controls here; a stronger jail is a host concern).
fn run_bounded(
    mut cmd: std::process::Command,
    timeout: std::time::Duration,
    max_output: u64,
) -> rsi::dgm::Result<(bool, String)> {
    use std::io::Read;
    let per_stream = (max_output / 2).max(1) as usize;
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| rsi::dgm::DgmError::Io(e.to_string()))?;
    let deadline = std::time::Instant::now() + timeout;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out_h = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout
            .by_ref()
            .take(per_stream as u64)
            .read_to_string(&mut s);
        s
    });
    let err_h = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr
            .by_ref()
            .take(per_stream as u64)
            .read_to_string(&mut s);
        s
    });
    loop {
        match child
            .try_wait()
            .map_err(|e| rsi::dgm::DgmError::Io(e.to_string()))?
        {
            Some(status) => {
                let out = out_h.join().unwrap_or_default();
                let err = err_h.join().unwrap_or_default();
                let combined = format!("{out}\n{err}");
                return Ok((status.success(), combined));
            }
            None => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break; // timed out ⇒ fall through to the not-success return
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
    let out = out_h.join().unwrap_or_default();
    let err = err_h.join().unwrap_or_default();
    // Reached only via the deadline break ⇒ the run timed out (not a success).
    Ok((false, format!("{out}\n{err}")))
}

/// Sum the `N passed` / `N failed` counters of every `test result:` line in a
/// cargo-test output (one line per test binary). These counts feed the
/// tamper-evident `RsiMutation` audit payload, so they must reflect the real
/// harness output format: `test result: ok. 5 passed; 0 failed; …`.
fn parse_test_counts(output: &str) -> (u32, u32) {
    let mut passed = 0u32;
    let mut failed = 0u32;
    for line in output.lines() {
        let Some(rest) = line.trim_start().strip_prefix("test result:") else {
            continue;
        };
        // Tokens look like "ok. 5 passed" / "0 failed" / "finished in 0.06s";
        // splitting on '.' too isolates the leading status word.
        for tok in rest.split([';', '.']) {
            let tok = tok.trim();
            if let Some(n) = tok.strip_suffix(" passed") {
                passed += n.trim().parse::<u32>().unwrap_or(0);
            } else if let Some(n) = tok.strip_suffix(" failed") {
                failed += n.trim().parse::<u32>().unwrap_or(0);
            }
        }
    }
    (passed, failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::GuardConfig;
    use crate::license::License;
    use rsi::dgm::{ClosureEvaluator, DgmError, Patch};

    const NOW: u64 = 1_000;

    fn pro() -> Licensing {
        Licensing::licensed(License {
            licensee: "acme".to_string(),
            expires_at: None,
            machine: None,
        })
    }

    /// The counters that feed the tamper-evident `RsiMutation` payload must
    /// parse the REAL cargo-test harness format (`N passed`, not `passed N`),
    /// summed across test binaries, ignoring the `finished in 0.06s` tail.
    #[test]
    fn parse_test_counts_reads_real_cargo_output() {
        let out = "running 5 tests\n\
                   test a ... ok\n\
                   test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s\n\
                   running 3 tests\n\
                   test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.20s\n";
        assert_eq!(parse_test_counts(out), (6, 2));
        assert_eq!(parse_test_counts("no harness line here"), (0, 0));
    }

    #[test]
    fn community_tier_refuses_rsi_and_dgm() {
        let l = Licensing::community();
        assert_eq!(
            RsiAccess::unlock(&l, NOW).unwrap_err(),
            LicenseError::FeatureLocked(Feature::RsiSelfImprovement)
        );
        assert_eq!(
            DgmAccess::unlock(&l, NOW).unwrap_err(),
            LicenseError::FeatureLocked(Feature::RsiDgm)
        );
    }

    #[test]
    fn ccosaudit_records_into_ccos_hashchain_and_verifies() {
        let mut audit = CcosAudit::new("rsi-session");
        assert_eq!(audit.len(), 0);
        let ev = AuditEvent {
            t: 1,
            si_global: 0.5,
            si_safe: 0.4,
            risk_global: 0.1,
            max_rpn: 0.2,
            most_critical: "none",
            strategy_id: 42,
            p_eff: 0.8,
        };
        let head = audit.record(&ev);
        assert!(!head.is_empty());
        assert_eq!(audit.len(), 1);
        assert_eq!(audit.head(), head);
        assert!(audit.verify());
        assert!(audit.event_log().verify_integrity().valid);
    }

    #[test]
    fn pro_unlocks_rsi_audit() {
        let access = RsiAccess::unlock(&pro(), NOW).unwrap();
        let audit = access.audit("rsi-pro");
        assert_eq!(audit.len(), 0);
    }

    // ── DGM hard-sandbox tests (deterministic, no cargo/network) ─────────────

    /// A deterministic proposer that proposes a single fixed patch on the first
    /// call, then nothing. Uses `Cell` because `Proposer::propose` takes `&self`.
    struct OnceProposer {
        patch: Patch,
        fired: std::cell::Cell<bool>,
    }
    impl Proposer for OnceProposer {
        fn propose(
            &self,
            _ctx: &ImprovementContext<'_>,
            _rng: &mut Rng,
        ) -> rsi::dgm::Result<Option<Proposal>> {
            if self.fired.get() {
                return Ok(None);
            }
            self.fired.set(true);
            Ok(Some(Proposal {
                patch: self.patch.clone(),
                rationale: "test patch".to_string(),
            }))
        }
    }

    fn write_workspace(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    #[test]
    fn guarded_dgm_promotes_allowlisted_patch_and_records_to_eventlog() {
        let tmp = tempdir();
        let live = tmp.path();
        write_workspace(live, "src/lib.rs", "fn old() {}\n");

        let patch = Patch::new("src/lib.rs", "fn old() {}", "fn new() {}");
        let proposer = OnceProposer {
            patch,
            fired: std::cell::Cell::new(false),
        };
        // Evaluator: the patched snapshot is "all green".
        let evaluator = ClosureEvaluator::new(|_ws| Fitness {
            compiles: true,
            tests_passed: 1,
            tests_failed: 0,
            score: 0.5,
            notes: String::new(),
        });
        let archive = Archive::with_root(Fitness::broken("baseline"));
        let config = DgmConfig::new(live, "improve old fn");
        let sandbox = GuardedDgmConfig {
            editable_allowlist: vec!["src/lib.rs".to_string()],
            backup_dir: None,
        };
        let guard = GuardLayer::new(GuardConfig::default());
        let access = DgmAccess::unlock(&pro(), NOW).unwrap();
        let mut dgm = access.guarded_dgm(archive, proposer, evaluator, config, 7, sandbox, guard);
        let mut audit = EventLog::new("dgm-test".into());

        let g = dgm.run_step(&mut audit).unwrap();
        assert!(g.outcome.accepted(), "outcome: {:?}", g.outcome);
        assert!(g.promoted, "patch should have been promoted");
        // The live tree now has the new function body.
        let live_content = std::fs::read_to_string(live.join("src/lib.rs")).unwrap();
        assert!(live_content.contains("fn new() {}"), "live: {live_content}");
        assert!(!live_content.contains("fn old() {}"));
        // The audit log recorded the promote + the step.
        assert!(
            audit.event_count() >= 2,
            "event_count={}",
            audit.event_count()
        );
        assert!(audit.verify_integrity().valid);
    }

    #[test]
    fn guarded_dgm_refuses_non_allowlisted_target() {
        let tmp = tempdir();
        let live = tmp.path();
        write_workspace(live, "src/lib.rs", "fn old() {}\n");
        write_workspace(live, "src/secret.rs", "pub const KEY: &str = \"secret\";\n");

        // Proposer targets a NON-allowlisted file.
        let patch = Patch::new("src/secret.rs", "\"secret\"", "\"leaked\"");
        let proposer = OnceProposer {
            patch,
            fired: std::cell::Cell::new(false),
        };
        let evaluator = ClosureEvaluator::new(|_ws| Fitness {
            compiles: true,
            tests_passed: 1,
            tests_failed: 0,
            score: 0.5,
            notes: String::new(),
        });
        let archive = Archive::with_root(Fitness::broken("baseline"));
        let config = DgmConfig::new(live, "should not edit secret");
        let sandbox = GuardedDgmConfig {
            editable_allowlist: vec!["src/lib.rs".to_string()], // secret.rs NOT allowed
            backup_dir: None,
        };
        let guard = GuardLayer::new(GuardConfig::default());
        let access = DgmAccess::unlock(&pro(), NOW).unwrap();
        let mut dgm = access.guarded_dgm(archive, proposer, evaluator, config, 7, sandbox, guard);
        let mut audit = EventLog::new("dgm-test".into());

        // The proposer refuses the non-allowlisted target → step returns an error
        // (PathNotAllowed) surfaced by the GuardedProposer.
        let res = dgm.run_step(&mut audit);
        assert!(
            matches!(res, Err(DgmError::PathNotAllowed(_))),
            "expected PathNotAllowed, got {res:?}"
        );
        // The secret file is untouched.
        let secret = std::fs::read_to_string(live.join("src/secret.rs")).unwrap();
        assert!(secret.contains("secret"));
        assert!(!secret.contains("leaked"));
    }

    // Minimal temp dir helper (avoids pulling in a tempfile dep just for tests).
    struct TempDir(PathBuf);
    fn tempdir() -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "ccos-rsi-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
