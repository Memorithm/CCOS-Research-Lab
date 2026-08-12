//! Canonical candidate -> evaluation -> adoption protocol for the Research-Lab
//! self-improvement boundary.
//!
//! The protocol is intentionally independent from CCOS itself: RSI/Forge can
//! produce these receipts without creating a circular dependency.  The CCOS
//! side mirrors the fingerprints into its primary EventLog.

use std::ffi::OsString;
use std::path::PathBuf;

use ccos_sandbox::{
    NetworkPolicy, SandboxError, SandboxExit, SandboxOutput, SandboxRunner, SandboxSpec,
};

use crate::sha256::sha256;

pub const CANDIDATE_PROTOCOL_VERSION: u16 = 1;

fn digest_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_bool(out: &mut Vec<u8>, value: bool) {
    push_u8(out, u8::from(value));
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    push_u64(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn push_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            push_u8(out, 1);
            push_str(out, value);
        }
        None => push_u8(out, 0),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateOrigin {
    Forge,
    Rsi,
    SciRust,
    External,
}

impl CandidateOrigin {
    fn tag(self) -> u8 {
        match self {
            Self::Forge => 1,
            Self::Rsi => 2,
            Self::SciRust => 3,
            Self::External => 255,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateEnvelope {
    pub schema_version: u16,
    /// Content-addressed identity owned by this protocol.  It is independent of
    /// trial seed and lineage, so the same source in two trials keeps one id.
    pub candidate_id: String,
    /// Optional producer-native identity (for example Forge's u64 CandidateId).
    pub producer_candidate_id: Option<String>,
    pub parent_candidate_id: Option<String>,
    pub origin: CandidateOrigin,
    pub domain: String,
    pub source_sha256: String,
    pub proposal_sha256: Option<String>,
    pub trial_seed: u64,
}

impl CandidateEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn from_source(
        origin: CandidateOrigin,
        domain: impl Into<String>,
        source: &[u8],
        producer_candidate_id: Option<String>,
        parent_candidate_id: Option<String>,
        proposal_sha256: Option<String>,
        trial_seed: u64,
    ) -> Result<Self, CandidateProtocolError> {
        let domain = domain.into();
        if domain.trim().is_empty() {
            return Err(CandidateProtocolError::InvalidField("domain"));
        }
        let source_sha256 = digest_hex(source);
        let mut identity = b"memorithm.candidate.identity.v1\0".to_vec();
        push_u8(&mut identity, origin.tag());
        push_str(&mut identity, &domain);
        push_str(&mut identity, &source_sha256);
        let candidate_id = digest_hex(&identity);
        Ok(Self {
            schema_version: CANDIDATE_PROTOCOL_VERSION,
            candidate_id,
            producer_candidate_id,
            parent_candidate_id,
            origin,
            domain,
            source_sha256,
            proposal_sha256,
            trial_seed,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = b"memorithm.candidate-envelope.v1\0".to_vec();
        push_u16(&mut out, self.schema_version);
        push_str(&mut out, &self.candidate_id);
        push_opt_str(&mut out, self.producer_candidate_id.as_deref());
        push_opt_str(&mut out, self.parent_candidate_id.as_deref());
        push_u8(&mut out, self.origin.tag());
        push_str(&mut out, &self.domain);
        push_str(&mut out, &self.source_sha256);
        push_opt_str(&mut out, self.proposal_sha256.as_deref());
        push_u64(&mut out, self.trial_seed);
        out
    }

    pub fn fingerprint(&self) -> String {
        digest_hex(&self.canonical_bytes())
    }

    pub fn audit_payload(&self) -> String {
        format!(
            "schema={};candidate={};envelope={};source={};trial={}",
            self.schema_version,
            self.candidate_id,
            self.fingerprint(),
            self.source_sha256,
            self.trial_seed
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ObjectiveValue {
    pub name: String,
    pub value: f64,
    pub minimize: bool,
}

impl ObjectiveValue {
    pub fn new(
        name: impl Into<String>,
        value: f64,
        minimize: bool,
    ) -> Result<Self, CandidateProtocolError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(CandidateProtocolError::InvalidField("objective.name"));
        }
        if !value.is_finite() {
            return Err(CandidateProtocolError::NonFiniteObjective(name));
        }
        Ok(Self {
            name,
            value,
            minimize,
        })
    }

    fn append_canonical(&self, out: &mut Vec<u8>) {
        push_str(out, &self.name);
        push_u64(out, self.value.to_bits());
        push_bool(out, self.minimize);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationStatus {
    Succeeded,
    CandidateFailed,
    InfrastructureFailed,
}

impl EvaluationStatus {
    fn tag(self) -> u8 {
        match self {
            Self::Succeeded => 1,
            Self::CandidateFailed => 2,
            Self::InfrastructureFailed => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvaluationReceipt {
    pub schema_version: u16,
    pub candidate_fingerprint: String,
    pub evaluator_id: String,
    pub sandbox_policy_id: String,
    /// Fingerprint of SciRust's architecture-neutral ExecutionAttestation when
    /// that runtime participates in the evaluation.
    pub execution_profile_sha256: Option<String>,
    pub verifier_sha256: Option<String>,
    pub trial_seed: u64,
    pub status: EvaluationStatus,
    pub objectives: Vec<ObjectiveValue>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub timed_out: bool,
    pub output_truncated: bool,
    pub failure_reason: Option<String>,
}

impl EvaluationReceipt {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = b"memorithm.evaluation-receipt.v1\0".to_vec();
        push_u16(&mut out, self.schema_version);
        push_str(&mut out, &self.candidate_fingerprint);
        push_str(&mut out, &self.evaluator_id);
        push_str(&mut out, &self.sandbox_policy_id);
        push_opt_str(&mut out, self.execution_profile_sha256.as_deref());
        push_opt_str(&mut out, self.verifier_sha256.as_deref());
        push_u64(&mut out, self.trial_seed);
        push_u8(&mut out, self.status.tag());
        push_u64(&mut out, self.objectives.len() as u64);
        for objective in &self.objectives {
            objective.append_canonical(&mut out);
        }
        push_str(&mut out, &self.stdout_sha256);
        push_str(&mut out, &self.stderr_sha256);
        push_bool(&mut out, self.timed_out);
        push_bool(&mut out, self.output_truncated);
        push_opt_str(&mut out, self.failure_reason.as_deref());
        out
    }

    pub fn fingerprint(&self) -> String {
        digest_hex(&self.canonical_bytes())
    }

    pub fn audit_payload(&self) -> String {
        format!(
            "schema={};candidate_envelope={};evaluation={};status={};trial={}",
            self.schema_version,
            self.candidate_fingerprint,
            self.fingerprint(),
            self.status.tag(),
            self.trial_seed
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionDecision {
    Promote,
    Reject,
    Quarantine,
}

impl AdoptionDecision {
    fn tag(self) -> u8 {
        match self {
            Self::Promote => 1,
            Self::Reject => 2,
            Self::Quarantine => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptionReceipt {
    pub schema_version: u16,
    pub evaluation_fingerprint: String,
    pub policy_id: String,
    pub decision: AdoptionDecision,
    pub reason: String,
    pub previous_champion_id: Option<String>,
    pub promoted_artifact_sha256: Option<String>,
}

impl AdoptionReceipt {
    pub fn new(
        evaluation: &EvaluationReceipt,
        policy_id: impl Into<String>,
        decision: AdoptionDecision,
        reason: impl Into<String>,
        previous_champion_id: Option<String>,
        promoted_artifact_sha256: Option<String>,
    ) -> Result<Self, CandidateProtocolError> {
        let policy_id = policy_id.into();
        let reason = reason.into();
        if policy_id.trim().is_empty() {
            return Err(CandidateProtocolError::InvalidField("adoption.policy_id"));
        }
        if reason.trim().is_empty() {
            return Err(CandidateProtocolError::InvalidField("adoption.reason"));
        }
        Ok(Self {
            schema_version: CANDIDATE_PROTOCOL_VERSION,
            evaluation_fingerprint: evaluation.fingerprint(),
            policy_id,
            decision,
            reason,
            previous_champion_id,
            promoted_artifact_sha256,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = b"memorithm.adoption-receipt.v1\0".to_vec();
        push_u16(&mut out, self.schema_version);
        push_str(&mut out, &self.evaluation_fingerprint);
        push_str(&mut out, &self.policy_id);
        push_u8(&mut out, self.decision.tag());
        push_str(&mut out, &self.reason);
        push_opt_str(&mut out, self.previous_champion_id.as_deref());
        push_opt_str(&mut out, self.promoted_artifact_sha256.as_deref());
        out
    }

    pub fn fingerprint(&self) -> String {
        digest_hex(&self.canonical_bytes())
    }

    pub fn audit_payload(&self) -> String {
        format!(
            "schema={};evaluation={};adoption={};decision={};policy={}",
            self.schema_version,
            self.evaluation_fingerprint,
            self.fingerprint(),
            self.decision.tag(),
            digest_hex(self.policy_id.as_bytes())
        )
    }
}

#[derive(Debug)]
pub enum CandidateProtocolError {
    InvalidField(&'static str),
    NonFiniteObjective(String),
    PolicyViolation(String),
    Harness(String),
}

impl std::fmt::Display for CandidateProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CandidateProtocolError {}

/// Trusted harness output.  The candidate itself remains untrusted; the harness
/// selects the executable, arguments, workspace and stable evaluator identities.
#[derive(Clone, Debug)]
pub struct PreparedEvaluation {
    pub spec: SandboxSpec,
    pub evaluator_id: String,
    pub sandbox_policy_id: String,
    pub execution_profile_sha256: Option<String>,
    pub verifier_sha256: Option<String>,
}

pub trait CandidateHarness {
    fn prepare(
        &self,
        candidate: &CandidateEnvelope,
    ) -> Result<PreparedEvaluation, CandidateProtocolError>;

    fn parse_objectives(
        &self,
        candidate: &CandidateEnvelope,
        output: &SandboxOutput,
    ) -> Result<Vec<ObjectiveValue>, CandidateProtocolError>;
}

/// Executes a prepared candidate only through `ccos-sandbox`.  There is no
/// direct-process fallback.  Network access is additionally required to be
/// `Deny` at this higher-level boundary so a permissive harness fails closed.
pub struct GuardedCandidateEvaluator<R> {
    runner: R,
}

impl<R> GuardedCandidateEvaluator<R>
where
    R: SandboxRunner,
{
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn evaluate<H: CandidateHarness>(
        &self,
        candidate: &CandidateEnvelope,
        harness: &H,
    ) -> Result<EvaluationReceipt, CandidateProtocolError> {
        let prepared = harness.prepare(candidate)?;
        if prepared.evaluator_id.trim().is_empty() {
            return Err(CandidateProtocolError::InvalidField("evaluator_id"));
        }
        if prepared.sandbox_policy_id.trim().is_empty() {
            return Err(CandidateProtocolError::InvalidField("sandbox_policy_id"));
        }
        if prepared.spec.network != NetworkPolicy::Deny {
            return Err(CandidateProtocolError::PolicyViolation(
                "generated candidate evaluation must deny network access".into(),
            ));
        }

        match self.runner.run(&prepared.spec) {
            Ok(output) => self.receipt_from_output(candidate, harness, prepared, output),
            Err(error) => Ok(self.infrastructure_failure(candidate, prepared, error)),
        }
    }

    fn receipt_from_output<H: CandidateHarness>(
        &self,
        candidate: &CandidateEnvelope,
        harness: &H,
        prepared: PreparedEvaluation,
        output: SandboxOutput,
    ) -> Result<EvaluationReceipt, CandidateProtocolError> {
        let process_succeeded = output.status == SandboxExit::Success && !output.timed_out;
        let (status, objectives, failure_reason) = if process_succeeded {
            match harness.parse_objectives(candidate, &output) {
                Ok(objectives) => {
                    if objectives.iter().any(|objective| !objective.value.is_finite()) {
                        return Err(CandidateProtocolError::PolicyViolation(
                            "harness returned a non-finite objective".into(),
                        ));
                    }
                    (EvaluationStatus::Succeeded, objectives, None)
                }
                Err(error) => (
                    EvaluationStatus::CandidateFailed,
                    Vec::new(),
                    Some(error.to_string()),
                ),
            }
        } else {
            (
                EvaluationStatus::CandidateFailed,
                Vec::new(),
                Some(if output.timed_out {
                    "candidate timed out".to_string()
                } else {
                    format!("candidate process exited as {:?}", output.status)
                }),
            )
        };

        Ok(EvaluationReceipt {
            schema_version: CANDIDATE_PROTOCOL_VERSION,
            candidate_fingerprint: candidate.fingerprint(),
            evaluator_id: prepared.evaluator_id,
            sandbox_policy_id: prepared.sandbox_policy_id,
            execution_profile_sha256: prepared.execution_profile_sha256,
            verifier_sha256: prepared.verifier_sha256,
            trial_seed: candidate.trial_seed,
            status,
            objectives,
            stdout_sha256: digest_hex(&output.stdout),
            stderr_sha256: digest_hex(&output.stderr),
            timed_out: output.timed_out,
            output_truncated: output.output_truncated,
            failure_reason,
        })
    }

    fn infrastructure_failure(
        &self,
        candidate: &CandidateEnvelope,
        prepared: PreparedEvaluation,
        error: SandboxError,
    ) -> EvaluationReceipt {
        EvaluationReceipt {
            schema_version: CANDIDATE_PROTOCOL_VERSION,
            candidate_fingerprint: candidate.fingerprint(),
            evaluator_id: prepared.evaluator_id,
            sandbox_policy_id: prepared.sandbox_policy_id,
            execution_profile_sha256: prepared.execution_profile_sha256,
            verifier_sha256: prepared.verifier_sha256,
            trial_seed: candidate.trial_seed,
            status: EvaluationStatus::InfrastructureFailed,
            objectives: Vec::new(),
            stdout_sha256: digest_hex(&[]),
            stderr_sha256: digest_hex(&[]),
            timed_out: matches!(error, SandboxError::Timeout),
            output_truncated: false,
            failure_reason: Some(error.to_string()),
        }
    }
}

/// Helper for trusted command harnesses that already materialized a candidate
/// workspace.  It is deliberately data-only; callers still decide how stdout is
/// interpreted into typed objectives through `CandidateHarness`.
#[derive(Clone, Debug)]
pub struct CommandEvaluation {
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

#[cfg(feature = "forge")]
pub fn envelope_from_forge<C: forge_core::Candidate>(
    candidate: &C,
    domain: &str,
    parent_candidate_id: Option<String>,
    proposal_sha256: Option<String>,
    trial_seed: u64,
) -> Result<CandidateEnvelope, CandidateProtocolError> {
    let repr = candidate.repr();
    CandidateEnvelope::from_source(
        CandidateOrigin::Forge,
        domain,
        repr.as_bytes(),
        Some(candidate.id().to_string()),
        parent_candidate_id,
        proposal_sha256,
        trial_seed,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::*;

    #[derive(Clone, Copy)]
    struct FakeRunner {
        fail: bool,
    }

    impl SandboxRunner for FakeRunner {
        fn run(&self, _spec: &SandboxSpec) -> Result<SandboxOutput, SandboxError> {
            if self.fail {
                return Err(SandboxError::Unavailable);
            }
            Ok(SandboxOutput {
                status: SandboxExit::Success,
                stdout: b"ok".to_vec(),
                stderr: Vec::new(),
                timed_out: false,
                output_truncated: false,
            })
        }
    }

    struct Harness {
        network: NetworkPolicy,
    }

    impl CandidateHarness for Harness {
        fn prepare(
            &self,
            _candidate: &CandidateEnvelope,
        ) -> Result<PreparedEvaluation, CandidateProtocolError> {
            Ok(PreparedEvaluation {
                spec: SandboxSpec {
                    program: "/usr/bin/true".into(),
                    args: Vec::new(),
                    cwd: "/tmp".into(),
                    writable_paths: vec!["/tmp".into()],
                    environment: BTreeMap::new(),
                    timeout: Duration::from_secs(1),
                    termination_grace: Duration::from_millis(10),
                    max_output_bytes: 1024,
                    max_memory_bytes: Some(64 * 1024 * 1024),
                    max_file_size_bytes: Some(1024 * 1024),
                    max_processes: Some(8),
                    cpu_time_limit: Some(Duration::from_secs(1)),
                    network: self.network,
                },
                evaluator_id: "test-harness-v1".into(),
                sandbox_policy_id: "research-airgap-v1".into(),
                execution_profile_sha256: Some("a".repeat(64)),
                verifier_sha256: Some("b".repeat(64)),
            })
        }

        fn parse_objectives(
            &self,
            _candidate: &CandidateEnvelope,
            _output: &SandboxOutput,
        ) -> Result<Vec<ObjectiveValue>, CandidateProtocolError> {
            Ok(vec![ObjectiveValue::new("latency_ns", 12.0, true)?])
        }
    }

    fn candidate(seed: u64) -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "simd_gemm",
            b"fn kernel() {}",
            Some("42".into()),
            None,
            None,
            seed,
        )
        .unwrap()
    }

    #[test]
    fn candidate_identity_is_content_addressed_but_envelope_binds_trial() {
        let a = candidate(1);
        let b = candidate(2);
        assert_eq!(a.candidate_id, b.candidate_id);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn objective_rejects_non_finite_values() {
        assert!(ObjectiveValue::new("bad", f64::NAN, true).is_err());
        assert!(ObjectiveValue::new("bad", f64::INFINITY, true).is_err());
    }

    #[test]
    fn evaluator_requires_airgapped_network_policy() {
        let evaluator = GuardedCandidateEvaluator::new(FakeRunner { fail: false });
        let error = evaluator
            .evaluate(
                &candidate(7),
                &Harness {
                    network: NetworkPolicy::LoopbackOnly,
                },
            )
            .unwrap_err();
        assert!(matches!(error, CandidateProtocolError::PolicyViolation(_)));
    }

    #[test]
    fn successful_evaluation_produces_deterministic_sealed_receipt() {
        let evaluator = GuardedCandidateEvaluator::new(FakeRunner { fail: false });
        let harness = Harness {
            network: NetworkPolicy::Deny,
        };
        let a = evaluator.evaluate(&candidate(9), &harness).unwrap();
        let b = evaluator.evaluate(&candidate(9), &harness).unwrap();
        assert_eq!(a.status, EvaluationStatus::Succeeded);
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.objectives.len(), 1);
    }

    #[test]
    fn unavailable_sandbox_is_a_fail_closed_receipt() {
        let evaluator = GuardedCandidateEvaluator::new(FakeRunner { fail: true });
        let receipt = evaluator
            .evaluate(
                &candidate(11),
                &Harness {
                    network: NetworkPolicy::Deny,
                },
            )
            .unwrap();
        assert_eq!(receipt.status, EvaluationStatus::InfrastructureFailed);
        assert!(receipt.objectives.is_empty());
    }

    #[test]
    fn adoption_receipt_is_bound_to_evaluation() {
        let evaluator = GuardedCandidateEvaluator::new(FakeRunner { fail: false });
        let evaluation = evaluator
            .evaluate(
                &candidate(13),
                &Harness {
                    network: NetworkPolicy::Deny,
                },
            )
            .unwrap();
        let adoption = AdoptionReceipt::new(
            &evaluation,
            "champion-challenger-v1",
            AdoptionDecision::Promote,
            "holdout passed",
            Some("old".into()),
            Some("c".repeat(64)),
        )
        .unwrap();
        assert_eq!(adoption.evaluation_fingerprint, evaluation.fingerprint());
        assert_eq!(adoption.fingerprint().len(), 64);
    }
}
