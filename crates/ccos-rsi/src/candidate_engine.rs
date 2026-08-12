//! Validated execution façade over the lower-level candidate harness API.
//!
//! CCOS-side code should depend on [`SealedCandidateEvaluator`], not on a raw
//! harness. The concrete sandbox adapter validates the candidate before running
//! anything and validates the returned receipt before releasing it upstream.

use ccos_sandbox::SandboxRunner;

use crate::candidate_policy::{validate_candidate, validate_evaluation};
use crate::candidate_protocol::{
    CandidateEnvelope, CandidateHarness, CandidateProtocolError, EvaluationReceipt,
    GuardedCandidateEvaluator,
};

pub trait SealedCandidateEvaluator {
    fn evaluate(
        &self,
        candidate: &CandidateEnvelope,
    ) -> Result<EvaluationReceipt, CandidateProtocolError>;
}

pub struct SandboxCandidateEvaluator<R, H> {
    evaluator: GuardedCandidateEvaluator<R>,
    harness: H,
}

impl<R, H> SandboxCandidateEvaluator<R, H>
where
    R: SandboxRunner,
    H: CandidateHarness,
{
    pub fn new(runner: R, harness: H) -> Self {
        Self {
            evaluator: GuardedCandidateEvaluator::new(runner),
            harness,
        }
    }
}

impl<R, H> SealedCandidateEvaluator for SandboxCandidateEvaluator<R, H>
where
    R: SandboxRunner,
    H: CandidateHarness,
{
    fn evaluate(
        &self,
        candidate: &CandidateEnvelope,
    ) -> Result<EvaluationReceipt, CandidateProtocolError> {
        validate_candidate(candidate)?;
        let receipt = self.evaluator.evaluate(candidate, &self.harness)?;
        validate_evaluation(candidate, &receipt)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use ccos_sandbox::{
        NetworkPolicy, SandboxError, SandboxExit, SandboxOutput, SandboxSpec,
    };

    use super::*;
    use crate::candidate_protocol::{
        CandidateOrigin, ObjectiveValue, PreparedEvaluation,
    };

    #[derive(Clone, Copy)]
    struct Runner;

    impl SandboxRunner for Runner {
        fn run(&self, _spec: &SandboxSpec) -> Result<SandboxOutput, SandboxError> {
            Ok(SandboxOutput {
                status: SandboxExit::Success,
                stdout: b"verified".to_vec(),
                stderr: Vec::new(),
                timed_out: false,
                output_truncated: false,
            })
        }
    }

    struct Harness;

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
                    network: NetworkPolicy::Deny,
                },
                evaluator_id: "test-evaluator-v1".into(),
                sandbox_policy_id: "test-airgap-v1".into(),
                execution_profile_sha256: Some("a".repeat(64)),
                verifier_sha256: Some("b".repeat(64)),
            })
        }

        fn parse_objectives(
            &self,
            _candidate: &CandidateEnvelope,
            _output: &SandboxOutput,
        ) -> Result<Vec<ObjectiveValue>, CandidateProtocolError> {
            Ok(vec![ObjectiveValue::new("latency_ns", 10.0, true)?])
        }
    }

    fn candidate() -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "simd_gemm",
            b"fn kernel() {}",
            None,
            None,
            None,
            7,
        )
        .unwrap()
    }

    #[test]
    fn valid_candidate_is_executed_and_sealed() {
        let evaluator = SandboxCandidateEvaluator::new(Runner, Harness);
        let candidate = candidate();
        let receipt = evaluator.evaluate(&candidate).unwrap();
        assert_eq!(receipt.candidate_fingerprint, candidate.fingerprint());
    }

    #[test]
    fn forged_candidate_is_rejected_before_runner() {
        let evaluator = SandboxCandidateEvaluator::new(Runner, Harness);
        let mut candidate = candidate();
        candidate.candidate_id = "0".repeat(64);
        assert!(evaluator.evaluate(&candidate).is_err());
    }
}
