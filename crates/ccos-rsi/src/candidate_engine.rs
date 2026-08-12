//! Validated execution façade over the lower-level candidate harness API.
//!
//! CCOS-side code should depend on [`SealedCandidateEvaluator`], not on a raw
//! harness. The concrete sandbox adapter validates the candidate before running
//! anything and validates the returned receipt before releasing it upstream.
//! With `execution-attestation`, a harness supplies the structured canonical
//! SciRust attestation; it never supplies the authoritative receipt fingerprint.
//! The sealed evaluator verifies and recomputes that fingerprint itself.

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

/// Optional structured execution identity supplied by a trusted runtime adapter.
///
/// The object is still treated as untrusted data by the sealed evaluator:
/// `ExecutionAttestation::verify()` is mandatory before its profile fingerprint
/// can enter an `EvaluationReceipt`.
#[cfg(feature = "execution-attestation")]
pub trait CandidateExecutionAttestation {
    fn execution_attestation(
        &self,
        candidate: &CandidateEnvelope,
    ) -> Result<Option<crate::execution_attestation::ExecutionAttestation>, CandidateProtocolError>;
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

#[cfg(not(feature = "execution-attestation"))]
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
        let mut receipt = self.evaluator.evaluate(candidate, &self.harness)?;
        // A raw lower-level harness digest has no authority at the sealed
        // boundary when canonical attestation verification is disabled.
        receipt.execution_profile_sha256 = None;
        validate_evaluation(candidate, &receipt)?;
        Ok(receipt)
    }
}

#[cfg(feature = "execution-attestation")]
impl<R, H> SealedCandidateEvaluator for SandboxCandidateEvaluator<R, H>
where
    R: SandboxRunner,
    H: CandidateHarness + CandidateExecutionAttestation,
{
    fn evaluate(
        &self,
        candidate: &CandidateEnvelope,
    ) -> Result<EvaluationReceipt, CandidateProtocolError> {
        validate_candidate(candidate)?;
        let attestation = self.harness.execution_attestation(candidate)?;
        let verified_profile = match attestation {
            Some(attestation) => {
                attestation.verify().map_err(|error| {
                    CandidateProtocolError::PolicyViolation(format!(
                        "SciRust execution attestation failed verification: {error:?}"
                    ))
                })?;
                Some(attestation.profile_sha256.as_str().to_string())
            }
            None => None,
        };

        let mut receipt = self.evaluator.evaluate(candidate, &self.harness)?;
        receipt.execution_profile_sha256 = verified_profile;
        validate_evaluation(candidate, &receipt)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use ccos_sandbox::{NetworkPolicy, SandboxError, SandboxExit, SandboxOutput, SandboxSpec};

    use super::*;
    use crate::candidate_protocol::{CandidateOrigin, ObjectiveValue, PreparedEvaluation};

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
                // Deliberately bogus: the sealed evaluator must never release
                // this self-asserted value as authoritative provenance.
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

    #[cfg(not(feature = "execution-attestation"))]
    #[test]
    fn unattested_build_strips_self_asserted_execution_profile() {
        let evaluator = SandboxCandidateEvaluator::new(Runner, Harness);
        let candidate = candidate();
        let receipt = evaluator.evaluate(&candidate).unwrap();
        assert_eq!(receipt.candidate_fingerprint, candidate.fingerprint());
        assert_eq!(receipt.execution_profile_sha256, None);
    }

    #[cfg(not(feature = "execution-attestation"))]
    #[test]
    fn forged_candidate_is_rejected_before_runner() {
        let evaluator = SandboxCandidateEvaluator::new(Runner, Harness);
        let mut candidate = candidate();
        candidate.candidate_id = "0".repeat(64);
        assert!(evaluator.evaluate(&candidate).is_err());
    }

    #[cfg(feature = "execution-attestation")]
    mod execution_attestation_tests {
        use super::*;
        use crate::execution_attestation::{
            ExecutionArchitecture, ExecutionArchitectureFamily, ExecutionAttestation,
            ExecutionBackendKind, ExecutionProfile, ExecutionReproducibility, Sha256Digest,
            EXECUTION_PROFILE_SCHEMA_VERSION,
        };

        struct AttestedHarness {
            attestation: Option<ExecutionAttestation>,
        }

        impl CandidateExecutionAttestation for AttestedHarness {
            fn execution_attestation(
                &self,
                _candidate: &CandidateEnvelope,
            ) -> Result<Option<ExecutionAttestation>, CandidateProtocolError> {
                Ok(self.attestation.clone())
            }
        }

        impl CandidateHarness for AttestedHarness {
            fn prepare(
                &self,
                candidate: &CandidateEnvelope,
            ) -> Result<PreparedEvaluation, CandidateProtocolError> {
                CandidateHarness::prepare(&Harness, candidate)
            }

            fn parse_objectives(
                &self,
                candidate: &CandidateEnvelope,
                output: &SandboxOutput,
            ) -> Result<Vec<ObjectiveValue>, CandidateProtocolError> {
                CandidateHarness::parse_objectives(&Harness, candidate, output)
            }
        }

        fn digest(byte: u8) -> Sha256Digest {
            Sha256Digest::parse(format!("{byte:02x}").repeat(32)).unwrap()
        }

        fn attestation() -> ExecutionAttestation {
            ExecutionAttestation::new(ExecutionProfile {
                schema_version: EXECUTION_PROFILE_SCHEMA_VERSION,
                backend: ExecutionBackendKind::Cuda,
                device_ordinal: 0,
                architecture: ExecutionArchitecture {
                    family: ExecutionArchitectureFamily::NvidiaGpu,
                    name: Some("sm_110".into()),
                },
                capability_profile_sha256: digest(0x11),
                topology_profile_sha256: digest(0x22),
                memory_budget_bytes: Some(8 * 1024 * 1024 * 1024),
                numeric_mode: "bf16_tensor_core".into(),
                reproducibility: ExecutionReproducibility::Deterministic,
                kernel_semantic_version: "sciagent.decode.v1".into(),
                sampler_semantic_version: Some("resident_sampler.v1".into()),
                model_sha256: digest(0x33),
                tokenizer_sha256: digest(0x44),
            })
            .unwrap()
        }

        #[test]
        fn canonical_profile_matches_scirust_golden_vector() {
            assert_eq!(
                attestation().profile_sha256.as_str(),
                "f0423da9a3c6c2e43f6e75acd4cd017bd020a0f21d65112a73d1076026c10826"
            );
        }

        #[test]
        fn sealed_receipt_uses_verified_scirust_fingerprint() {
            let harness = AttestedHarness {
                attestation: Some(attestation()),
            };
            let evaluator = SandboxCandidateEvaluator::new(Runner, harness);
            let receipt = evaluator.evaluate(&candidate()).unwrap();
            assert_eq!(
                receipt.execution_profile_sha256.as_deref(),
                Some("f0423da9a3c6c2e43f6e75acd4cd017bd020a0f21d65112a73d1076026c10826")
            );
        }

        #[test]
        fn tampered_scirust_attestation_fails_before_receipt_release() {
            let mut tampered = attestation();
            tampered.profile.numeric_mode = "f32".into();
            let harness = AttestedHarness {
                attestation: Some(tampered),
            };
            let evaluator = SandboxCandidateEvaluator::new(Runner, harness);
            assert!(evaluator.evaluate(&candidate()).is_err());
        }

        #[test]
        fn no_attestation_strips_lower_level_self_asserted_digest() {
            let harness = AttestedHarness { attestation: None };
            let evaluator = SandboxCandidateEvaluator::new(Runner, harness);
            let receipt = evaluator.evaluate(&candidate()).unwrap();
            assert_eq!(receipt.execution_profile_sha256, None);
        }
    }
}
