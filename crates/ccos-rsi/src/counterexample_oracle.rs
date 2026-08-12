//! Sandboxed production adapter for counterexample oracles.
//!
//! The generic counterexample engine is deliberately execution-agnostic. This
//! adapter is the only supported bridge from that engine to generated candidate
//! execution: a trusted harness prepares a `SandboxSpec`, the runner enforces the
//! common fail-closed boundary, and the harness interprets the captured result.
//! There is no direct-process fallback.

use ccos_sandbox::{NetworkPolicy, SandboxOutput, SandboxRunner, SandboxSpec};

use crate::candidate_policy::validate_candidate;
use crate::candidate_protocol::{CandidateEnvelope, CandidateProtocolError};
use crate::counterexample::{CounterexampleOracle, OracleVerdict};

pub trait SandboxedCounterexampleHarness {
    fn oracle_id(&self) -> &str;
    fn contract_sha256(&self) -> &str;

    fn prepare(
        &self,
        candidate: &CandidateEnvelope,
        input: &[u8],
    ) -> Result<SandboxSpec, CandidateProtocolError>;

    fn interpret(
        &self,
        candidate: &CandidateEnvelope,
        input: &[u8],
        output: &SandboxOutput,
    ) -> Result<OracleVerdict, CandidateProtocolError>;
}

pub struct SandboxCounterexampleOracle<R, H> {
    runner: R,
    harness: H,
}

impl<R, H> SandboxCounterexampleOracle<R, H>
where
    R: SandboxRunner,
    H: SandboxedCounterexampleHarness,
{
    pub fn new(runner: R, harness: H) -> Self {
        Self { runner, harness }
    }

    pub fn harness(&self) -> &H {
        &self.harness
    }
}

impl<R, H> CounterexampleOracle for SandboxCounterexampleOracle<R, H>
where
    R: SandboxRunner,
    H: SandboxedCounterexampleHarness,
{
    fn oracle_id(&self) -> &str {
        self.harness.oracle_id()
    }

    fn contract_sha256(&self) -> &str {
        self.harness.contract_sha256()
    }

    fn evaluate(
        &self,
        candidate: &CandidateEnvelope,
        input: &[u8],
    ) -> Result<OracleVerdict, CandidateProtocolError> {
        validate_candidate(candidate)?;
        let spec = self.harness.prepare(candidate, input)?;
        if spec.network != NetworkPolicy::Deny {
            return Err(CandidateProtocolError::PolicyViolation(
                "counterexample candidate execution must deny network access".into(),
            ));
        }

        match self.runner.run(&spec) {
            Ok(output) => self.harness.interpret(candidate, input, &output),
            Err(error) => Ok(OracleVerdict::InfrastructureFailure {
                reason: format!("sandbox refused counterexample query: {error}"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::time::Duration;

    use ccos_sandbox::{SandboxError, SandboxExit};

    use super::*;
    use crate::candidate_protocol::CandidateOrigin;

    fn candidate() -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "sandbox-counterexample-test",
            b"fn candidate() {}",
            None,
            None,
            None,
            9,
        )
        .unwrap()
    }

    struct Runner {
        fail: bool,
        calls: Cell<u64>,
    }

    impl SandboxRunner for Runner {
        fn run(&self, _spec: &SandboxSpec) -> Result<SandboxOutput, SandboxError> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                return Err(SandboxError::Unavailable);
            }
            Ok(SandboxOutput {
                status: SandboxExit::Success,
                stdout: b"FAIL=contains-42".to_vec(),
                stderr: Vec::new(),
                timed_out: false,
                output_truncated: false,
            })
        }
    }

    struct Harness {
        network: NetworkPolicy,
    }

    impl SandboxedCounterexampleHarness for Harness {
        fn oracle_id(&self) -> &str {
            "sandbox-oracle-v1"
        }

        fn contract_sha256(&self) -> &str {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }

        fn prepare(
            &self,
            _candidate: &CandidateEnvelope,
            _input: &[u8],
        ) -> Result<SandboxSpec, CandidateProtocolError> {
            Ok(SandboxSpec {
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
            })
        }

        fn interpret(
            &self,
            _candidate: &CandidateEnvelope,
            input: &[u8],
            output: &SandboxOutput,
        ) -> Result<OracleVerdict, CandidateProtocolError> {
            if output.status == SandboxExit::Success && input.contains(&42) {
                Ok(OracleVerdict::Counterexample {
                    failure_kind: "contains-42".into(),
                })
            } else {
                Ok(OracleVerdict::Pass)
            }
        }
    }

    #[test]
    fn sandboxed_oracle_returns_semantic_verdict_from_trusted_harness() {
        let oracle = SandboxCounterexampleOracle::new(
            Runner {
                fail: false,
                calls: Cell::new(0),
            },
            Harness {
                network: NetworkPolicy::Deny,
            },
        );
        assert_eq!(
            oracle.evaluate(&candidate(), &[42]).unwrap(),
            OracleVerdict::Counterexample {
                failure_kind: "contains-42".into(),
            }
        );
        assert_eq!(oracle.runner.calls.get(), 1);
    }

    #[test]
    fn permissive_network_spec_is_rejected_before_runner() {
        let oracle = SandboxCounterexampleOracle::new(
            Runner {
                fail: false,
                calls: Cell::new(0),
            },
            Harness {
                network: NetworkPolicy::LoopbackOnly,
            },
        );
        assert!(oracle.evaluate(&candidate(), &[42]).is_err());
        assert_eq!(oracle.runner.calls.get(), 0);
    }

    #[test]
    fn sandbox_failure_is_infrastructure_not_semantic_counterexample() {
        let oracle = SandboxCounterexampleOracle::new(
            Runner {
                fail: true,
                calls: Cell::new(0),
            },
            Harness {
                network: NetworkPolicy::Deny,
            },
        );
        let verdict = oracle.evaluate(&candidate(), &[42]).unwrap();
        assert!(matches!(
            verdict,
            OracleVerdict::InfrastructureFailure { .. }
        ));
        assert_eq!(oracle.runner.calls.get(), 1);
    }
}
