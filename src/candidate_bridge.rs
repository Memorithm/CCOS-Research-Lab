//! CCOS-side mirror for the Research-Lab candidate protocol.
//!
//! RSI/Forge owns the portable candidate/evaluation/adoption receipts.  This
//! module keeps the dependency direction CCOS -> RSI and mirrors only canonical
//! receipt payloads into the primary CCOS hash-chained EventLog.

use crate::event_log::{EventLog, EventPayload, EventType};
use rsi::{AdoptionReceipt, CandidateEnvelope, EvaluationReceipt};

#[derive(Debug)]
pub struct CcosCandidateAudit {
    log: EventLog,
}

impl CcosCandidateAudit {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            log: EventLog::new(session_id.into()),
        }
    }

    pub fn event_log(&self) -> &EventLog {
        &self.log
    }

    pub fn record_candidate(&mut self, candidate: &CandidateEnvelope) -> String {
        self.log.append(
            EventType::AgentAction,
            EventPayload::Custom {
                key: "candidate_envelope_v1".to_string(),
                value: candidate.audit_payload(),
            },
        );
        self.log.chain_head()
    }

    pub fn record_evaluation(&mut self, receipt: &EvaluationReceipt) -> String {
        self.log.append(
            EventType::AgentAction,
            EventPayload::Custom {
                key: "candidate_evaluation_v1".to_string(),
                value: receipt.audit_payload(),
            },
        );
        self.log.chain_head()
    }

    pub fn record_adoption(&mut self, receipt: &AdoptionReceipt) -> String {
        self.log.append(
            EventType::AgentAction,
            EventPayload::Custom {
                key: "candidate_adoption_v1".to_string(),
                value: receipt.audit_payload(),
            },
        );
        self.log.chain_head()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsi::{
        AdoptionDecision, AdoptionReceipt, CandidateOrigin, EvaluationReceipt, EvaluationStatus,
        ObjectiveValue, CANDIDATE_PROTOCOL_VERSION,
    };

    fn candidate() -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "simd_gemm",
            b"fn kernel() {}",
            Some("7".into()),
            None,
            Some("a".repeat(64)),
            42,
        )
        .unwrap()
    }

    fn evaluation(candidate: &CandidateEnvelope) -> EvaluationReceipt {
        EvaluationReceipt {
            schema_version: CANDIDATE_PROTOCOL_VERSION,
            candidate_fingerprint: candidate.fingerprint(),
            evaluator_id: "forge-scirust-v1".into(),
            sandbox_policy_id: "research-airgap-v1".into(),
            execution_profile_sha256: Some("b".repeat(64)),
            verifier_sha256: Some("c".repeat(64)),
            trial_seed: candidate.trial_seed,
            status: EvaluationStatus::Succeeded,
            objectives: vec![ObjectiveValue::new("latency_ns", 10.0, true).unwrap()],
            stdout_sha256: "d".repeat(64),
            stderr_sha256: "e".repeat(64),
            timed_out: false,
            output_truncated: false,
            failure_reason: None,
        }
    }

    #[test]
    fn complete_candidate_chain_is_integrity_checked() {
        let candidate = candidate();
        let evaluation = evaluation(&candidate);
        let adoption = AdoptionReceipt::new(
            &evaluation,
            "champion-challenger-v1",
            AdoptionDecision::Promote,
            "holdout and regression gates passed",
            Some("previous".into()),
            Some("f".repeat(64)),
        )
        .unwrap();

        let mut audit = CcosCandidateAudit::new("candidate-test");
        audit.record_candidate(&candidate);
        audit.record_evaluation(&evaluation);
        audit.record_adoption(&adoption);

        assert_eq!(audit.event_log().events.len(), 3);
        assert!(audit.event_log().verify_integrity().valid);
    }

    #[test]
    fn identical_receipts_produce_identical_ccos_chain_heads() {
        let build = || {
            let candidate = candidate();
            let evaluation = evaluation(&candidate);
            let adoption = AdoptionReceipt::new(
                &evaluation,
                "champion-challenger-v1",
                AdoptionDecision::Reject,
                "challenger did not beat champion",
                Some("previous".into()),
                None,
            )
            .unwrap();
            let mut audit = CcosCandidateAudit::new("candidate-test");
            audit.record_candidate(&candidate);
            audit.record_evaluation(&evaluation);
            audit.record_adoption(&adoption);
            audit.event_log().chain_head()
        };

        assert_eq!(build(), build());
    }
}
