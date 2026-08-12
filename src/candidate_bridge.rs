//! CCOS-side mirror for the Research-Lab candidate protocol.
//!
//! RSI/Forge owns the portable candidate/evaluation/adoption receipts. This
//! module keeps the dependency direction CCOS -> RSI and mirrors only validated,
//! canonically-linked receipt payloads into the primary CCOS hash-chained
//! `EventLog`. Repeated synchronization is idempotent.

use std::collections::BTreeSet;

use crate::event_log::{EventLog, EventPayload, EventType};
use rsi::{
    validate_adoption, validate_candidate, validate_evaluation, AdoptionReceipt,
    CandidateEnvelope, CandidateProtocolError, EvaluationReceipt,
};

#[derive(Debug)]
pub struct CcosCandidateAudit {
    log: EventLog,
    candidates: BTreeSet<String>,
    evaluations: BTreeSet<String>,
    adoptions: BTreeSet<String>,
}

impl CcosCandidateAudit {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            log: EventLog::new(session_id.into()),
            candidates: BTreeSet::new(),
            evaluations: BTreeSet::new(),
            adoptions: BTreeSet::new(),
        }
    }

    pub fn event_log(&self) -> &EventLog {
        &self.log
    }

    pub fn record_candidate(
        &mut self,
        candidate: &CandidateEnvelope,
    ) -> Result<String, CandidateProtocolError> {
        validate_candidate(candidate)?;
        let fingerprint = candidate.fingerprint();
        if !self.candidates.insert(fingerprint) {
            return Ok(self.log.chain_head());
        }
        self.log.append(
            EventType::AgentAction,
            EventPayload::Custom {
                key: "candidate_envelope_v1".to_string(),
                value: candidate.audit_payload(),
            },
        );
        Ok(self.log.chain_head())
    }

    pub fn record_evaluation(
        &mut self,
        candidate: &CandidateEnvelope,
        receipt: &EvaluationReceipt,
    ) -> Result<String, CandidateProtocolError> {
        validate_evaluation(candidate, receipt)?;
        if !self.candidates.contains(&candidate.fingerprint()) {
            return Err(CandidateProtocolError::PolicyViolation(
                "candidate must be recorded before its evaluation".into(),
            ));
        }
        let fingerprint = receipt.fingerprint();
        if !self.evaluations.insert(fingerprint) {
            return Ok(self.log.chain_head());
        }
        self.log.append(
            EventType::AgentAction,
            EventPayload::Custom {
                key: "candidate_evaluation_v1".to_string(),
                value: receipt.audit_payload(),
            },
        );
        Ok(self.log.chain_head())
    }

    pub fn record_adoption(
        &mut self,
        evaluation: &EvaluationReceipt,
        receipt: &AdoptionReceipt,
    ) -> Result<String, CandidateProtocolError> {
        validate_adoption(evaluation, receipt)?;
        if !self.evaluations.contains(&evaluation.fingerprint()) {
            return Err(CandidateProtocolError::PolicyViolation(
                "evaluation must be recorded before its adoption decision".into(),
            ));
        }
        let fingerprint = receipt.fingerprint();
        if !self.adoptions.insert(fingerprint) {
            return Ok(self.log.chain_head());
        }
        self.log.append(
            EventType::AgentAction,
            EventPayload::Custom {
                key: "candidate_adoption_v1".to_string(),
                value: receipt.audit_payload(),
            },
        );
        Ok(self.log.chain_head())
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
        audit.record_candidate(&candidate).unwrap();
        audit.record_evaluation(&candidate, &evaluation).unwrap();
        audit.record_adoption(&evaluation, &adoption).unwrap();

        assert_eq!(audit.event_log().events.len(), 3);
        assert!(audit.event_log().verify_integrity().valid);
    }

    #[test]
    fn identical_receipts_are_idempotent_and_replay_to_same_head() {
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
            audit.record_candidate(&candidate).unwrap();
            audit.record_candidate(&candidate).unwrap();
            audit.record_evaluation(&candidate, &evaluation).unwrap();
            audit.record_evaluation(&candidate, &evaluation).unwrap();
            audit.record_adoption(&evaluation, &adoption).unwrap();
            audit.record_adoption(&evaluation, &adoption).unwrap();
            assert_eq!(audit.event_log().events.len(), 3);
            audit.event_log().chain_head()
        };

        assert_eq!(build(), build());
    }

    #[test]
    fn out_of_order_evaluation_is_rejected_without_mutating_log() {
        let candidate = candidate();
        let evaluation = evaluation(&candidate);
        let mut audit = CcosCandidateAudit::new("candidate-test");
        assert!(audit.record_evaluation(&candidate, &evaluation).is_err());
        assert!(audit.event_log().events.is_empty());
    }

    #[test]
    fn forged_candidate_is_rejected_before_primary_log_mutation() {
        let mut candidate = candidate();
        candidate.candidate_id = "0".repeat(64);
        let mut audit = CcosCandidateAudit::new("candidate-test");
        assert!(audit.record_candidate(&candidate).is_err());
        assert!(audit.event_log().events.is_empty());
    }
}
