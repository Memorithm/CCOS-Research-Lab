//! CCOS-side mirror and closed pipeline for the Research-Lab candidate protocol.
//!
//! RSI/Forge owns the portable candidate/evaluation/adoption receipts. This
//! module keeps the dependency direction CCOS -> RSI and mirrors only validated,
//! canonically-linked receipt payloads into the primary CCOS hash-chained
//! `EventLog`. Repeated synchronization is idempotent.

use std::collections::BTreeSet;

use crate::event_log::{EventLog, EventPayload, EventType};
use rsi::{
    validate_adoption, validate_candidate, validate_evaluation, AdoptionReceipt, CandidateEnvelope,
    CandidateProtocolError, ChampionChallengerPolicy, EvaluationReceipt, SealedCandidateEvaluator,
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

    /// Execute the complete candidate -> sealed evaluation audit transition.
    /// The candidate is committed to the primary log before execution. A
    /// protocol or infrastructure failure therefore remains observable without
    /// ever fabricating an evaluation event.
    pub fn evaluate<E: SealedCandidateEvaluator>(
        &mut self,
        candidate: &CandidateEnvelope,
        evaluator: &E,
    ) -> Result<EvaluationReceipt, CandidateProtocolError> {
        self.record_candidate(candidate)?;
        let receipt = evaluator.evaluate(candidate)?;
        self.record_evaluation(candidate, &receipt)?;
        Ok(receipt)
    }

    /// Compare a recorded challenger with a champion under the typed promotion
    /// policy, then seal the resulting Promote/Reject decision in the same CCOS
    /// chain. A challenger evaluation not previously audited is refused.
    pub fn decide_champion_challenger(
        &mut self,
        champion: &EvaluationReceipt,
        challenger: &EvaluationReceipt,
        policy: &ChampionChallengerPolicy,
        promoted_artifact_sha256: Option<String>,
    ) -> Result<AdoptionReceipt, CandidateProtocolError> {
        if !self.evaluations.contains(&challenger.fingerprint()) {
            return Err(CandidateProtocolError::PolicyViolation(
                "challenger evaluation must be audited before adoption".into(),
            ));
        }
        let adoption = policy.decide(champion, challenger, promoted_artifact_sha256)?;
        self.record_adoption(challenger, &adoption)?;
        Ok(adoption)
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

    fn candidate_with_source(source: &[u8]) -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "simd_gemm",
            source,
            Some("7".into()),
            None,
            Some("a".repeat(64)),
            42,
        )
        .unwrap()
    }

    fn candidate() -> CandidateEnvelope {
        candidate_with_source(b"fn kernel() {}")
    }

    fn evaluation_with_latency(candidate: &CandidateEnvelope, latency: f64) -> EvaluationReceipt {
        EvaluationReceipt {
            schema_version: CANDIDATE_PROTOCOL_VERSION,
            candidate_fingerprint: candidate.fingerprint(),
            evaluator_id: "forge-scirust-v1".into(),
            sandbox_policy_id: "research-airgap-v1".into(),
            execution_profile_sha256: Some("b".repeat(64)),
            verifier_sha256: Some("c".repeat(64)),
            trial_seed: candidate.trial_seed,
            status: EvaluationStatus::Succeeded,
            objectives: vec![ObjectiveValue::new("latency_ns", latency, true).unwrap()],
            stdout_sha256: "d".repeat(64),
            stderr_sha256: "e".repeat(64),
            timed_out: false,
            output_truncated: false,
            failure_reason: None,
        }
    }

    fn evaluation(candidate: &CandidateEnvelope) -> EvaluationReceipt {
        evaluation_with_latency(candidate, 10.0)
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

    struct StaticEvaluator {
        receipt: EvaluationReceipt,
    }

    impl SealedCandidateEvaluator for StaticEvaluator {
        fn evaluate(
            &self,
            _candidate: &CandidateEnvelope,
        ) -> Result<EvaluationReceipt, CandidateProtocolError> {
            Ok(self.receipt.clone())
        }
    }

    #[test]
    fn closed_pipeline_evaluates_then_promotes_audited_challenger() {
        let champion_candidate = candidate_with_source(b"champion");
        let challenger_candidate = candidate_with_source(b"challenger");
        let champion = evaluation_with_latency(&champion_candidate, 100.0);
        let challenger = evaluation_with_latency(&challenger_candidate, 80.0);
        let evaluator = StaticEvaluator {
            receipt: challenger.clone(),
        };
        let policy = ChampionChallengerPolicy::new("cc-v1", 0.10, 0.0).unwrap();

        let mut audit = CcosCandidateAudit::new("pipeline-test");
        let measured = audit.evaluate(&challenger_candidate, &evaluator).unwrap();
        let adoption = audit
            .decide_champion_challenger(&champion, &measured, &policy, Some("f".repeat(64)))
            .unwrap();

        assert_eq!(adoption.decision, AdoptionDecision::Promote);
        assert_eq!(audit.event_log().events.len(), 3);
        assert!(audit.event_log().verify_integrity().valid);
    }
}
