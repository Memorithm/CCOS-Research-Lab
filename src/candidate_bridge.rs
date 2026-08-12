//! CCOS-side mirror and closed pipeline for the Research-Lab candidate protocol.
//!
//! RSI/Forge owns the portable candidate/evaluation/adoption receipts. This
//! module keeps the dependency direction CCOS -> RSI and mirrors only validated,
//! canonically-linked receipt payloads into the primary CCOS hash-chained
//! `EventLog`. Repeated synchronization is idempotent.

use std::collections::{BTreeMap, BTreeSet};

use crate::event_log::{EventLog, EventPayload, EventType};
use rsi::{
    validate_adoption, validate_candidate, validate_evaluation, AdoptionDecision, AdoptionReceipt,
    CandidateEnvelope, CandidateProtocolError, ChampionChallengerPolicy, CounterexampleWitness,
    EvaluationPair, EvaluationReceipt, PromotionEvidenceBundle, RepeatedSeedDecision,
    RepeatedSeedPromotionPolicy, SealedCandidateEvaluator,
};

#[derive(Debug)]
pub struct CcosCandidateAudit {
    log: EventLog,
    candidates: BTreeSet<String>,
    evaluations: BTreeSet<String>,
    promotion_evidence: BTreeSet<String>,
    counterexamples_by_candidate: BTreeMap<String, BTreeSet<String>>,
    counterexample_vetoes: BTreeSet<String>,
    adoptions: BTreeSet<String>,
}

impl CcosCandidateAudit {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            log: EventLog::new(session_id.into()),
            candidates: BTreeSet::new(),
            evaluations: BTreeSet::new(),
            promotion_evidence: BTreeSet::new(),
            counterexamples_by_candidate: BTreeMap::new(),
            counterexample_vetoes: BTreeSet::new(),
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

    /// Fast single-seed selection gate. Passing produces `Quarantine`, never
    /// direct promotion. The resulting decision is still journaled so the
    /// transition into repeated-seed holdout is auditable.
    pub fn decide_champion_challenger(
        &mut self,
        champion: &EvaluationReceipt,
        challenger: &EvaluationReceipt,
        policy: &ChampionChallengerPolicy,
        promoted_artifact_sha256: Option<String>,
    ) -> Result<AdoptionReceipt, CandidateProtocolError> {
        if !self.evaluations.contains(&challenger.fingerprint()) {
            return Err(CandidateProtocolError::PolicyViolation(
                "challenger evaluation must be audited before selection decision".into(),
            ));
        }
        let adoption = policy.decide(champion, challenger, promoted_artifact_sha256)?;
        self.record_adoption(challenger, &adoption)?;
        Ok(adoption)
    }

    /// Hard promotion path. All selection and holdout evaluations must already
    /// exist in the primary CCOS chain. Evidence is written before adoption.
    ///
    /// A previously audited semantic counterexample for the challenger's
    /// content-addressed candidate id is an unconditional promotion veto. The
    /// veto is itself appended once to the primary EventLog, together with the
    /// repeated-seed evidence fingerprint that would otherwise have promoted.
    pub fn decide_repeated_seed(
        &mut self,
        selection: &[EvaluationPair<'_>],
        holdout: &[EvaluationPair<'_>],
        policy: &RepeatedSeedPromotionPolicy,
        promoted_artifact_sha256: Option<String>,
    ) -> Result<RepeatedSeedDecision, CandidateProtocolError> {
        let decision = policy.decide(selection, holdout, promoted_artifact_sha256)?;
        self.record_promotion_evidence(decision.evidence())?;

        if decision.adoption().decision == AdoptionDecision::Promote {
            let challenger_id = decision.evidence().challenger_candidate_id();
            if let Some(counterexamples) = self.counterexamples_by_candidate.get(challenger_id) {
                if let Some(counterexample) = counterexamples.iter().next() {
                    let evidence = decision.evidence().fingerprint();
                    let veto_key = format!("{challenger_id}:{counterexample}:{evidence}");
                    if self.counterexample_vetoes.insert(veto_key) {
                        self.log.append(
                            EventType::AgentAction,
                            EventPayload::Custom {
                                key: "candidate_promotion_veto_v1".to_string(),
                                value: format!(
                                    "candidate={challenger_id};counterexample={counterexample};evidence={evidence}"
                                ),
                            },
                        );
                    }
                    return Err(CandidateProtocolError::PolicyViolation(format!(
                        "promotion vetoed by audited counterexample {counterexample} for candidate {challenger_id}"
                    )));
                }
            }
        }

        let anchor = selection
            .iter()
            .chain(holdout.iter())
            .map(|pair| pair.challenger)
            .find(|receipt| receipt.fingerprint() == decision.adoption().evaluation_fingerprint)
            .ok_or_else(|| {
                CandidateProtocolError::PolicyViolation(
                    "repeated-seed adoption anchor is absent from supplied evidence".into(),
                )
            })?;
        self.record_adoption(anchor, decision.adoption())?;
        Ok(decision)
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

    /// Record a validated minimized counterexample against one exact candidate
    /// envelope, then index it by the candidate's content-addressed id so the
    /// veto survives across later trial/holdout envelopes for the same code.
    pub fn record_counterexample(
        &mut self,
        candidate: &CandidateEnvelope,
        witness: &CounterexampleWitness,
    ) -> Result<String, CandidateProtocolError> {
        witness.validate(candidate)?;
        if !self.candidates.contains(&candidate.fingerprint()) {
            return Err(CandidateProtocolError::PolicyViolation(
                "candidate must be recorded before its counterexample".into(),
            ));
        }

        let fingerprint = witness.receipt.fingerprint();
        let candidate_receipts = self
            .counterexamples_by_candidate
            .entry(candidate.candidate_id.clone())
            .or_default();
        if !candidate_receipts.insert(fingerprint.clone()) {
            return Ok(self.log.chain_head());
        }
        self.log.append(
            EventType::AgentAction,
            EventPayload::Custom {
                key: "candidate_counterexample_v1".to_string(),
                value: format!(
                    "candidate_id={};{}",
                    candidate.candidate_id,
                    witness.receipt.audit_payload()
                ),
            },
        );
        Ok(self.log.chain_head())
    }

    pub fn has_counterexample(&self, candidate_id: &str) -> bool {
        self.counterexamples_by_candidate
            .get(candidate_id)
            .is_some_and(|receipts| !receipts.is_empty())
    }

    pub fn record_promotion_evidence(
        &mut self,
        evidence: &PromotionEvidenceBundle,
    ) -> Result<String, CandidateProtocolError> {
        for row in evidence.selection().iter().chain(evidence.holdout()) {
            if !self
                .evaluations
                .contains(row.champion_evaluation_fingerprint())
                || !self
                    .evaluations
                    .contains(row.challenger_evaluation_fingerprint())
            {
                return Err(CandidateProtocolError::PolicyViolation(
                    "every promotion-evidence evaluation must be audited before the evidence bundle"
                        .into(),
                ));
            }
        }
        let fingerprint = evidence.fingerprint();
        if !self.promotion_evidence.insert(fingerprint) {
            return Ok(self.log.chain_head());
        }
        self.log.append(
            EventType::AgentAction,
            EventPayload::Custom {
                key: "candidate_promotion_evidence_v1".to_string(),
                value: evidence.audit_payload(),
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
        if receipt.decision == AdoptionDecision::Promote
            && !self
                .promotion_evidence
                .iter()
                .any(|evidence| receipt.reason.contains(evidence))
        {
            return Err(CandidateProtocolError::PolicyViolation(
                "promotion must bind a previously audited repeated-seed evidence bundle".into(),
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
        AdoptionReceipt, CandidateOrigin, ChunkDeletionShrinker, CounterexampleConfig,
        CounterexampleEngine, CounterexampleGenerator, CounterexampleOracle,
        CounterexampleSearchResult, EvaluationStatus, ObjectiveValue, OracleVerdict,
        CANDIDATE_PROTOCOL_VERSION,
    };

    fn candidate_with_source_and_seed(source: &[u8], seed: u64) -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "simd_gemm",
            source,
            Some("7".into()),
            None,
            Some("a".repeat(64)),
            seed,
        )
        .unwrap()
    }

    fn candidate_with_source(source: &[u8]) -> CandidateEnvelope {
        candidate_with_source_and_seed(source, 42)
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
            AdoptionDecision::Quarantine,
            "single-seed gate passed; holdout required",
            Some("previous".into()),
            None,
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
    fn closed_pipeline_quarantines_single_seed_gain_for_holdout() {
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

        assert_eq!(adoption.decision, AdoptionDecision::Quarantine);
        assert_eq!(adoption.promoted_artifact_sha256, None);
        assert_eq!(audit.event_log().events.len(), 3);
        assert!(audit.event_log().verify_integrity().valid);
    }

    fn pair(
        seed: u64,
        challenger_latency: f64,
    ) -> (
        CandidateEnvelope,
        EvaluationReceipt,
        CandidateEnvelope,
        EvaluationReceipt,
    ) {
        let champion_candidate = candidate_with_source_and_seed(b"champion", seed);
        let challenger_candidate = candidate_with_source_and_seed(b"challenger", seed);
        let champion = evaluation_with_latency(&champion_candidate, 100.0);
        let challenger = evaluation_with_latency(&challenger_candidate, challenger_latency);
        (
            champion_candidate,
            champion,
            challenger_candidate,
            challenger,
        )
    }

    fn record_pair(
        audit: &mut CcosCandidateAudit,
        pair: &(
            CandidateEnvelope,
            EvaluationReceipt,
            CandidateEnvelope,
            EvaluationReceipt,
        ),
    ) {
        audit.record_candidate(&pair.0).unwrap();
        audit.record_evaluation(&pair.0, &pair.1).unwrap();
        audit.record_candidate(&pair.2).unwrap();
        audit.record_evaluation(&pair.2, &pair.3).unwrap();
    }

    #[test]
    fn repeated_seed_promotion_requires_audited_disjoint_evidence() {
        let s1 = pair(101, 80.0);
        let s2 = pair(102, 82.0);
        let h1 = pair(201, 84.0);
        let h2 = pair(202, 83.0);
        let selection = [
            EvaluationPair {
                champion_candidate: &s1.0,
                champion: &s1.1,
                challenger_candidate: &s1.2,
                challenger: &s1.3,
            },
            EvaluationPair {
                champion_candidate: &s2.0,
                champion: &s2.1,
                challenger_candidate: &s2.2,
                challenger: &s2.3,
            },
        ];
        let holdout = [
            EvaluationPair {
                champion_candidate: &h1.0,
                champion: &h1.1,
                challenger_candidate: &h1.2,
                challenger: &h1.3,
            },
            EvaluationPair {
                champion_candidate: &h2.0,
                champion: &h2.1,
                challenger_candidate: &h2.2,
                challenger: &h2.3,
            },
        ];
        let policy =
            RepeatedSeedPromotionPolicy::new("repeat-v1", 2, 2, 0.10, 0.0, 10_000).unwrap();
        let mut audit = CcosCandidateAudit::new("repeated-seed-test");
        for pair in [&s1, &s2, &h1, &h2] {
            record_pair(&mut audit, pair);
        }

        let decision = audit
            .decide_repeated_seed(&selection, &holdout, &policy, Some("f".repeat(64)))
            .unwrap();

        assert_eq!(decision.adoption().decision, AdoptionDecision::Promote);
        assert!(decision
            .adoption()
            .reason
            .contains(&decision.evidence().fingerprint()));
        assert_eq!(audit.event_log().events.len(), 18);
        assert!(audit.event_log().verify_integrity().valid);
    }

    struct OneCaseGenerator;

    impl CounterexampleGenerator for OneCaseGenerator {
        fn generator_id(&self) -> &str {
            "ccos-one-case-v1"
        }

        fn generate(&self, _seed: u64, _ordinal: u64) -> Result<Vec<u8>, CandidateProtocolError> {
            Ok(vec![1, 42, 2])
        }
    }

    struct Contains42Oracle;

    impl CounterexampleOracle for Contains42Oracle {
        fn oracle_id(&self) -> &str {
            "ccos-contains-42-v1"
        }

        fn contract_sha256(&self) -> &str {
            "abababababababababababababababababababababababababababababababab"
        }

        fn evaluate(
            &self,
            _candidate: &CandidateEnvelope,
            input: &[u8],
        ) -> Result<OracleVerdict, CandidateProtocolError> {
            if input.contains(&42) {
                Ok(OracleVerdict::Counterexample {
                    failure_kind: "contains-42".into(),
                })
            } else {
                Ok(OracleVerdict::Pass)
            }
        }
    }

    #[test]
    fn audited_counterexample_vetoes_same_challenger_across_holdout_seeds() {
        let s1 = pair(101, 80.0);
        let s2 = pair(102, 82.0);
        let h1 = pair(201, 84.0);
        let h2 = pair(202, 83.0);
        assert_eq!(s1.2.candidate_id, h2.2.candidate_id);

        let selection = [
            EvaluationPair {
                champion_candidate: &s1.0,
                champion: &s1.1,
                challenger_candidate: &s1.2,
                challenger: &s1.3,
            },
            EvaluationPair {
                champion_candidate: &s2.0,
                champion: &s2.1,
                challenger_candidate: &s2.2,
                challenger: &s2.3,
            },
        ];
        let holdout = [
            EvaluationPair {
                champion_candidate: &h1.0,
                champion: &h1.1,
                challenger_candidate: &h1.2,
                challenger: &h1.3,
            },
            EvaluationPair {
                champion_candidate: &h2.0,
                champion: &h2.1,
                challenger_candidate: &h2.2,
                challenger: &h2.3,
            },
        ];
        let policy =
            RepeatedSeedPromotionPolicy::new("repeat-v1", 2, 2, 0.10, 0.0, 10_000).unwrap();
        let engine = CounterexampleEngine::new(
            OneCaseGenerator,
            ChunkDeletionShrinker,
            Contains42Oracle,
            CounterexampleConfig::new(1, 32, 64).unwrap(),
        )
        .unwrap();
        let witness = match engine.search(&s1.2, 9001).unwrap() {
            CounterexampleSearchResult::Found(witness) => witness,
            CounterexampleSearchResult::NoCounterexample { .. } => panic!("witness expected"),
        };
        assert_eq!(witness.minimized_input, vec![42]);

        let mut audit = CcosCandidateAudit::new("counterexample-veto-test");
        for pair in [&s1, &s2, &h1, &h2] {
            record_pair(&mut audit, pair);
        }
        audit.record_counterexample(&s1.2, &witness).unwrap();
        audit.record_counterexample(&s1.2, &witness).unwrap();
        assert!(audit.has_counterexample(&h2.2.candidate_id));

        let error = audit
            .decide_repeated_seed(&selection, &holdout, &policy, Some("f".repeat(64)))
            .unwrap_err();
        assert!(format!("{error}").contains("promotion vetoed by audited counterexample"));
        assert_eq!(audit.event_log().events.len(), 19);
        assert!(audit.event_log().verify_integrity().valid);

        let again = audit
            .decide_repeated_seed(&selection, &holdout, &policy, Some("f".repeat(64)))
            .unwrap_err();
        assert!(format!("{again}").contains("promotion vetoed by audited counterexample"));
        assert_eq!(audit.event_log().events.len(), 19);
    }

    #[test]
    fn forged_promotion_reason_without_recorded_evidence_is_rejected() {
        let candidate = candidate();
        let evaluation = evaluation(&candidate);
        let adoption = AdoptionReceipt::new(
            &evaluation,
            "repeat-v1",
            AdoptionDecision::Promote,
            format!("holdout passed; evidence_sha256={}", "f".repeat(64)),
            None,
            Some("e".repeat(64)),
        )
        .unwrap();
        let mut audit = CcosCandidateAudit::new("forged-promotion");
        audit.record_candidate(&candidate).unwrap();
        audit.record_evaluation(&candidate, &evaluation).unwrap();
        assert!(audit.record_adoption(&evaluation, &adoption).is_err());
        assert_eq!(audit.event_log().events.len(), 2);
    }
}
