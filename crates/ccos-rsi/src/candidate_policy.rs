//! Fail-closed validation and first promotion policy for candidate receipts.
//!
//! The protocol structs remain portable data. This module is the authority that
//! decides whether their links are internally coherent and whether a challenger
//! may replace a measured champion.

use crate::candidate_protocol::{
    AdoptionDecision, AdoptionReceipt, CandidateEnvelope, CandidateOrigin, CandidateProtocolError,
    EvaluationReceipt, EvaluationStatus, ObjectiveValue, CANDIDATE_PROTOCOL_VERSION,
};
use crate::sha256::sha256;

fn digest_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn origin_tag(origin: CandidateOrigin) -> u8 {
    match origin {
        CandidateOrigin::Forge => 1,
        CandidateOrigin::Rsi => 2,
        CandidateOrigin::SciRust => 3,
        CandidateOrigin::External => 255,
    }
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    push_u64(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn validate_optional_digest(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), CandidateProtocolError> {
    if let Some(value) = value {
        if !is_sha256_hex(value) {
            return Err(CandidateProtocolError::InvalidField(field));
        }
    }
    Ok(())
}

pub fn validate_candidate(candidate: &CandidateEnvelope) -> Result<(), CandidateProtocolError> {
    if candidate.schema_version != CANDIDATE_PROTOCOL_VERSION {
        return Err(CandidateProtocolError::InvalidField("candidate.schema_version"));
    }
    if candidate.domain.trim().is_empty() {
        return Err(CandidateProtocolError::InvalidField("candidate.domain"));
    }
    if !is_sha256_hex(&candidate.source_sha256) {
        return Err(CandidateProtocolError::InvalidField("candidate.source_sha256"));
    }
    validate_optional_digest(
        candidate.proposal_sha256.as_deref(),
        "candidate.proposal_sha256",
    )?;
    if let Some(parent) = candidate.parent_candidate_id.as_deref() {
        if !is_sha256_hex(parent) {
            return Err(CandidateProtocolError::InvalidField(
                "candidate.parent_candidate_id",
            ));
        }
    }

    let mut identity = b"memorithm.candidate.identity.v1\0".to_vec();
    identity.push(origin_tag(candidate.origin));
    push_str(&mut identity, &candidate.domain);
    push_str(&mut identity, &candidate.source_sha256);
    if candidate.candidate_id != digest_hex(&identity) {
        return Err(CandidateProtocolError::PolicyViolation(
            "candidate content identity does not match its declared source digest".into(),
        ));
    }
    Ok(())
}

fn validate_objective(objective: &ObjectiveValue) -> Result<(), CandidateProtocolError> {
    if objective.name.trim().is_empty() {
        return Err(CandidateProtocolError::InvalidField("objective.name"));
    }
    if !objective.value.is_finite() {
        return Err(CandidateProtocolError::NonFiniteObjective(
            objective.name.clone(),
        ));
    }
    Ok(())
}

pub fn validate_evaluation(
    candidate: &CandidateEnvelope,
    receipt: &EvaluationReceipt,
) -> Result<(), CandidateProtocolError> {
    validate_candidate(candidate)?;
    if receipt.schema_version != CANDIDATE_PROTOCOL_VERSION {
        return Err(CandidateProtocolError::InvalidField(
            "evaluation.schema_version",
        ));
    }
    if receipt.candidate_fingerprint != candidate.fingerprint() {
        return Err(CandidateProtocolError::PolicyViolation(
            "evaluation receipt is not bound to the supplied candidate envelope".into(),
        ));
    }
    if receipt.trial_seed != candidate.trial_seed {
        return Err(CandidateProtocolError::PolicyViolation(
            "evaluation trial seed differs from candidate envelope".into(),
        ));
    }
    if receipt.evaluator_id.trim().is_empty() {
        return Err(CandidateProtocolError::InvalidField("evaluation.evaluator_id"));
    }
    if receipt.sandbox_policy_id.trim().is_empty() {
        return Err(CandidateProtocolError::InvalidField(
            "evaluation.sandbox_policy_id",
        ));
    }
    validate_optional_digest(
        receipt.execution_profile_sha256.as_deref(),
        "evaluation.execution_profile_sha256",
    )?;
    validate_optional_digest(
        receipt.verifier_sha256.as_deref(),
        "evaluation.verifier_sha256",
    )?;
    if !is_sha256_hex(&receipt.stdout_sha256) || !is_sha256_hex(&receipt.stderr_sha256) {
        return Err(CandidateProtocolError::InvalidField(
            "evaluation.output_sha256",
        ));
    }
    for objective in &receipt.objectives {
        validate_objective(objective)?;
    }

    match receipt.status {
        EvaluationStatus::Succeeded => {
            if receipt.timed_out || receipt.failure_reason.is_some() || receipt.objectives.is_empty() {
                return Err(CandidateProtocolError::PolicyViolation(
                    "successful evaluation must contain objectives and no failure state".into(),
                ));
            }
        }
        EvaluationStatus::CandidateFailed | EvaluationStatus::InfrastructureFailed => {
            if !receipt.objectives.is_empty() || receipt.failure_reason.is_none() {
                return Err(CandidateProtocolError::PolicyViolation(
                    "failed evaluation must carry a reason and no fitness objectives".into(),
                ));
            }
        }
    }
    Ok(())
}

pub fn validate_adoption(
    evaluation: &EvaluationReceipt,
    adoption: &AdoptionReceipt,
) -> Result<(), CandidateProtocolError> {
    if adoption.schema_version != CANDIDATE_PROTOCOL_VERSION {
        return Err(CandidateProtocolError::InvalidField("adoption.schema_version"));
    }
    if adoption.evaluation_fingerprint != evaluation.fingerprint() {
        return Err(CandidateProtocolError::PolicyViolation(
            "adoption receipt is not bound to the supplied evaluation".into(),
        ));
    }
    if adoption.policy_id.trim().is_empty() || adoption.reason.trim().is_empty() {
        return Err(CandidateProtocolError::InvalidField("adoption.policy"));
    }
    validate_optional_digest(
        adoption.promoted_artifact_sha256.as_deref(),
        "adoption.promoted_artifact_sha256",
    )?;
    if adoption.decision == AdoptionDecision::Promote {
        if evaluation.status != EvaluationStatus::Succeeded {
            return Err(CandidateProtocolError::PolicyViolation(
                "a failed evaluation can never be promoted".into(),
            ));
        }
        if adoption.promoted_artifact_sha256.is_none() {
            return Err(CandidateProtocolError::PolicyViolation(
                "promotion requires a content digest for the promoted artifact".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ChampionChallengerPolicy {
    pub policy_id: String,
    /// Relative primary-objective improvement required to replace the champion.
    pub min_primary_relative_improvement: f64,
    /// Maximum relative regression tolerated on any non-primary objective.
    pub max_relative_regression: f64,
}

impl ChampionChallengerPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        min_primary_relative_improvement: f64,
        max_relative_regression: f64,
    ) -> Result<Self, CandidateProtocolError> {
        let policy_id = policy_id.into();
        if policy_id.trim().is_empty() {
            return Err(CandidateProtocolError::InvalidField("promotion.policy_id"));
        }
        if !min_primary_relative_improvement.is_finite()
            || min_primary_relative_improvement < 0.0
            || !max_relative_regression.is_finite()
            || max_relative_regression < 0.0
        {
            return Err(CandidateProtocolError::InvalidField(
                "promotion.relative_threshold",
            ));
        }
        Ok(Self {
            policy_id,
            min_primary_relative_improvement,
            max_relative_regression,
        })
    }

    pub fn decide(
        &self,
        champion: &EvaluationReceipt,
        challenger: &EvaluationReceipt,
        promoted_artifact_sha256: Option<String>,
    ) -> Result<AdoptionReceipt, CandidateProtocolError> {
        if champion.status != EvaluationStatus::Succeeded
            || challenger.status != EvaluationStatus::Succeeded
        {
            return AdoptionReceipt::new(
                challenger,
                self.policy_id.clone(),
                AdoptionDecision::Reject,
                "champion/challenger comparison requires two successful evaluations",
                Some(champion.candidate_fingerprint.clone()),
                None,
            );
        }
        self.require_comparable(champion, challenger)?;

        let mut improvements = Vec::with_capacity(champion.objectives.len());
        for (baseline, candidate) in champion.objectives.iter().zip(&challenger.objectives) {
            let denominator = baseline.value.abs().max(1e-12);
            let improvement = if baseline.minimize {
                (baseline.value - candidate.value) / denominator
            } else {
                (candidate.value - baseline.value) / denominator
            };
            improvements.push(improvement);
        }

        if improvements
            .iter()
            .skip(1)
            .any(|improvement| *improvement < -self.max_relative_regression)
        {
            return AdoptionReceipt::new(
                challenger,
                self.policy_id.clone(),
                AdoptionDecision::Reject,
                "challenger regresses a protected secondary objective",
                Some(champion.candidate_fingerprint.clone()),
                None,
            );
        }

        if improvements[0] < self.min_primary_relative_improvement {
            return AdoptionReceipt::new(
                challenger,
                self.policy_id.clone(),
                AdoptionDecision::Reject,
                "challenger does not meet the primary improvement threshold",
                Some(champion.candidate_fingerprint.clone()),
                None,
            );
        }

        let adoption = AdoptionReceipt::new(
            challenger,
            self.policy_id.clone(),
            AdoptionDecision::Promote,
            "challenger passed comparable champion/challenger objective gates",
            Some(champion.candidate_fingerprint.clone()),
            promoted_artifact_sha256,
        )?;
        validate_adoption(challenger, &adoption)?;
        Ok(adoption)
    }

    fn require_comparable(
        &self,
        champion: &EvaluationReceipt,
        challenger: &EvaluationReceipt,
    ) -> Result<(), CandidateProtocolError> {
        if champion.evaluator_id != challenger.evaluator_id
            || champion.sandbox_policy_id != challenger.sandbox_policy_id
            || champion.execution_profile_sha256 != challenger.execution_profile_sha256
            || champion.verifier_sha256 != challenger.verifier_sha256
        {
            return Err(CandidateProtocolError::PolicyViolation(
                "champion and challenger were not measured under the same execution contract"
                    .into(),
            ));
        }
        if champion.objectives.is_empty() || champion.objectives.len() != challenger.objectives.len()
        {
            return Err(CandidateProtocolError::PolicyViolation(
                "champion and challenger objective schemas differ".into(),
            ));
        }
        for (baseline, candidate) in champion.objectives.iter().zip(&challenger.objectives) {
            if baseline.name != candidate.name || baseline.minimize != candidate.minimize {
                return Err(CandidateProtocolError::PolicyViolation(
                    "champion and challenger objective schemas differ".into(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(seed: u64, source: &[u8]) -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "simd_gemm",
            source,
            None,
            None,
            None,
            seed,
        )
        .unwrap()
    }

    fn evaluation(candidate: &CandidateEnvelope, latency: f64, memory: f64) -> EvaluationReceipt {
        EvaluationReceipt {
            schema_version: CANDIDATE_PROTOCOL_VERSION,
            candidate_fingerprint: candidate.fingerprint(),
            evaluator_id: "forge-scirust-v1".into(),
            sandbox_policy_id: "research-airgap-v1".into(),
            execution_profile_sha256: Some("a".repeat(64)),
            verifier_sha256: Some("b".repeat(64)),
            trial_seed: candidate.trial_seed,
            status: EvaluationStatus::Succeeded,
            objectives: vec![
                ObjectiveValue::new("latency_ns", latency, true).unwrap(),
                ObjectiveValue::new("memory_bytes", memory, true).unwrap(),
            ],
            stdout_sha256: "c".repeat(64),
            stderr_sha256: "d".repeat(64),
            timed_out: false,
            output_truncated: false,
            failure_reason: None,
        }
    }

    #[test]
    fn forged_candidate_identity_is_rejected() {
        let mut candidate = candidate(1, b"a");
        candidate.candidate_id = "0".repeat(64);
        assert!(validate_candidate(&candidate).is_err());
    }

    #[test]
    fn evaluation_must_bind_candidate_and_trial() {
        let candidate = candidate(2, b"a");
        let mut receipt = evaluation(&candidate, 100.0, 10.0);
        assert!(validate_evaluation(&candidate, &receipt).is_ok());
        receipt.trial_seed += 1;
        assert!(validate_evaluation(&candidate, &receipt).is_err());
    }

    #[test]
    fn failed_evaluation_cannot_be_promoted() {
        let candidate = candidate(3, b"a");
        let mut receipt = evaluation(&candidate, 100.0, 10.0);
        receipt.status = EvaluationStatus::CandidateFailed;
        receipt.objectives.clear();
        receipt.failure_reason = Some("failed".into());
        let adoption = AdoptionReceipt::new(
            &receipt,
            "policy",
            AdoptionDecision::Promote,
            "bad",
            None,
            Some("e".repeat(64)),
        )
        .unwrap();
        assert!(validate_adoption(&receipt, &adoption).is_err());
    }

    #[test]
    fn champion_challenger_promotes_only_comparable_gain() {
        let champion_candidate = candidate(4, b"champion");
        let challenger_candidate = candidate(4, b"challenger");
        let champion = evaluation(&champion_candidate, 100.0, 100.0);
        let challenger = evaluation(&challenger_candidate, 85.0, 102.0);
        let policy = ChampionChallengerPolicy::new("cc-v1", 0.10, 0.05).unwrap();
        let adoption = policy
            .decide(&champion, &challenger, Some("f".repeat(64)))
            .unwrap();
        assert_eq!(adoption.decision, AdoptionDecision::Promote);
    }

    #[test]
    fn champion_challenger_rejects_secondary_regression() {
        let champion_candidate = candidate(5, b"champion");
        let challenger_candidate = candidate(5, b"challenger");
        let champion = evaluation(&champion_candidate, 100.0, 100.0);
        let challenger = evaluation(&challenger_candidate, 80.0, 120.0);
        let policy = ChampionChallengerPolicy::new("cc-v1", 0.10, 0.05).unwrap();
        let adoption = policy
            .decide(&champion, &challenger, Some("f".repeat(64)))
            .unwrap();
        assert_eq!(adoption.decision, AdoptionDecision::Reject);
    }

    #[test]
    fn changed_execution_profile_is_not_comparable() {
        let champion_candidate = candidate(6, b"champion");
        let challenger_candidate = candidate(6, b"challenger");
        let champion = evaluation(&champion_candidate, 100.0, 100.0);
        let mut challenger = evaluation(&challenger_candidate, 80.0, 100.0);
        challenger.execution_profile_sha256 = Some("9".repeat(64));
        let policy = ChampionChallengerPolicy::new("cc-v1", 0.10, 0.05).unwrap();
        assert!(policy
            .decide(&champion, &challenger, Some("f".repeat(64)))
            .is_err());
    }
}
