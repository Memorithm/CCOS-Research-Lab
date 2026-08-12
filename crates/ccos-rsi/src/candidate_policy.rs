//! Fail-closed validation and promotion policy for candidate receipts.
//!
//! A single champion/challenger comparison is only a selection gate. Actual
//! promotion requires repeated paired measurements on a selection seed set and
//! a disjoint holdout seed set. The resulting evidence bundle has its own
//! canonical SHA-256 fingerprint, which is embedded into the canonical adoption
//! reason so the final `AdoptionReceipt` is cryptographically bound to the exact
//! receipts that justified the decision.

use std::collections::BTreeSet;

use crate::candidate_protocol::{
    AdoptionDecision, AdoptionReceipt, CandidateEnvelope, CandidateOrigin, CandidateProtocolError,
    EvaluationReceipt, EvaluationStatus, ObjectiveValue, CANDIDATE_PROTOCOL_VERSION,
};
use crate::sha256::sha256;

const MAX_BPS: u16 = 10_000;

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
        return Err(CandidateProtocolError::InvalidField(
            "candidate.schema_version",
        ));
    }
    if candidate.domain.trim().is_empty() {
        return Err(CandidateProtocolError::InvalidField("candidate.domain"));
    }
    if !is_sha256_hex(&candidate.source_sha256) {
        return Err(CandidateProtocolError::InvalidField(
            "candidate.source_sha256",
        ));
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
        return Err(CandidateProtocolError::InvalidField(
            "evaluation.evaluator_id",
        ));
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
            if receipt.timed_out
                || receipt.failure_reason.is_some()
                || receipt.objectives.is_empty()
            {
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
        return Err(CandidateProtocolError::InvalidField(
            "adoption.schema_version",
        ));
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
        if !adoption.reason.contains("evidence_sha256=") {
            return Err(CandidateProtocolError::PolicyViolation(
                "promotion requires a canonical repeated-seed evidence binding".into(),
            ));
        }
    }
    Ok(())
}

fn require_comparable(
    champion: &EvaluationReceipt,
    challenger: &EvaluationReceipt,
) -> Result<(), CandidateProtocolError> {
    if champion.evaluator_id != challenger.evaluator_id
        || champion.sandbox_policy_id != challenger.sandbox_policy_id
        || champion.execution_profile_sha256 != challenger.execution_profile_sha256
        || champion.verifier_sha256 != challenger.verifier_sha256
    {
        return Err(CandidateProtocolError::PolicyViolation(
            "champion and challenger were not measured under the same execution contract".into(),
        ));
    }
    if champion.objectives.is_empty() || champion.objectives.len() != challenger.objectives.len() {
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

fn relative_improvements(
    champion: &EvaluationReceipt,
    challenger: &EvaluationReceipt,
) -> Result<Vec<f64>, CandidateProtocolError> {
    require_comparable(champion, challenger)?;
    let mut improvements = Vec::with_capacity(champion.objectives.len());
    for (baseline, candidate) in champion.objectives.iter().zip(&challenger.objectives) {
        let denominator = baseline.value.abs().max(1e-12);
        let improvement = if baseline.minimize {
            (baseline.value - candidate.value) / denominator
        } else {
            (candidate.value - baseline.value) / denominator
        };
        if !improvement.is_finite() {
            return Err(CandidateProtocolError::PolicyViolation(
                "relative objective improvement is non-finite".into(),
            ));
        }
        improvements.push(improvement);
    }
    Ok(improvements)
}

/// Fast single-seed selection gate.
///
/// Passing this gate no longer authorizes promotion. It returns `Quarantine`,
/// meaning “eligible for repeated-seed holdout”. Only
/// [`RepeatedSeedPromotionPolicy`] can emit `Promote`.
#[derive(Clone, Debug)]
pub struct ChampionChallengerPolicy {
    pub policy_id: String,
    pub min_primary_relative_improvement: f64,
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
        _promoted_artifact_sha256: Option<String>,
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
        let improvements = relative_improvements(champion, challenger)?;

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

        AdoptionReceipt::new(
            challenger,
            self.policy_id.clone(),
            AdoptionDecision::Quarantine,
            "single-seed gate passed; repeated-seed disjoint holdout is required for promotion",
            Some(champion.candidate_fingerprint.clone()),
            None,
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EvaluationPair<'a> {
    pub champion_candidate: &'a CandidateEnvelope,
    pub champion: &'a EvaluationReceipt,
    pub challenger_candidate: &'a CandidateEnvelope,
    pub challenger: &'a EvaluationReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeedEvidence {
    seed: u64,
    champion_candidate_id: String,
    challenger_candidate_id: String,
    champion_envelope_fingerprint: String,
    challenger_envelope_fingerprint: String,
    champion_evaluation_fingerprint: String,
    challenger_evaluation_fingerprint: String,
}

impl SeedEvidence {
    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn champion_evaluation_fingerprint(&self) -> &str {
        &self.champion_evaluation_fingerprint
    }

    pub fn challenger_evaluation_fingerprint(&self) -> &str {
        &self.challenger_evaluation_fingerprint
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionEvidenceBundle {
    champion_candidate_id: String,
    challenger_candidate_id: String,
    selection: Vec<SeedEvidence>,
    holdout: Vec<SeedEvidence>,
}

impl PromotionEvidenceBundle {
    fn from_pairs(
        selection: &[EvaluationPair<'_>],
        holdout: &[EvaluationPair<'_>],
    ) -> Result<Self, CandidateProtocolError> {
        let first = selection
            .first()
            .or_else(|| holdout.first())
            .ok_or_else(|| {
                CandidateProtocolError::PolicyViolation("empty evidence bundle".into())
            })?;
        let champion_candidate_id = first.champion_candidate.candidate_id.clone();
        let challenger_candidate_id = first.challenger_candidate.candidate_id.clone();
        if champion_candidate_id == challenger_candidate_id {
            return Err(CandidateProtocolError::PolicyViolation(
                "champion and challenger must be different content-addressed candidates".into(),
            ));
        }

        let selection_entries = Self::validate_stage(
            selection,
            &champion_candidate_id,
            &challenger_candidate_id,
            first,
        )?;
        let holdout_entries = Self::validate_stage(
            holdout,
            &champion_candidate_id,
            &challenger_candidate_id,
            first,
        )?;

        let selection_seeds: BTreeSet<u64> =
            selection_entries.iter().map(|entry| entry.seed).collect();
        if holdout_entries
            .iter()
            .any(|entry| selection_seeds.contains(&entry.seed))
        {
            return Err(CandidateProtocolError::PolicyViolation(
                "selection and holdout seed sets must be disjoint".into(),
            ));
        }

        Ok(Self {
            champion_candidate_id,
            challenger_candidate_id,
            selection: selection_entries,
            holdout: holdout_entries,
        })
    }

    fn validate_stage(
        pairs: &[EvaluationPair<'_>],
        champion_candidate_id: &str,
        challenger_candidate_id: &str,
        contract_anchor: &EvaluationPair<'_>,
    ) -> Result<Vec<SeedEvidence>, CandidateProtocolError> {
        let mut seeds = BTreeSet::new();
        let mut entries = Vec::with_capacity(pairs.len());
        for pair in pairs {
            validate_evaluation(pair.champion_candidate, pair.champion)?;
            validate_evaluation(pair.challenger_candidate, pair.challenger)?;
            if pair.champion.status != EvaluationStatus::Succeeded
                || pair.challenger.status != EvaluationStatus::Succeeded
            {
                return Err(CandidateProtocolError::PolicyViolation(
                    "repeated-seed evidence requires successful paired evaluations".into(),
                ));
            }
            if pair.champion_candidate.trial_seed != pair.challenger_candidate.trial_seed
                || pair.champion.trial_seed != pair.challenger.trial_seed
                || pair.champion.trial_seed != pair.champion_candidate.trial_seed
            {
                return Err(CandidateProtocolError::PolicyViolation(
                    "champion/challenger evidence pair must use one identical trial seed".into(),
                ));
            }
            if !seeds.insert(pair.champion.trial_seed) {
                return Err(CandidateProtocolError::PolicyViolation(
                    "duplicate seed inside repeated-seed evidence stage".into(),
                ));
            }
            if pair.champion_candidate.candidate_id != champion_candidate_id
                || pair.challenger_candidate.candidate_id != challenger_candidate_id
            {
                return Err(CandidateProtocolError::PolicyViolation(
                    "all evidence rows must measure the same champion and challenger content"
                        .into(),
                ));
            }
            if pair.champion_candidate.domain != pair.challenger_candidate.domain
                || pair.champion_candidate.domain != contract_anchor.champion_candidate.domain
            {
                return Err(CandidateProtocolError::PolicyViolation(
                    "all evidence rows must use one candidate domain".into(),
                ));
            }
            require_comparable(pair.champion, pair.challenger)?;
            require_comparable(contract_anchor.champion, pair.champion)?;
            require_comparable(contract_anchor.champion, pair.challenger)?;

            entries.push(SeedEvidence {
                seed: pair.champion.trial_seed,
                champion_candidate_id: pair.champion_candidate.candidate_id.clone(),
                challenger_candidate_id: pair.challenger_candidate.candidate_id.clone(),
                champion_envelope_fingerprint: pair.champion_candidate.fingerprint(),
                challenger_envelope_fingerprint: pair.challenger_candidate.fingerprint(),
                champion_evaluation_fingerprint: pair.champion.fingerprint(),
                challenger_evaluation_fingerprint: pair.challenger.fingerprint(),
            });
        }
        entries.sort_by_key(|entry| entry.seed);
        Ok(entries)
    }

    pub fn selection(&self) -> &[SeedEvidence] {
        &self.selection
    }

    pub fn holdout(&self) -> &[SeedEvidence] {
        &self.holdout
    }

    pub fn champion_candidate_id(&self) -> &str {
        &self.champion_candidate_id
    }

    pub fn challenger_candidate_id(&self) -> &str {
        &self.challenger_candidate_id
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = b"memorithm.promotion-evidence.v1\0".to_vec();
        push_str(&mut out, &self.champion_candidate_id);
        push_str(&mut out, &self.challenger_candidate_id);
        Self::append_stage(&mut out, &self.selection);
        Self::append_stage(&mut out, &self.holdout);
        out
    }

    fn append_stage(out: &mut Vec<u8>, entries: &[SeedEvidence]) {
        push_u64(out, entries.len() as u64);
        for entry in entries {
            push_u64(out, entry.seed);
            push_str(out, &entry.champion_candidate_id);
            push_str(out, &entry.challenger_candidate_id);
            push_str(out, &entry.champion_envelope_fingerprint);
            push_str(out, &entry.challenger_envelope_fingerprint);
            push_str(out, &entry.champion_evaluation_fingerprint);
            push_str(out, &entry.challenger_evaluation_fingerprint);
        }
    }

    pub fn fingerprint(&self) -> String {
        digest_hex(&self.canonical_bytes())
    }

    pub fn audit_payload(&self) -> String {
        format!(
            "schema=1;evidence={};champion={};challenger={};selection={};holdout={}",
            self.fingerprint(),
            self.champion_candidate_id,
            self.challenger_candidate_id,
            self.selection.len(),
            self.holdout.len()
        )
    }
}

#[derive(Clone, Debug)]
pub struct RepeatedSeedDecision {
    adoption: AdoptionReceipt,
    evidence: PromotionEvidenceBundle,
}

impl RepeatedSeedDecision {
    pub fn adoption(&self) -> &AdoptionReceipt {
        &self.adoption
    }

    pub fn evidence(&self) -> &PromotionEvidenceBundle {
        &self.evidence
    }

    pub fn into_parts(self) -> (AdoptionReceipt, PromotionEvidenceBundle) {
        (self.adoption, self.evidence)
    }
}

#[derive(Clone, Debug)]
pub struct RepeatedSeedPromotionPolicy {
    pub policy_id: String,
    pub min_selection_pairs: usize,
    pub min_holdout_pairs: usize,
    pub min_primary_relative_improvement: f64,
    pub max_relative_regression: f64,
    pub min_primary_win_rate_bps: u16,
}

impl RepeatedSeedPromotionPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        min_selection_pairs: usize,
        min_holdout_pairs: usize,
        min_primary_relative_improvement: f64,
        max_relative_regression: f64,
        min_primary_win_rate_bps: u16,
    ) -> Result<Self, CandidateProtocolError> {
        let policy_id = policy_id.into();
        if policy_id.trim().is_empty() {
            return Err(CandidateProtocolError::InvalidField(
                "repeated_promotion.policy_id",
            ));
        }
        if min_selection_pairs == 0 || min_holdout_pairs == 0 {
            return Err(CandidateProtocolError::InvalidField(
                "repeated_promotion.minimum_pairs",
            ));
        }
        if !min_primary_relative_improvement.is_finite()
            || min_primary_relative_improvement < 0.0
            || !max_relative_regression.is_finite()
            || max_relative_regression < 0.0
            || min_primary_win_rate_bps > MAX_BPS
        {
            return Err(CandidateProtocolError::InvalidField(
                "repeated_promotion.threshold",
            ));
        }
        Ok(Self {
            policy_id,
            min_selection_pairs,
            min_holdout_pairs,
            min_primary_relative_improvement,
            max_relative_regression,
            min_primary_win_rate_bps,
        })
    }

    pub fn decide(
        &self,
        selection: &[EvaluationPair<'_>],
        holdout: &[EvaluationPair<'_>],
        promoted_artifact_sha256: Option<String>,
    ) -> Result<RepeatedSeedDecision, CandidateProtocolError> {
        if selection.len() < self.min_selection_pairs || holdout.len() < self.min_holdout_pairs {
            return Err(CandidateProtocolError::PolicyViolation(
                "insufficient paired evidence for repeated-seed promotion".into(),
            ));
        }
        let evidence = PromotionEvidenceBundle::from_pairs(selection, holdout)?;
        let evidence_fingerprint = evidence.fingerprint();
        let anchor = holdout
            .iter()
            .min_by_key(|pair| pair.challenger.trial_seed)
            .ok_or_else(|| CandidateProtocolError::PolicyViolation("holdout is empty".into()))?;

        let selection_passed = self.stage_passes(selection)?;
        let holdout_passed = self.stage_passes(holdout)?;
        let (decision, reason, artifact) = if !selection_passed {
            (
                AdoptionDecision::Reject,
                format!(
                    "selection repeated-seed gate failed; evidence_sha256={evidence_fingerprint}"
                ),
                None,
            )
        } else if !holdout_passed {
            (
                AdoptionDecision::Reject,
                format!("disjoint holdout gate failed; evidence_sha256={evidence_fingerprint}"),
                None,
            )
        } else {
            let artifact = promoted_artifact_sha256.ok_or_else(|| {
                CandidateProtocolError::PolicyViolation(
                    "successful repeated-seed promotion requires artifact digest".into(),
                )
            })?;
            if !is_sha256_hex(&artifact) {
                return Err(CandidateProtocolError::InvalidField(
                    "promotion.promoted_artifact_sha256",
                ));
            }
            (
                AdoptionDecision::Promote,
                format!(
                    "selection and disjoint holdout passed repeated-seed gates; evidence_sha256={evidence_fingerprint}"
                ),
                Some(artifact),
            )
        };

        let adoption = AdoptionReceipt::new(
            anchor.challenger,
            self.policy_id.clone(),
            decision,
            reason,
            Some(evidence.champion_candidate_id.clone()),
            artifact,
        )?;
        validate_adoption(anchor.challenger, &adoption)?;
        Ok(RepeatedSeedDecision { adoption, evidence })
    }

    fn stage_passes(&self, pairs: &[EvaluationPair<'_>]) -> Result<bool, CandidateProtocolError> {
        let mut primary = Vec::with_capacity(pairs.len());
        let mut wins = 0usize;
        for pair in pairs {
            let improvements = relative_improvements(pair.champion, pair.challenger)?;
            if improvements
                .iter()
                .skip(1)
                .any(|value| *value < -self.max_relative_regression)
            {
                return Ok(false);
            }
            let primary_improvement = improvements[0];
            if primary_improvement >= self.min_primary_relative_improvement {
                wins += 1;
            }
            primary.push(primary_improvement);
        }
        primary.sort_by(f64::total_cmp);
        let lower_median = primary[(primary.len() - 1) / 2];
        let win_rate_passes = wins.saturating_mul(MAX_BPS as usize)
            >= pairs
                .len()
                .saturating_mul(self.min_primary_win_rate_bps as usize);
        Ok(lower_median >= self.min_primary_relative_improvement && win_rate_passes)
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

    fn pair(
        seed: u64,
        challenger_latency: f64,
    ) -> (
        CandidateEnvelope,
        EvaluationReceipt,
        CandidateEnvelope,
        EvaluationReceipt,
    ) {
        let champion_candidate = candidate(seed, b"champion");
        let challenger_candidate = candidate(seed, b"challenger");
        let champion = evaluation(&champion_candidate, 100.0, 100.0);
        let challenger = evaluation(&challenger_candidate, challenger_latency, 102.0);
        (
            champion_candidate,
            champion,
            challenger_candidate,
            challenger,
        )
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
    fn single_seed_gain_only_quarantines_for_holdout() {
        let champion_candidate = candidate(4, b"champion");
        let challenger_candidate = candidate(4, b"challenger");
        let champion = evaluation(&champion_candidate, 100.0, 100.0);
        let challenger = evaluation(&challenger_candidate, 85.0, 102.0);
        let policy = ChampionChallengerPolicy::new("cc-v1", 0.10, 0.05).unwrap();
        let adoption = policy
            .decide(&champion, &challenger, Some("f".repeat(64)))
            .unwrap();
        assert_eq!(adoption.decision, AdoptionDecision::Quarantine);
        assert_eq!(adoption.promoted_artifact_sha256, None);
    }

    #[test]
    fn champion_challenger_rejects_secondary_regression() {
        let champion_candidate = candidate(5, b"champion");
        let challenger_candidate = candidate(5, b"challenger");
        let champion = evaluation(&champion_candidate, 100.0, 100.0);
        let challenger = evaluation(&challenger_candidate, 80.0, 120.0);
        let policy = ChampionChallengerPolicy::new("cc-v1", 0.10, 0.05).unwrap();
        let adoption = policy.decide(&champion, &challenger, None).unwrap();
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
        assert!(policy.decide(&champion, &challenger, None).is_err());
    }

    #[test]
    fn repeated_seed_disjoint_holdout_can_promote() {
        let s1 = pair(101, 80.0);
        let s2 = pair(102, 82.0);
        let h1 = pair(201, 85.0);
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
            RepeatedSeedPromotionPolicy::new("repeat-v1", 2, 2, 0.10, 0.05, 10_000).unwrap();
        let decision = policy
            .decide(&selection, &holdout, Some("f".repeat(64)))
            .unwrap();
        assert_eq!(decision.adoption().decision, AdoptionDecision::Promote);
        assert!(decision
            .adoption()
            .reason
            .contains(&decision.evidence().fingerprint()));
        assert_eq!(decision.evidence().selection().len(), 2);
        assert_eq!(decision.evidence().holdout().len(), 2);
    }

    #[test]
    fn repeated_seed_overlap_between_selection_and_holdout_is_rejected() {
        let s1 = pair(101, 80.0);
        let h1 = pair(101, 80.0);
        let selection = [EvaluationPair {
            champion_candidate: &s1.0,
            champion: &s1.1,
            challenger_candidate: &s1.2,
            challenger: &s1.3,
        }];
        let holdout = [EvaluationPair {
            champion_candidate: &h1.0,
            champion: &h1.1,
            challenger_candidate: &h1.2,
            challenger: &h1.3,
        }];
        let policy =
            RepeatedSeedPromotionPolicy::new("repeat-v1", 1, 1, 0.10, 0.05, 10_000).unwrap();
        assert!(policy
            .decide(&selection, &holdout, Some("f".repeat(64)))
            .is_err());
    }

    #[test]
    fn repeated_seed_holdout_failure_blocks_promotion() {
        let s1 = pair(101, 80.0);
        let s2 = pair(102, 82.0);
        let h1 = pair(201, 99.0);
        let h2 = pair(202, 100.0);
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
            RepeatedSeedPromotionPolicy::new("repeat-v1", 2, 2, 0.10, 0.05, 10_000).unwrap();
        let decision = policy
            .decide(&selection, &holdout, Some("f".repeat(64)))
            .unwrap();
        assert_eq!(decision.adoption().decision, AdoptionDecision::Reject);
        assert_eq!(decision.adoption().promoted_artifact_sha256, None);
    }
}
