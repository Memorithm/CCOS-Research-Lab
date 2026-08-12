//! Deterministic JSON transport for candidate protocol v1.
//!
//! JSON is transport only: receipt fingerprints remain the canonical binary
//! encodings defined by `candidate_protocol`. u64 values are canonical decimal
//! strings and f64 objectives are transported by their exact lowercase
//! IEEE-754 bit pattern so a JSON parser cannot silently change experiment
//! identity.

use std::collections::{BTreeMap, BTreeSet};

use crate::candidate_policy::{validate_adoption, validate_candidate, validate_evaluation};
use crate::candidate_protocol::{
    AdoptionDecision, AdoptionReceipt, CandidateEnvelope, CandidateOrigin, CandidateProtocolError,
    EvaluationReceipt, EvaluationStatus, ObjectiveValue,
};
use crate::Json;

#[derive(Debug)]
pub enum CandidateWireError {
    Parse(String),
    Invalid(&'static str),
    Protocol(CandidateProtocolError),
}

impl std::fmt::Display for CandidateWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CandidateWireError {}

impl From<CandidateProtocolError> for CandidateWireError {
    fn from(value: CandidateProtocolError) -> Self {
        Self::Protocol(value)
    }
}

fn option_string(value: Option<&str>) -> Json {
    value
        .map(|value| Json::Str(value.to_string()))
        .unwrap_or(Json::Null)
}

fn require_object(value: Json) -> Result<BTreeMap<String, Json>, CandidateWireError> {
    match value {
        Json::Obj(map) => Ok(map),
        _ => Err(CandidateWireError::Invalid("wire.object")),
    }
}

fn require_exact_keys(
    map: &BTreeMap<String, Json>,
    keys: &[&str],
) -> Result<(), CandidateWireError> {
    let expected: BTreeSet<&str> = keys.iter().copied().collect();
    let actual: BTreeSet<&str> = map.keys().map(String::as_str).collect();
    if expected == actual {
        Ok(())
    } else {
        Err(CandidateWireError::Invalid("wire.keys"))
    }
}

fn required_string(
    map: &BTreeMap<String, Json>,
    key: &'static str,
) -> Result<String, CandidateWireError> {
    map.get(key)
        .and_then(Json::as_str)
        .map(str::to_string)
        .ok_or(CandidateWireError::Invalid(key))
}

fn optional_string(
    map: &BTreeMap<String, Json>,
    key: &'static str,
) -> Result<Option<String>, CandidateWireError> {
    match map.get(key) {
        Some(Json::Null) => Ok(None),
        Some(Json::Str(value)) => Ok(Some(value.clone())),
        _ => Err(CandidateWireError::Invalid(key)),
    }
}

fn required_bool(
    map: &BTreeMap<String, Json>,
    key: &'static str,
) -> Result<bool, CandidateWireError> {
    map.get(key)
        .and_then(Json::as_bool)
        .ok_or(CandidateWireError::Invalid(key))
}

fn required_u16(
    map: &BTreeMap<String, Json>,
    key: &'static str,
) -> Result<u16, CandidateWireError> {
    let value = map
        .get(key)
        .and_then(Json::as_f64)
        .filter(|value| {
            value.is_finite() && *value >= 0.0 && value.fract() == 0.0 && *value <= u16::MAX as f64
        })
        .ok_or(CandidateWireError::Invalid(key))?;
    Ok(value as u16)
}

fn required_u64_string(
    map: &BTreeMap<String, Json>,
    key: &'static str,
) -> Result<u64, CandidateWireError> {
    let raw = required_string(map, key)?;
    let value = raw
        .parse::<u64>()
        .map_err(|_| CandidateWireError::Invalid(key))?;
    if value.to_string() != raw {
        return Err(CandidateWireError::Invalid(key));
    }
    Ok(value)
}

fn origin_name(origin: CandidateOrigin) -> &'static str {
    match origin {
        CandidateOrigin::Forge => "forge",
        CandidateOrigin::Rsi => "rsi",
        CandidateOrigin::SciRust => "scirust",
        CandidateOrigin::External => "external",
    }
}

fn parse_origin(value: &str) -> Result<CandidateOrigin, CandidateWireError> {
    match value {
        "forge" => Ok(CandidateOrigin::Forge),
        "rsi" => Ok(CandidateOrigin::Rsi),
        "scirust" => Ok(CandidateOrigin::SciRust),
        "external" => Ok(CandidateOrigin::External),
        _ => Err(CandidateWireError::Invalid("candidate.origin")),
    }
}

fn status_name(status: EvaluationStatus) -> &'static str {
    match status {
        EvaluationStatus::Succeeded => "succeeded",
        EvaluationStatus::CandidateFailed => "candidate_failed",
        EvaluationStatus::InfrastructureFailed => "infrastructure_failed",
    }
}

fn parse_status(value: &str) -> Result<EvaluationStatus, CandidateWireError> {
    match value {
        "succeeded" => Ok(EvaluationStatus::Succeeded),
        "candidate_failed" => Ok(EvaluationStatus::CandidateFailed),
        "infrastructure_failed" => Ok(EvaluationStatus::InfrastructureFailed),
        _ => Err(CandidateWireError::Invalid("evaluation.status")),
    }
}

fn decision_name(decision: AdoptionDecision) -> &'static str {
    match decision {
        AdoptionDecision::Promote => "promote",
        AdoptionDecision::Reject => "reject",
        AdoptionDecision::Quarantine => "quarantine",
    }
}

fn parse_decision(value: &str) -> Result<AdoptionDecision, CandidateWireError> {
    match value {
        "promote" => Ok(AdoptionDecision::Promote),
        "reject" => Ok(AdoptionDecision::Reject),
        "quarantine" => Ok(AdoptionDecision::Quarantine),
        _ => Err(CandidateWireError::Invalid("adoption.decision")),
    }
}

pub fn encode_candidate(candidate: &CandidateEnvelope) -> Result<String, CandidateWireError> {
    validate_candidate(candidate)?;
    let mut json = Json::obj();
    json.set("candidate_id", Json::Str(candidate.candidate_id.clone()))
        .set("domain", Json::Str(candidate.domain.clone()))
        .set("fingerprint", Json::Str(candidate.fingerprint()))
        .set(
            "origin",
            Json::Str(origin_name(candidate.origin).to_string()),
        )
        .set(
            "parent_candidate_id",
            option_string(candidate.parent_candidate_id.as_deref()),
        )
        .set(
            "producer_candidate_id",
            option_string(candidate.producer_candidate_id.as_deref()),
        )
        .set(
            "proposal_sha256",
            option_string(candidate.proposal_sha256.as_deref()),
        )
        .set("schema_version", Json::Num(candidate.schema_version as f64))
        .set("source_sha256", Json::Str(candidate.source_sha256.clone()))
        .set("trial_seed", Json::Str(candidate.trial_seed.to_string()));
    Ok(json.to_string())
}

pub fn decode_candidate(input: &str) -> Result<CandidateEnvelope, CandidateWireError> {
    let map = require_object(Json::parse(input).map_err(CandidateWireError::Parse)?)?;
    require_exact_keys(
        &map,
        &[
            "candidate_id",
            "domain",
            "fingerprint",
            "origin",
            "parent_candidate_id",
            "producer_candidate_id",
            "proposal_sha256",
            "schema_version",
            "source_sha256",
            "trial_seed",
        ],
    )?;
    let fingerprint = required_string(&map, "fingerprint")?;
    let candidate = CandidateEnvelope {
        schema_version: required_u16(&map, "schema_version")?,
        candidate_id: required_string(&map, "candidate_id")?,
        producer_candidate_id: optional_string(&map, "producer_candidate_id")?,
        parent_candidate_id: optional_string(&map, "parent_candidate_id")?,
        origin: parse_origin(&required_string(&map, "origin")?)?,
        domain: required_string(&map, "domain")?,
        source_sha256: required_string(&map, "source_sha256")?,
        proposal_sha256: optional_string(&map, "proposal_sha256")?,
        trial_seed: required_u64_string(&map, "trial_seed")?,
    };
    validate_candidate(&candidate)?;
    if candidate.fingerprint() != fingerprint {
        return Err(CandidateWireError::Invalid("candidate.fingerprint"));
    }
    Ok(candidate)
}

fn encode_objective(objective: &ObjectiveValue) -> Json {
    let mut json = Json::obj();
    json.set("minimize", Json::Bool(objective.minimize))
        .set("name", Json::Str(objective.name.clone()))
        .set(
            "value_bits",
            Json::Str(format!("{:016x}", objective.value.to_bits())),
        );
    json
}

fn decode_objective(value: Json) -> Result<ObjectiveValue, CandidateWireError> {
    let map = require_object(value)?;
    require_exact_keys(&map, &["minimize", "name", "value_bits"])?;
    let bits = required_string(&map, "value_bits")?;
    if bits.len() != 16
        || !bits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CandidateWireError::Invalid("objective.value_bits"));
    }
    let bits = u64::from_str_radix(&bits, 16)
        .map_err(|_| CandidateWireError::Invalid("objective.value_bits"))?;
    ObjectiveValue::new(
        required_string(&map, "name")?,
        f64::from_bits(bits),
        required_bool(&map, "minimize")?,
    )
    .map_err(Into::into)
}

pub fn encode_evaluation(
    candidate: &CandidateEnvelope,
    receipt: &EvaluationReceipt,
) -> Result<String, CandidateWireError> {
    validate_evaluation(candidate, receipt)?;
    let mut json = Json::obj();
    json.set(
        "candidate_fingerprint",
        Json::Str(receipt.candidate_fingerprint.clone()),
    )
    .set("evaluator_id", Json::Str(receipt.evaluator_id.clone()))
    .set(
        "execution_profile_sha256",
        option_string(receipt.execution_profile_sha256.as_deref()),
    )
    .set(
        "failure_reason",
        option_string(receipt.failure_reason.as_deref()),
    )
    .set("fingerprint", Json::Str(receipt.fingerprint()))
    .set(
        "objectives",
        Json::Arr(receipt.objectives.iter().map(encode_objective).collect()),
    )
    .set("output_truncated", Json::Bool(receipt.output_truncated))
    .set(
        "sandbox_policy_id",
        Json::Str(receipt.sandbox_policy_id.clone()),
    )
    .set("schema_version", Json::Num(receipt.schema_version as f64))
    .set("status", Json::Str(status_name(receipt.status).to_string()))
    .set("stderr_sha256", Json::Str(receipt.stderr_sha256.clone()))
    .set("stdout_sha256", Json::Str(receipt.stdout_sha256.clone()))
    .set("timed_out", Json::Bool(receipt.timed_out))
    .set("trial_seed", Json::Str(receipt.trial_seed.to_string()))
    .set(
        "verifier_sha256",
        option_string(receipt.verifier_sha256.as_deref()),
    );
    Ok(json.to_string())
}

pub fn decode_evaluation(
    input: &str,
    candidate: &CandidateEnvelope,
) -> Result<EvaluationReceipt, CandidateWireError> {
    let map = require_object(Json::parse(input).map_err(CandidateWireError::Parse)?)?;
    require_exact_keys(
        &map,
        &[
            "candidate_fingerprint",
            "evaluator_id",
            "execution_profile_sha256",
            "failure_reason",
            "fingerprint",
            "objectives",
            "output_truncated",
            "sandbox_policy_id",
            "schema_version",
            "status",
            "stderr_sha256",
            "stdout_sha256",
            "timed_out",
            "trial_seed",
            "verifier_sha256",
        ],
    )?;
    let fingerprint = required_string(&map, "fingerprint")?;
    let objectives = map
        .get("objectives")
        .and_then(Json::as_array)
        .ok_or(CandidateWireError::Invalid("evaluation.objectives"))?
        .iter()
        .cloned()
        .map(decode_objective)
        .collect::<Result<Vec<_>, _>>()?;
    let receipt = EvaluationReceipt {
        schema_version: required_u16(&map, "schema_version")?,
        candidate_fingerprint: required_string(&map, "candidate_fingerprint")?,
        evaluator_id: required_string(&map, "evaluator_id")?,
        sandbox_policy_id: required_string(&map, "sandbox_policy_id")?,
        execution_profile_sha256: optional_string(&map, "execution_profile_sha256")?,
        verifier_sha256: optional_string(&map, "verifier_sha256")?,
        trial_seed: required_u64_string(&map, "trial_seed")?,
        status: parse_status(&required_string(&map, "status")?)?,
        objectives,
        stdout_sha256: required_string(&map, "stdout_sha256")?,
        stderr_sha256: required_string(&map, "stderr_sha256")?,
        timed_out: required_bool(&map, "timed_out")?,
        output_truncated: required_bool(&map, "output_truncated")?,
        failure_reason: optional_string(&map, "failure_reason")?,
    };
    validate_evaluation(candidate, &receipt)?;
    if receipt.fingerprint() != fingerprint {
        return Err(CandidateWireError::Invalid("evaluation.fingerprint"));
    }
    Ok(receipt)
}

pub fn encode_adoption(
    evaluation: &EvaluationReceipt,
    receipt: &AdoptionReceipt,
) -> Result<String, CandidateWireError> {
    validate_adoption(evaluation, receipt)?;
    let mut json = Json::obj();
    json.set(
        "decision",
        Json::Str(decision_name(receipt.decision).to_string()),
    )
    .set(
        "evaluation_fingerprint",
        Json::Str(receipt.evaluation_fingerprint.clone()),
    )
    .set("fingerprint", Json::Str(receipt.fingerprint()))
    .set("policy_id", Json::Str(receipt.policy_id.clone()))
    .set(
        "previous_champion_id",
        option_string(receipt.previous_champion_id.as_deref()),
    )
    .set(
        "promoted_artifact_sha256",
        option_string(receipt.promoted_artifact_sha256.as_deref()),
    )
    .set("reason", Json::Str(receipt.reason.clone()))
    .set("schema_version", Json::Num(receipt.schema_version as f64));
    Ok(json.to_string())
}

pub fn decode_adoption(
    input: &str,
    evaluation: &EvaluationReceipt,
) -> Result<AdoptionReceipt, CandidateWireError> {
    let map = require_object(Json::parse(input).map_err(CandidateWireError::Parse)?)?;
    require_exact_keys(
        &map,
        &[
            "decision",
            "evaluation_fingerprint",
            "fingerprint",
            "policy_id",
            "previous_champion_id",
            "promoted_artifact_sha256",
            "reason",
            "schema_version",
        ],
    )?;
    let fingerprint = required_string(&map, "fingerprint")?;
    let receipt = AdoptionReceipt {
        schema_version: required_u16(&map, "schema_version")?,
        evaluation_fingerprint: required_string(&map, "evaluation_fingerprint")?,
        policy_id: required_string(&map, "policy_id")?,
        decision: parse_decision(&required_string(&map, "decision")?)?,
        reason: required_string(&map, "reason")?,
        previous_champion_id: optional_string(&map, "previous_champion_id")?,
        promoted_artifact_sha256: optional_string(&map, "promoted_artifact_sha256")?,
    };
    validate_adoption(evaluation, &receipt)?;
    if receipt.fingerprint() != fingerprint {
        return Err(CandidateWireError::Invalid("adoption.fingerprint"));
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_protocol::CANDIDATE_PROTOCOL_VERSION;

    fn candidate(seed: u64) -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "simd_gemm",
            b"fn kernel() {}",
            Some("18446744073709551615".into()),
            None,
            None,
            seed,
        )
        .unwrap()
    }

    fn evaluation(candidate: &CandidateEnvelope) -> EvaluationReceipt {
        EvaluationReceipt {
            schema_version: CANDIDATE_PROTOCOL_VERSION,
            candidate_fingerprint: candidate.fingerprint(),
            evaluator_id: "forge-scirust-v1".into(),
            sandbox_policy_id: "research-airgap-v1".into(),
            execution_profile_sha256: Some(
                "f0423da9a3c6c2e43f6e75acd4cd017bd020a0f21d65112a73d1076026c10826".into(),
            ),
            verifier_sha256: Some("b".repeat(64)),
            trial_seed: candidate.trial_seed,
            status: EvaluationStatus::Succeeded,
            objectives: vec![ObjectiveValue::new("latency_ns", 1.0 / 3.0, true).unwrap()],
            stdout_sha256: "c".repeat(64),
            stderr_sha256: "d".repeat(64),
            timed_out: false,
            output_truncated: false,
            failure_reason: None,
        }
    }

    #[test]
    fn candidate_wire_preserves_full_u64_seed() {
        let original = candidate(u64::MAX);
        let wire = encode_candidate(&original).unwrap();
        let decoded = decode_candidate(&wire).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.trial_seed, u64::MAX);
    }

    #[test]
    fn noncanonical_u64_seed_is_rejected() {
        let original = candidate(7);
        let wire = encode_candidate(&original).unwrap();
        let tampered = wire.replace("\"trial_seed\":\"7\"", "\"trial_seed\":\"007\"");
        assert!(decode_candidate(&tampered).is_err());
    }

    #[test]
    fn fractional_schema_version_is_rejected() {
        let original = candidate(7);
        let wire = encode_candidate(&original).unwrap();
        let tampered = wire.replace("\"schema_version\":1", "\"schema_version\":1.5");
        assert!(decode_candidate(&tampered).is_err());
    }

    #[test]
    fn evaluation_wire_preserves_exact_f64_bits_and_scirust_fingerprint() {
        let candidate = candidate(7);
        let original = evaluation(&candidate);
        let wire = encode_evaluation(&candidate, &original).unwrap();
        let decoded = decode_evaluation(&wire, &candidate).unwrap();
        assert_eq!(
            decoded.objectives[0].value.to_bits(),
            original.objectives[0].value.to_bits()
        );
        assert_eq!(decoded.fingerprint(), original.fingerprint());
    }

    #[test]
    fn uppercase_objective_bits_are_rejected_as_noncanonical() {
        let candidate = candidate(8);
        let original = evaluation(&candidate);
        let wire = encode_evaluation(&candidate, &original).unwrap();
        let bits = format!("{:016x}", original.objectives[0].value.to_bits());
        let uppercase = bits.to_ascii_uppercase();
        if uppercase != bits {
            let tampered = wire.replace(&bits, &uppercase);
            assert!(decode_evaluation(&tampered, &candidate).is_err());
        }
    }

    #[test]
    fn adoption_wire_round_trip_is_fingerprint_exact() {
        let candidate = candidate(9);
        let evaluation = evaluation(&candidate);
        let original = AdoptionReceipt::new(
            &evaluation,
            "repeat-v1",
            AdoptionDecision::Promote,
            format!("holdout passed; evidence_sha256={}", "f".repeat(64)),
            None,
            Some("e".repeat(64)),
        )
        .unwrap();
        let wire = encode_adoption(&evaluation, &original).unwrap();
        let decoded = decode_adoption(&wire, &evaluation).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.fingerprint(), original.fingerprint());
    }

    #[test]
    fn unknown_wire_field_is_rejected() {
        let original = candidate(11);
        let wire = encode_candidate(&original).unwrap();
        let tampered = wire.replacen('{', "{\"unexpected\":true,", 1);
        assert!(decode_candidate(&tampered).is_err());
    }

    #[test]
    fn fingerprint_tampering_is_rejected() {
        let original = candidate(13);
        let wire = encode_candidate(&original).unwrap();
        let tampered = wire.replace(&original.fingerprint(), &"0".repeat(64));
        assert!(decode_candidate(&tampered).is_err());
    }
}
