//! Deterministic counterexample generation and shrinking.
//!
//! This module is intentionally execution-agnostic: it never runs generated
//! candidate code directly. Production oracles must be adapters over the sealed
//! sandbox/evaluation boundary. Infrastructure failures are fail-closed errors,
//! never semantic counterexamples.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use crate::candidate_policy::validate_candidate;
use crate::candidate_protocol::{CandidateEnvelope, CandidateProtocolError};
use crate::sha256::sha256;

pub const COUNTEREXAMPLE_PROTOCOL_VERSION: u16 = 1;

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

fn validate_id(value: &str, field: &'static str) -> Result<(), CandidateProtocolError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b';' && byte != b'=');
    if valid {
        Ok(())
    } else {
        Err(CandidateProtocolError::InvalidField(field))
    }
}

fn validate_failure_kind(value: &str) -> Result<(), CandidateProtocolError> {
    validate_id(value, "counterexample.failure_kind")
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    push_u64(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleVerdict {
    Pass,
    Counterexample { failure_kind: String },
    InfrastructureFailure { reason: String },
}

pub trait CounterexampleGenerator {
    fn generator_id(&self) -> &str;

    fn generate(&self, seed: u64, ordinal: u64) -> Result<Vec<u8>, CandidateProtocolError>;
}

pub trait CounterexampleShrinker {
    fn shrinker_id(&self) -> &str;

    fn candidates(&self, input: &[u8]) -> Result<Vec<Vec<u8>>, CandidateProtocolError>;
}

/// Trusted semantic oracle contract.
///
/// `contract_sha256` must identify the complete verifier/execution contract
/// used by the oracle. A production implementation should derive it from the
/// sealed evaluator/verifier rather than from model-supplied text.
pub trait CounterexampleOracle {
    fn oracle_id(&self) -> &str;
    fn contract_sha256(&self) -> &str;

    fn evaluate(
        &self,
        candidate: &CandidateEnvelope,
        input: &[u8],
    ) -> Result<OracleVerdict, CandidateProtocolError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterexampleConfig {
    pub generation_budget: u64,
    pub shrink_query_budget: u64,
    pub max_case_bytes: usize,
}

impl CounterexampleConfig {
    pub fn new(
        generation_budget: u64,
        shrink_query_budget: u64,
        max_case_bytes: usize,
    ) -> Result<Self, CandidateProtocolError> {
        if generation_budget == 0 {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample.generation_budget",
            ));
        }
        if shrink_query_budget == 0 {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample.shrink_query_budget",
            ));
        }
        if max_case_bytes == 0 {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample.max_case_bytes",
            ));
        }
        Ok(Self {
            generation_budget,
            shrink_query_budget,
            max_case_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterexampleReceipt {
    pub schema_version: u16,
    pub candidate_fingerprint: String,
    pub generator_id: String,
    pub oracle_id: String,
    pub oracle_contract_sha256: String,
    pub shrinker_id: String,
    pub search_seed: u64,
    pub generation_ordinal: u64,
    pub original_input_sha256: String,
    pub original_input_bytes: u64,
    pub minimized_input_sha256: String,
    pub minimized_input_bytes: u64,
    pub failure_kind: String,
    pub generation_oracle_queries: u64,
    pub shrink_oracle_queries: u64,
}

impl CounterexampleReceipt {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = b"memorithm.counterexample-receipt.v1\0".to_vec();
        push_u16(&mut out, self.schema_version);
        push_str(&mut out, &self.candidate_fingerprint);
        push_str(&mut out, &self.generator_id);
        push_str(&mut out, &self.oracle_id);
        push_str(&mut out, &self.oracle_contract_sha256);
        push_str(&mut out, &self.shrinker_id);
        push_u64(&mut out, self.search_seed);
        push_u64(&mut out, self.generation_ordinal);
        push_str(&mut out, &self.original_input_sha256);
        push_u64(&mut out, self.original_input_bytes);
        push_str(&mut out, &self.minimized_input_sha256);
        push_u64(&mut out, self.minimized_input_bytes);
        push_str(&mut out, &self.failure_kind);
        push_u64(&mut out, self.generation_oracle_queries);
        push_u64(&mut out, self.shrink_oracle_queries);
        out
    }

    pub fn fingerprint(&self) -> String {
        digest_hex(&self.canonical_bytes())
    }

    pub fn audit_payload(&self) -> String {
        format!(
            "schema={};candidate={};counterexample={};original={};minimized={};failure={};seed={};ordinal={};gen_queries={};shrink_queries={}",
            self.schema_version,
            self.candidate_fingerprint,
            self.fingerprint(),
            self.original_input_sha256,
            self.minimized_input_sha256,
            self.failure_kind,
            self.search_seed,
            self.generation_ordinal,
            self.generation_oracle_queries,
            self.shrink_oracle_queries
        )
    }
}

pub fn validate_counterexample_receipt(
    candidate: &CandidateEnvelope,
    receipt: &CounterexampleReceipt,
) -> Result<(), CandidateProtocolError> {
    validate_candidate(candidate)?;
    if receipt.schema_version != COUNTEREXAMPLE_PROTOCOL_VERSION {
        return Err(CandidateProtocolError::InvalidField(
            "counterexample.schema_version",
        ));
    }
    if receipt.candidate_fingerprint != candidate.fingerprint() {
        return Err(CandidateProtocolError::PolicyViolation(
            "counterexample receipt is not bound to the supplied candidate envelope".into(),
        ));
    }
    validate_id(&receipt.generator_id, "counterexample.generator_id")?;
    validate_id(&receipt.oracle_id, "counterexample.oracle_id")?;
    validate_id(&receipt.shrinker_id, "counterexample.shrinker_id")?;
    validate_failure_kind(&receipt.failure_kind)?;
    if !is_sha256_hex(&receipt.oracle_contract_sha256) {
        return Err(CandidateProtocolError::InvalidField(
            "counterexample.oracle_contract_sha256",
        ));
    }
    if !is_sha256_hex(&receipt.original_input_sha256)
        || !is_sha256_hex(&receipt.minimized_input_sha256)
    {
        return Err(CandidateProtocolError::InvalidField(
            "counterexample.input_sha256",
        ));
    }
    if receipt.original_input_bytes == 0
        || receipt.minimized_input_bytes == 0
        || receipt.minimized_input_bytes > receipt.original_input_bytes
    {
        return Err(CandidateProtocolError::PolicyViolation(
            "counterexample byte lengths are inconsistent".into(),
        ));
    }
    if receipt.generation_oracle_queries == 0 {
        return Err(CandidateProtocolError::PolicyViolation(
            "counterexample receipt must include at least one generation oracle query".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterexampleWitness {
    pub receipt: CounterexampleReceipt,
    pub original_input: Vec<u8>,
    pub minimized_input: Vec<u8>,
}

impl CounterexampleWitness {
    pub fn validate(&self, candidate: &CandidateEnvelope) -> Result<(), CandidateProtocolError> {
        validate_counterexample_receipt(candidate, &self.receipt)?;
        if self.receipt.original_input_bytes != self.original_input.len() as u64
            || self.receipt.minimized_input_bytes != self.minimized_input.len() as u64
            || self.receipt.original_input_sha256 != digest_hex(&self.original_input)
            || self.receipt.minimized_input_sha256 != digest_hex(&self.minimized_input)
        {
            return Err(CandidateProtocolError::PolicyViolation(
                "counterexample witness bytes do not match the sealed receipt".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CounterexampleSearchResult {
    NoCounterexample {
        generated_cases: u64,
        oracle_queries: u64,
    },
    Found(CounterexampleWitness),
}

pub struct CounterexampleEngine<G, S, O> {
    generator: G,
    shrinker: S,
    oracle: O,
    config: CounterexampleConfig,
}

impl<G, S, O> CounterexampleEngine<G, S, O>
where
    G: CounterexampleGenerator,
    S: CounterexampleShrinker,
    O: CounterexampleOracle,
{
    pub fn new(
        generator: G,
        shrinker: S,
        oracle: O,
        config: CounterexampleConfig,
    ) -> Result<Self, CandidateProtocolError> {
        validate_id(generator.generator_id(), "counterexample.generator_id")?;
        validate_id(shrinker.shrinker_id(), "counterexample.shrinker_id")?;
        validate_id(oracle.oracle_id(), "counterexample.oracle_id")?;
        if !is_sha256_hex(oracle.contract_sha256()) {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample.oracle_contract_sha256",
            ));
        }
        CounterexampleConfig::new(
            config.generation_budget,
            config.shrink_query_budget,
            config.max_case_bytes,
        )?;
        Ok(Self {
            generator,
            shrinker,
            oracle,
            config,
        })
    }

    pub fn search(
        &self,
        candidate: &CandidateEnvelope,
        search_seed: u64,
    ) -> Result<CounterexampleSearchResult, CandidateProtocolError> {
        validate_candidate(candidate)?;
        let mut generated_hashes = BTreeSet::new();
        let mut generation_oracle_queries = 0_u64;

        for ordinal in 0..self.config.generation_budget {
            let input = self.generator.generate(search_seed, ordinal)?;
            self.validate_generated_case(&input)?;
            let input_hash = digest_hex(&input);
            if !generated_hashes.insert(input_hash) {
                continue;
            }

            generation_oracle_queries = generation_oracle_queries.saturating_add(1);
            match self.oracle.evaluate(candidate, &input)? {
                OracleVerdict::Pass => {}
                OracleVerdict::InfrastructureFailure { reason } => {
                    return Err(infrastructure_error(reason));
                }
                OracleVerdict::Counterexample { failure_kind } => {
                    validate_failure_kind(&failure_kind)?;
                    let (minimized_input, shrink_oracle_queries) =
                        self.shrink(candidate, &input, &failure_kind)?;
                    let receipt = CounterexampleReceipt {
                        schema_version: COUNTEREXAMPLE_PROTOCOL_VERSION,
                        candidate_fingerprint: candidate.fingerprint(),
                        generator_id: self.generator.generator_id().to_string(),
                        oracle_id: self.oracle.oracle_id().to_string(),
                        oracle_contract_sha256: self.oracle.contract_sha256().to_string(),
                        shrinker_id: self.shrinker.shrinker_id().to_string(),
                        search_seed,
                        generation_ordinal: ordinal,
                        original_input_sha256: digest_hex(&input),
                        original_input_bytes: input.len() as u64,
                        minimized_input_sha256: digest_hex(&minimized_input),
                        minimized_input_bytes: minimized_input.len() as u64,
                        failure_kind,
                        generation_oracle_queries,
                        shrink_oracle_queries,
                    };
                    let witness = CounterexampleWitness {
                        receipt,
                        original_input: input,
                        minimized_input,
                    };
                    witness.validate(candidate)?;
                    return Ok(CounterexampleSearchResult::Found(witness));
                }
            }
        }

        Ok(CounterexampleSearchResult::NoCounterexample {
            generated_cases: generated_hashes.len() as u64,
            oracle_queries: generation_oracle_queries,
        })
    }

    fn validate_generated_case(&self, input: &[u8]) -> Result<(), CandidateProtocolError> {
        if input.len() > self.config.max_case_bytes {
            return Err(CandidateProtocolError::PolicyViolation(format!(
                "counterexample generator exceeded max_case_bytes: {} > {}",
                input.len(),
                self.config.max_case_bytes
            )));
        }
        Ok(())
    }

    fn shrink(
        &self,
        candidate: &CandidateEnvelope,
        original: &[u8],
        failure_kind: &str,
    ) -> Result<(Vec<u8>, u64), CandidateProtocolError> {
        let mut current = original.to_vec();
        let mut oracle_queries = 0_u64;

        'shrink: loop {
            let candidates = self.shrinker.candidates(&current)?;
            let mut normalized = candidates
                .into_iter()
                .filter(|candidate| {
                    candidate.len() <= self.config.max_case_bytes
                        && case_order(candidate, &current) == Ordering::Less
                })
                .collect::<Vec<_>>();
            normalized.sort_by(|left, right| case_order(left, right));
            normalized.dedup();

            let mut accepted = None;
            for proposed in normalized {
                if oracle_queries >= self.config.shrink_query_budget {
                    break 'shrink;
                }
                oracle_queries = oracle_queries.saturating_add(1);
                match self.oracle.evaluate(candidate, &proposed)? {
                    OracleVerdict::Pass => {}
                    OracleVerdict::InfrastructureFailure { reason } => {
                        return Err(infrastructure_error(reason));
                    }
                    OracleVerdict::Counterexample {
                        failure_kind: proposed_kind,
                    } => {
                        validate_failure_kind(&proposed_kind)?;
                        if proposed_kind == failure_kind {
                            accepted = Some(proposed);
                            break;
                        }
                    }
                }
            }

            match accepted {
                Some(smaller) => current = smaller,
                None => break,
            }
        }

        Ok((current, oracle_queries))
    }
}

fn case_order(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn infrastructure_error(reason: String) -> CandidateProtocolError {
    let reason = if reason.trim().is_empty() {
        "unspecified oracle infrastructure failure".to_string()
    } else {
        reason
    };
    CandidateProtocolError::PolicyViolation(format!(
        "counterexample oracle infrastructure failure: {reason}"
    ))
}

/// Deterministic byte-level shrinker that deletes contiguous chunks.
///
/// Candidate order from this implementation is deliberately not relied upon:
/// [`CounterexampleEngine`] canonicalizes every shrink frontier by `(len, bytes)`
/// before asking the oracle.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChunkDeletionShrinker;

impl CounterexampleShrinker for ChunkDeletionShrinker {
    fn shrinker_id(&self) -> &str {
        "byte-chunk-delete-v1"
    }

    fn candidates(&self, input: &[u8]) -> Result<Vec<Vec<u8>>, CandidateProtocolError> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut chunk = input.len();
        loop {
            for start in 0..=input.len() - chunk {
                let mut candidate = Vec::with_capacity(input.len() - chunk);
                candidate.extend_from_slice(&input[..start]);
                candidate.extend_from_slice(&input[start + chunk..]);
                out.push(candidate);
            }
            if chunk == 1 {
                break;
            }
            chunk = (chunk + 1) / 2;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_protocol::CandidateOrigin;
    use std::cell::Cell;

    fn candidate() -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "counterexample-test",
            b"fn candidate() {}",
            Some("7".into()),
            None,
            None,
            11,
        )
        .unwrap()
    }

    struct SequenceGenerator {
        cases: Vec<Vec<u8>>,
    }

    impl CounterexampleGenerator for SequenceGenerator {
        fn generator_id(&self) -> &str {
            "sequence-v1"
        }

        fn generate(&self, _seed: u64, ordinal: u64) -> Result<Vec<u8>, CandidateProtocolError> {
            Ok(self.cases[ordinal as usize % self.cases.len()].clone())
        }
    }

    struct ForbiddenByteOracle {
        queries: Cell<u64>,
    }

    impl ForbiddenByteOracle {
        fn new() -> Self {
            Self {
                queries: Cell::new(0),
            }
        }
    }

    impl CounterexampleOracle for ForbiddenByteOracle {
        fn oracle_id(&self) -> &str {
            "forbidden-byte-v1"
        }

        fn contract_sha256(&self) -> &str {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }

        fn evaluate(
            &self,
            _candidate: &CandidateEnvelope,
            input: &[u8],
        ) -> Result<OracleVerdict, CandidateProtocolError> {
            self.queries.set(self.queries.get() + 1);
            if input.contains(&42) {
                Ok(OracleVerdict::Counterexample {
                    failure_kind: "contains-42".into(),
                })
            } else {
                Ok(OracleVerdict::Pass)
            }
        }
    }

    fn config(shrink_query_budget: u64) -> CounterexampleConfig {
        CounterexampleConfig::new(4, shrink_query_budget, 64).unwrap()
    }

    #[test]
    fn deterministic_search_shrinks_to_minimal_forbidden_byte() {
        let engine = CounterexampleEngine::new(
            SequenceGenerator {
                cases: vec![vec![1, 42, 2]],
            },
            ChunkDeletionShrinker,
            ForbiddenByteOracle::new(),
            config(64),
        )
        .unwrap();
        let first = engine.search(&candidate(), 123).unwrap();
        let second = engine.search(&candidate(), 123).unwrap();
        assert_eq!(first, second);
        match first {
            CounterexampleSearchResult::Found(witness) => {
                assert_eq!(witness.original_input, vec![1, 42, 2]);
                assert_eq!(witness.minimized_input, vec![42]);
                assert_eq!(witness.receipt.failure_kind, "contains-42");
                witness.validate(&candidate()).unwrap();
            }
            CounterexampleSearchResult::NoCounterexample { .. } => panic!("witness expected"),
        }
    }

    struct InfrastructureOracle;

    impl CounterexampleOracle for InfrastructureOracle {
        fn oracle_id(&self) -> &str {
            "infra-v1"
        }

        fn contract_sha256(&self) -> &str {
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }

        fn evaluate(
            &self,
            _candidate: &CandidateEnvelope,
            _input: &[u8],
        ) -> Result<OracleVerdict, CandidateProtocolError> {
            Ok(OracleVerdict::InfrastructureFailure {
                reason: "runner unavailable".into(),
            })
        }
    }

    #[test]
    fn infrastructure_failure_never_becomes_counterexample() {
        let engine = CounterexampleEngine::new(
            SequenceGenerator {
                cases: vec![vec![42]],
            },
            ChunkDeletionShrinker,
            InfrastructureOracle,
            config(4),
        )
        .unwrap();
        let error = engine.search(&candidate(), 1).unwrap_err();
        assert!(format!("{error}").contains("infrastructure failure"));
    }

    struct FailureKindOracle;

    impl CounterexampleOracle for FailureKindOracle {
        fn oracle_id(&self) -> &str {
            "failure-kind-v1"
        }

        fn contract_sha256(&self) -> &str {
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }

        fn evaluate(
            &self,
            _candidate: &CandidateEnvelope,
            input: &[u8],
        ) -> Result<OracleVerdict, CandidateProtocolError> {
            if input == [1, 42] {
                Ok(OracleVerdict::Counterexample {
                    failure_kind: "original-kind".into(),
                })
            } else if input == [42] {
                Ok(OracleVerdict::Counterexample {
                    failure_kind: "different-kind".into(),
                })
            } else {
                Ok(OracleVerdict::Pass)
            }
        }
    }

    struct OnlySingleByteShrinker;

    impl CounterexampleShrinker for OnlySingleByteShrinker {
        fn shrinker_id(&self) -> &str {
            "single-byte-v1"
        }

        fn candidates(&self, _input: &[u8]) -> Result<Vec<Vec<u8>>, CandidateProtocolError> {
            Ok(vec![vec![42]])
        }
    }

    #[test]
    fn shrinker_must_preserve_the_same_failure_kind() {
        let engine = CounterexampleEngine::new(
            SequenceGenerator {
                cases: vec![vec![1, 42]],
            },
            OnlySingleByteShrinker,
            FailureKindOracle,
            config(8),
        )
        .unwrap();
        match engine.search(&candidate(), 2).unwrap() {
            CounterexampleSearchResult::Found(witness) => {
                assert_eq!(witness.minimized_input, vec![1, 42]);
                assert_eq!(witness.receipt.failure_kind, "original-kind");
            }
            CounterexampleSearchResult::NoCounterexample { .. } => panic!("witness expected"),
        }
    }

    #[test]
    fn oversized_generated_case_fails_closed() {
        let engine = CounterexampleEngine::new(
            SequenceGenerator {
                cases: vec![vec![1; 65]],
            },
            ChunkDeletionShrinker,
            ForbiddenByteOracle::new(),
            config(8),
        )
        .unwrap();
        assert!(engine.search(&candidate(), 3).is_err());
    }

    #[test]
    fn shrink_query_budget_is_hard() {
        let engine = CounterexampleEngine::new(
            SequenceGenerator {
                cases: vec![vec![1, 42, 2]],
            },
            ChunkDeletionShrinker,
            ForbiddenByteOracle::new(),
            config(1),
        )
        .unwrap();
        match engine.search(&candidate(), 4).unwrap() {
            CounterexampleSearchResult::Found(witness) => {
                assert_eq!(witness.receipt.shrink_oracle_queries, 1);
                assert_eq!(witness.minimized_input, vec![1, 42, 2]);
            }
            CounterexampleSearchResult::NoCounterexample { .. } => panic!("witness expected"),
        }
    }

    struct PassOracle {
        queries: Cell<u64>,
    }

    impl CounterexampleOracle for PassOracle {
        fn oracle_id(&self) -> &str {
            "pass-v1"
        }

        fn contract_sha256(&self) -> &str {
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }

        fn evaluate(
            &self,
            _candidate: &CandidateEnvelope,
            _input: &[u8],
        ) -> Result<OracleVerdict, CandidateProtocolError> {
            self.queries.set(self.queries.get() + 1);
            Ok(OracleVerdict::Pass)
        }
    }

    #[test]
    fn duplicate_generated_cases_are_deduplicated_before_oracle() {
        let engine = CounterexampleEngine::new(
            SequenceGenerator {
                cases: vec![vec![7]],
            },
            ChunkDeletionShrinker,
            PassOracle {
                queries: Cell::new(0),
            },
            CounterexampleConfig::new(4, 4, 64).unwrap(),
        )
        .unwrap();
        assert_eq!(
            engine.search(&candidate(), 5).unwrap(),
            CounterexampleSearchResult::NoCounterexample {
                generated_cases: 1,
                oracle_queries: 1,
            }
        );
    }

    struct ReverseShrinker;

    impl CounterexampleShrinker for ReverseShrinker {
        fn shrinker_id(&self) -> &str {
            "reverse-byte-chunk-delete-v1"
        }

        fn candidates(&self, input: &[u8]) -> Result<Vec<Vec<u8>>, CandidateProtocolError> {
            let mut candidates = ChunkDeletionShrinker.candidates(input)?;
            candidates.reverse();
            Ok(candidates)
        }
    }

    #[test]
    fn engine_canonicalizes_shrinker_candidate_order() {
        let direct = CounterexampleEngine::new(
            SequenceGenerator {
                cases: vec![vec![3, 42, 1]],
            },
            ChunkDeletionShrinker,
            ForbiddenByteOracle::new(),
            config(64),
        )
        .unwrap();
        let reversed = CounterexampleEngine::new(
            SequenceGenerator {
                cases: vec![vec![3, 42, 1]],
            },
            ReverseShrinker,
            ForbiddenByteOracle::new(),
            config(64),
        )
        .unwrap();

        let direct = direct.search(&candidate(), 6).unwrap();
        let reversed = reversed.search(&candidate(), 6).unwrap();
        let direct_min = match direct {
            CounterexampleSearchResult::Found(witness) => witness.minimized_input,
            CounterexampleSearchResult::NoCounterexample { .. } => panic!("witness expected"),
        };
        let reversed_min = match reversed {
            CounterexampleSearchResult::Found(witness) => witness.minimized_input,
            CounterexampleSearchResult::NoCounterexample { .. } => panic!("witness expected"),
        };
        assert_eq!(direct_min, reversed_min);
        assert_eq!(direct_min, vec![42]);
    }

    #[test]
    fn witness_byte_tampering_is_rejected() {
        let engine = CounterexampleEngine::new(
            SequenceGenerator {
                cases: vec![vec![1, 42, 2]],
            },
            ChunkDeletionShrinker,
            ForbiddenByteOracle::new(),
            config(64),
        )
        .unwrap();
        let mut witness = match engine.search(&candidate(), 7).unwrap() {
            CounterexampleSearchResult::Found(witness) => witness,
            CounterexampleSearchResult::NoCounterexample { .. } => panic!("witness expected"),
        };
        witness.minimized_input[0] = 41;
        assert!(witness.validate(&candidate()).is_err());
    }
}
