//! Content-addressed regression corpus built from minimized counterexamples.
//!
//! A corpus entry is portable negative evidence. It keeps the minimized witness
//! bytes together with the exact oracle contract and the content-addressed id of
//! the candidate that originally failed. Entries are deterministically ordered
//! and deduplicated by SHA-256. Replaying a corpus against a later candidate is
//! execution-agnostic and goes through the same [`CounterexampleOracle`] trait;
//! production callers therefore inherit the sandbox-only oracle boundary.

use std::collections::BTreeMap;

use crate::candidate_policy::validate_candidate;
use crate::candidate_protocol::{CandidateEnvelope, CandidateProtocolError};
use crate::counterexample::{CounterexampleOracle, CounterexampleWitness, OracleVerdict};
use crate::sha256::sha256;

pub const COUNTEREXAMPLE_CORPUS_SCHEMA_VERSION: u16 = 1;

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

fn valid_semantic_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b';' && byte != b'=')
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
pub struct CounterexampleCorpusEntry {
    pub schema_version: u16,
    pub source_candidate_id: String,
    pub source_counterexample_fingerprint: String,
    pub oracle_id: String,
    pub oracle_contract_sha256: String,
    pub failure_kind: String,
    pub minimized_input_sha256: String,
    pub minimized_input_bytes: u64,
}

impl CounterexampleCorpusEntry {
    fn from_witness(
        source_candidate: &CandidateEnvelope,
        witness: &CounterexampleWitness,
    ) -> Result<Self, CandidateProtocolError> {
        witness.validate(source_candidate)?;
        Ok(Self {
            schema_version: COUNTEREXAMPLE_CORPUS_SCHEMA_VERSION,
            source_candidate_id: source_candidate.candidate_id.clone(),
            source_counterexample_fingerprint: witness.receipt.fingerprint(),
            oracle_id: witness.receipt.oracle_id.clone(),
            oracle_contract_sha256: witness.receipt.oracle_contract_sha256.clone(),
            failure_kind: witness.receipt.failure_kind.clone(),
            minimized_input_sha256: witness.receipt.minimized_input_sha256.clone(),
            minimized_input_bytes: witness.receipt.minimized_input_bytes,
        })
    }

    pub fn validate(&self) -> Result<(), CandidateProtocolError> {
        if self.schema_version != COUNTEREXAMPLE_CORPUS_SCHEMA_VERSION {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample_corpus.schema_version",
            ));
        }
        if !is_sha256_hex(&self.source_candidate_id) {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample_corpus.source_candidate_id",
            ));
        }
        if !is_sha256_hex(&self.source_counterexample_fingerprint) {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample_corpus.source_counterexample_fingerprint",
            ));
        }
        if !valid_semantic_id(&self.oracle_id) {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample_corpus.oracle_id",
            ));
        }
        if !is_sha256_hex(&self.oracle_contract_sha256) {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample_corpus.oracle_contract_sha256",
            ));
        }
        if !valid_semantic_id(&self.failure_kind) {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample_corpus.failure_kind",
            ));
        }
        if !is_sha256_hex(&self.minimized_input_sha256) {
            return Err(CandidateProtocolError::InvalidField(
                "counterexample_corpus.minimized_input_sha256",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CandidateProtocolError> {
        self.validate()?;
        let mut out = b"memorithm.counterexample-corpus-entry.v1\0".to_vec();
        push_u16(&mut out, self.schema_version);
        push_str(&mut out, &self.source_candidate_id);
        push_str(&mut out, &self.source_counterexample_fingerprint);
        push_str(&mut out, &self.oracle_id);
        push_str(&mut out, &self.oracle_contract_sha256);
        push_str(&mut out, &self.failure_kind);
        push_str(&mut out, &self.minimized_input_sha256);
        push_u64(&mut out, self.minimized_input_bytes);
        Ok(out)
    }

    pub fn fingerprint(&self) -> Result<String, CandidateProtocolError> {
        Ok(digest_hex(&self.canonical_bytes()?))
    }

    pub fn audit_payload(&self) -> Result<String, CandidateProtocolError> {
        Ok(format!(
            "schema={};entry={};source_candidate={};counterexample={};input={};failure={};oracle_contract={}",
            self.schema_version,
            self.fingerprint()?,
            self.source_candidate_id,
            self.source_counterexample_fingerprint,
            self.minimized_input_sha256,
            self.failure_kind,
            self.oracle_contract_sha256
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCounterexample {
    entry: CounterexampleCorpusEntry,
    minimized_input: Vec<u8>,
}

impl StoredCounterexample {
    pub fn entry(&self) -> &CounterexampleCorpusEntry {
        &self.entry
    }

    pub fn minimized_input(&self) -> &[u8] {
        &self.minimized_input
    }

    pub fn validate(&self) -> Result<(), CandidateProtocolError> {
        self.entry.validate()?;
        if self.entry.minimized_input_bytes != self.minimized_input.len() as u64
            || self.entry.minimized_input_sha256 != digest_hex(&self.minimized_input)
        {
            return Err(CandidateProtocolError::PolicyViolation(
                "counterexample corpus bytes do not match their content-addressed entry".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegressionOutcome {
    Fixed,
    Reproduced,
    DifferentFailure { observed_failure_kind: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegressionReplay {
    pub entry_fingerprint: String,
    pub outcome: RegressionOutcome,
}

#[derive(Clone, Debug, Default)]
pub struct CounterexampleRegressionCorpus {
    entries: BTreeMap<String, StoredCounterexample>,
}

impl CounterexampleRegressionCorpus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, fingerprint: &str) -> Option<&StoredCounterexample> {
        self.entries.get(fingerprint)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&str, &StoredCounterexample)> {
        self.entries
            .iter()
            .map(|(fingerprint, stored)| (fingerprint.as_str(), stored))
    }

    pub fn insert(
        &mut self,
        source_candidate: &CandidateEnvelope,
        witness: &CounterexampleWitness,
    ) -> Result<String, CandidateProtocolError> {
        validate_candidate(source_candidate)?;
        witness.validate(source_candidate)?;
        let entry = CounterexampleCorpusEntry::from_witness(source_candidate, witness)?;
        let fingerprint = entry.fingerprint()?;
        let stored = StoredCounterexample {
            entry,
            minimized_input: witness.minimized_input.clone(),
        };
        stored.validate()?;
        self.entries.entry(fingerprint.clone()).or_insert(stored);
        Ok(fingerprint)
    }

    pub fn canonical_manifest_bytes(&self) -> Result<Vec<u8>, CandidateProtocolError> {
        let mut out = b"memorithm.counterexample-regression-corpus.v1\0".to_vec();
        push_u16(&mut out, COUNTEREXAMPLE_CORPUS_SCHEMA_VERSION);
        push_u64(&mut out, self.entries.len() as u64);
        for (fingerprint, stored) in &self.entries {
            stored.validate()?;
            if stored.entry.fingerprint()? != *fingerprint {
                return Err(CandidateProtocolError::PolicyViolation(
                    "counterexample corpus map key differs from entry fingerprint".into(),
                ));
            }
            push_str(&mut out, fingerprint);
        }
        Ok(out)
    }

    pub fn fingerprint(&self) -> Result<String, CandidateProtocolError> {
        Ok(digest_hex(&self.canonical_manifest_bytes()?))
    }

    pub fn replay_entry<O: CounterexampleOracle>(
        &self,
        target_candidate: &CandidateEnvelope,
        entry_fingerprint: &str,
        oracle: &O,
    ) -> Result<RegressionOutcome, CandidateProtocolError> {
        validate_candidate(target_candidate)?;
        let stored = self.entries.get(entry_fingerprint).ok_or_else(|| {
            CandidateProtocolError::PolicyViolation(format!(
                "unknown counterexample corpus entry {entry_fingerprint}"
            ))
        })?;
        stored.validate()?;
        if oracle.oracle_id() != stored.entry.oracle_id {
            return Err(CandidateProtocolError::PolicyViolation(
                "counterexample replay oracle id differs from corpus entry".into(),
            ));
        }
        if oracle.contract_sha256() != stored.entry.oracle_contract_sha256 {
            return Err(CandidateProtocolError::PolicyViolation(
                "counterexample replay oracle contract differs from corpus entry".into(),
            ));
        }

        match oracle.evaluate(target_candidate, &stored.minimized_input)? {
            OracleVerdict::Pass => Ok(RegressionOutcome::Fixed),
            OracleVerdict::Counterexample { failure_kind }
                if failure_kind == stored.entry.failure_kind =>
            {
                Ok(RegressionOutcome::Reproduced)
            }
            OracleVerdict::Counterexample { failure_kind } => {
                if !valid_semantic_id(&failure_kind) {
                    return Err(CandidateProtocolError::InvalidField(
                        "counterexample_corpus.observed_failure_kind",
                    ));
                }
                Ok(RegressionOutcome::DifferentFailure {
                    observed_failure_kind: failure_kind,
                })
            }
            OracleVerdict::InfrastructureFailure { reason } => {
                Err(CandidateProtocolError::PolicyViolation(format!(
                    "counterexample regression replay infrastructure failure: {reason}"
                )))
            }
        }
    }

    pub fn replay_all<O: CounterexampleOracle>(
        &self,
        target_candidate: &CandidateEnvelope,
        oracle: &O,
    ) -> Result<Vec<RegressionReplay>, CandidateProtocolError> {
        let mut results = Vec::with_capacity(self.entries.len());
        for fingerprint in self.entries.keys() {
            results.push(RegressionReplay {
                entry_fingerprint: fingerprint.clone(),
                outcome: self.replay_entry(target_candidate, fingerprint, oracle)?,
            });
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_protocol::CandidateOrigin;
    use crate::counterexample::{
        ChunkDeletionShrinker, CounterexampleConfig, CounterexampleEngine, CounterexampleGenerator,
        CounterexampleSearchResult,
    };

    fn candidate(source: &[u8], seed: u64) -> CandidateEnvelope {
        CandidateEnvelope::from_source(
            CandidateOrigin::Forge,
            "corpus-test",
            source,
            None,
            None,
            None,
            seed,
        )
        .unwrap()
    }

    struct Generator;

    impl CounterexampleGenerator for Generator {
        fn generator_id(&self) -> &str {
            "corpus-generator-v1"
        }

        fn generate(
            &self,
            _seed: u64,
            _ordinal: u64,
        ) -> Result<Vec<u8>, CandidateProtocolError> {
            Ok(vec![1, 42, 2])
        }
    }

    #[derive(Clone, Copy)]
    struct Contains42Oracle;

    impl CounterexampleOracle for Contains42Oracle {
        fn oracle_id(&self) -> &str {
            "corpus-oracle-v1"
        }

        fn contract_sha256(&self) -> &str {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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

    fn witness(source_candidate: &CandidateEnvelope) -> CounterexampleWitness {
        let engine = CounterexampleEngine::new(
            Generator,
            ChunkDeletionShrinker,
            Contains42Oracle,
            CounterexampleConfig::new(1, 32, 64).unwrap(),
        )
        .unwrap();
        match engine.search(source_candidate, 99).unwrap() {
            CounterexampleSearchResult::Found(witness) => witness,
            CounterexampleSearchResult::NoCounterexample { .. } => panic!("witness expected"),
        }
    }

    #[test]
    fn counterexample_corpus_insert_is_content_addressed_and_idempotent() {
        let source = candidate(b"broken", 1);
        let witness = witness(&source);
        let mut corpus = CounterexampleRegressionCorpus::new();
        let first = corpus.insert(&source, &witness).unwrap();
        let second = corpus.insert(&source, &witness).unwrap();
        assert_eq!(first, second);
        assert_eq!(corpus.len(), 1);
        let stored = corpus.get(&first).unwrap();
        assert_eq!(stored.minimized_input(), &[42]);
        stored.validate().unwrap();
    }

    #[test]
    fn counterexample_corpus_manifest_is_insertion_order_independent() {
        let a = candidate(b"broken-a", 1);
        let b = candidate(b"broken-b", 2);
        let wa = witness(&a);
        let wb = witness(&b);

        let mut left = CounterexampleRegressionCorpus::new();
        left.insert(&a, &wa).unwrap();
        left.insert(&b, &wb).unwrap();

        let mut right = CounterexampleRegressionCorpus::new();
        right.insert(&b, &wb).unwrap();
        right.insert(&a, &wa).unwrap();

        assert_eq!(left.fingerprint().unwrap(), right.fingerprint().unwrap());
        assert_eq!(left.canonical_manifest_bytes().unwrap(), right.canonical_manifest_bytes().unwrap());
    }

    #[test]
    fn counterexample_corpus_replay_reproduces_same_failure_on_later_candidate() {
        let source = candidate(b"broken", 1);
        let later = candidate(b"still-broken", 200);
        let witness = witness(&source);
        let mut corpus = CounterexampleRegressionCorpus::new();
        let entry = corpus.insert(&source, &witness).unwrap();

        assert_eq!(
            corpus.replay_entry(&later, &entry, &Contains42Oracle).unwrap(),
            RegressionOutcome::Reproduced
        );
    }

    struct FixedOracle;

    impl CounterexampleOracle for FixedOracle {
        fn oracle_id(&self) -> &str {
            "corpus-oracle-v1"
        }

        fn contract_sha256(&self) -> &str {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }

        fn evaluate(
            &self,
            _candidate: &CandidateEnvelope,
            _input: &[u8],
        ) -> Result<OracleVerdict, CandidateProtocolError> {
            Ok(OracleVerdict::Pass)
        }
    }

    #[test]
    fn counterexample_corpus_replay_can_mark_regression_fixed() {
        let source = candidate(b"broken", 1);
        let fixed = candidate(b"fixed", 2);
        let witness = witness(&source);
        let mut corpus = CounterexampleRegressionCorpus::new();
        let entry = corpus.insert(&source, &witness).unwrap();
        assert_eq!(
            corpus.replay_entry(&fixed, &entry, &FixedOracle).unwrap(),
            RegressionOutcome::Fixed
        );
    }

    struct DifferentFailureOracle;

    impl CounterexampleOracle for DifferentFailureOracle {
        fn oracle_id(&self) -> &str {
            "corpus-oracle-v1"
        }

        fn contract_sha256(&self) -> &str {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }

        fn evaluate(
            &self,
            _candidate: &CandidateEnvelope,
            _input: &[u8],
        ) -> Result<OracleVerdict, CandidateProtocolError> {
            Ok(OracleVerdict::Counterexample {
                failure_kind: "different-failure".into(),
            })
        }
    }

    #[test]
    fn counterexample_corpus_replay_reports_changed_failure_class() {
        let source = candidate(b"broken", 1);
        let later = candidate(b"different-bug", 2);
        let witness = witness(&source);
        let mut corpus = CounterexampleRegressionCorpus::new();
        let entry = corpus.insert(&source, &witness).unwrap();
        assert_eq!(
            corpus
                .replay_entry(&later, &entry, &DifferentFailureOracle)
                .unwrap(),
            RegressionOutcome::DifferentFailure {
                observed_failure_kind: "different-failure".into()
            }
        );
    }

    struct WrongContractOracle;

    impl CounterexampleOracle for WrongContractOracle {
        fn oracle_id(&self) -> &str {
            "corpus-oracle-v1"
        }

        fn contract_sha256(&self) -> &str {
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }

        fn evaluate(
            &self,
            _candidate: &CandidateEnvelope,
            _input: &[u8],
        ) -> Result<OracleVerdict, CandidateProtocolError> {
            Ok(OracleVerdict::Pass)
        }
    }

    #[test]
    fn counterexample_corpus_replay_rejects_oracle_contract_drift() {
        let source = candidate(b"broken", 1);
        let witness = witness(&source);
        let mut corpus = CounterexampleRegressionCorpus::new();
        let entry = corpus.insert(&source, &witness).unwrap();
        assert!(corpus
            .replay_entry(&source, &entry, &WrongContractOracle)
            .is_err());
    }

    struct InfraOracle;

    impl CounterexampleOracle for InfraOracle {
        fn oracle_id(&self) -> &str {
            "corpus-oracle-v1"
        }

        fn contract_sha256(&self) -> &str {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
    fn counterexample_corpus_replay_fails_closed_on_infrastructure_error() {
        let source = candidate(b"broken", 1);
        let witness = witness(&source);
        let mut corpus = CounterexampleRegressionCorpus::new();
        let entry = corpus.insert(&source, &witness).unwrap();
        assert!(corpus.replay_entry(&source, &entry, &InfraOracle).is_err());
    }
}
