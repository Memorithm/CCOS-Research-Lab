use rsi::{encode_candidate, CandidateEnvelope, CandidateOrigin};

const SOURCE: &[u8] = b"pub fn kernel() {}";
const SOURCE_SHA256: &str = "3b6e6e212c45273719067e12eac78aceaf44fbb2ffcafef4ab4519a64c5083e1";
const CANDIDATE_ID: &str = "4457784cc3119a48ab2f90fbac86d5e5c1ab0c99b46b567edd8dbd1bb3a3446f";
const ENVELOPE_SHA256: &str = "9a531d78fbf991077c087bdac953db53b1ede544349a71c5e6bdbe25f00e8693";
const PROPOSAL_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";

const GOLDEN_WIRE: &str = concat!(
    "{\"candidate_id\":\"4457784cc3119a48ab2f90fbac86d5e5c1ab0c99b46b567edd8dbd1bb3a3446f\",",
    "\"domain\":\"simd_gemm\",",
    "\"fingerprint\":\"9a531d78fbf991077c087bdac953db53b1ede544349a71c5e6bdbe25f00e8693\",",
    "\"origin\":\"forge\",",
    "\"parent_candidate_id\":null,",
    "\"producer_candidate_id\":\"42\",",
    "\"proposal_sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",",
    "\"schema_version\":1,",
    "\"source_sha256\":\"3b6e6e212c45273719067e12eac78aceaf44fbb2ffcafef4ab4519a64c5083e1\",",
    "\"trial_seed\":\"18446744073709551615\"}"
);

#[test]
fn forge_candidate_envelope_v1_is_pinned_cross_repo() {
    let envelope = CandidateEnvelope::from_source(
        CandidateOrigin::Forge,
        "simd_gemm",
        SOURCE,
        Some("42".to_string()),
        None,
        Some(PROPOSAL_SHA256.to_string()),
        u64::MAX,
    )
    .unwrap();

    assert_eq!(envelope.source_sha256, SOURCE_SHA256);
    assert_eq!(envelope.candidate_id, CANDIDATE_ID);
    assert_eq!(envelope.fingerprint(), ENVELOPE_SHA256);
    assert_eq!(encode_candidate(&envelope).unwrap(), GOLDEN_WIRE);
}
