use scirust_agent_protocol::{
    EXECUTION_PROFILE_SCHEMA_VERSION, ExecutionArchitecture, ExecutionArchitectureFamily,
    ExecutionAttestation, ExecutionAttestationError, ExecutionBackendKind, ExecutionProfile,
    ExecutionReproducibility, Sha256Digest,
};

fn hash(byte: u8) -> Sha256Digest {
    Sha256Digest::parse(format!("{byte:02x}").repeat(32)).unwrap()
}

fn profile() -> ExecutionProfile {
    ExecutionProfile {
        schema_version: EXECUTION_PROFILE_SCHEMA_VERSION,
        backend: ExecutionBackendKind::Cuda,
        device_ordinal: 0,
        architecture: ExecutionArchitecture {
            family: ExecutionArchitectureFamily::NvidiaGpu,
            name: Some("sm_110".to_string()),
        },
        capability_profile_sha256: hash(0x11),
        topology_profile_sha256: hash(0x22),
        memory_budget_bytes: Some(8 * 1024 * 1024 * 1024),
        numeric_mode: "bf16_tensor_core".to_string(),
        reproducibility: ExecutionReproducibility::Deterministic,
        kernel_semantic_version: "sciagent.decode.v1".to_string(),
        sampler_semantic_version: Some("resident_sampler.v1".to_string()),
        model_sha256: hash(0x33),
        tokenizer_sha256: hash(0x44),
    }
}

#[test]
fn upstream_v1_profile_has_the_same_golden_fingerprint() {
    assert_eq!(
        profile().fingerprint().unwrap().as_str(),
        "f0423da9a3c6c2e43f6e75acd4cd017bd020a0f21d65112a73d1076026c10826"
    );
}

#[test]
fn verified_attestation_rejects_profile_tampering() {
    let attestation = ExecutionAttestation::new(profile()).unwrap();
    assert_eq!(attestation.verify(), Ok(()));

    let mut value = serde_json::to_value(attestation).unwrap();
    value["profile"]["numeric_mode"] = serde_json::json!("f32");
    let tampered: ExecutionAttestation = serde_json::from_value(value).unwrap();
    assert_eq!(
        tampered.verify(),
        Err(ExecutionAttestationError::DigestMismatch)
    );
}
