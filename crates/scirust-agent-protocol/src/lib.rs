#![forbid(unsafe_code)]

mod execution_attestation;

pub use execution_attestation::{
    EXECUTION_PROFILE_SCHEMA_VERSION, ExecutionArchitecture, ExecutionArchitectureFamily,
    ExecutionAttestation, ExecutionAttestationError, ExecutionBackendKind, ExecutionProfile,
    ExecutionReproducibility, Sha256Digest,
};
