//! Structures de données sérialisables transitant entre le Master et les Workers
//! d'évaluation.
//!
//! Le transport utilise des trames JSON à longueur explicite. Ce framing évite
//! de dépendre d'un EOF pour délimiter une requête, borne les allocations avant
//! désérialisation et retire la dépendance `bincode` du chemin Forge actif.
//!
//! ## Protocole TCP
//! 1. Le Master ouvre une connexion TCP synchrone vers le Worker.
//! 2. Il envoie un préfixe `u32` big-endian suivi du JSON [`EvaluationPayload`].
//! 3. Le Worker renvoie le même framing pour [`EvaluationResult`].

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::candidate::CandidateId;
use crate::error::{ForgeError, Result};

/// Taille maximale d'une trame de protocole Forge.
///
/// La limite est vérifiée avant allocation côté réception et avant émission.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Structures de données du protocole
// ---------------------------------------------------------------------------

/// Paquet envoyé par le Master à un Worker pour demander l'évaluation
/// d'un candidat.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvaluationPayload {
    /// Identifiant unique du candidat (hash FNV-1a).
    pub candidate_id: CandidateId,
    /// Code source Rust du candidat à compiler et exécuter.
    pub source_code: String,
    /// Graine du trial pour reproductibilité.
    pub seed: u64,
    /// Génération courante.
    pub generation: u64,
}

/// Réponse renvoyée par le Worker après évaluation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvaluationResult {
    /// Identifiant du candidat évalué.
    pub candidate_id: CandidateId,
    /// Le candidat a-t-il passé la porte de vérification ?
    pub is_valid: bool,
    /// Objectifs mesurés (vide si invalide).
    pub objectives: Vec<f64>,
    /// Message d'erreur en cas d'échec de compilation ou de crash.
    pub error_message: Option<String>,
}

fn write_json_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: Write,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)
        .map_err(|e| ForgeError::Evaluation(format!("Échec sérialisation JSON: {e}")))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ForgeError::Evaluation(format!(
            "Trame Forge trop grande: {} octets (max {MAX_FRAME_BYTES})",
            payload.len()
        )));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| ForgeError::Evaluation("Longueur de trame Forge hors plage u32".into()))?;
    writer
        .write_all(&len.to_be_bytes())
        .map_err(|e| ForgeError::Evaluation(format!("Échec écriture longueur de trame: {e}")))?;
    writer
        .write_all(&payload)
        .map_err(|e| ForgeError::Evaluation(format!("Échec écriture payload: {e}")))?;
    Ok(())
}

fn read_json_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut len_bytes = [0_u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .map_err(|e| ForgeError::Evaluation(format!("Échec lecture longueur de trame: {e}")))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ForgeError::Evaluation(format!(
            "Trame Forge annoncée trop grande: {len} octets (max {MAX_FRAME_BYTES})"
        )));
    }
    let mut payload = vec![0_u8; len];
    reader
        .read_exact(&mut payload)
        .map_err(|e| ForgeError::Evaluation(format!("Trame Forge tronquée: {e}")))?;
    serde_json::from_slice(&payload)
        .map_err(|e| ForgeError::Evaluation(format!("Payload JSON corrompu: {e}")))
}

// ---------------------------------------------------------------------------
// Fonction de routage maître (dispatch synchrone)
// ---------------------------------------------------------------------------

/// Envoie un [`EvaluationPayload`] à un Worker distant et récupère le
/// [`EvaluationResult`]. Conçu pour être appelé depuis un thread Rayon
/// (dispatch synchrone avec timeout agressif).
///
/// Chaque message est encadré par une longueur `u32` big-endian et la taille
/// annoncée est refusée au-delà de [`MAX_FRAME_BYTES`].
pub fn dispatch_evaluation_to_worker(
    addr: &str,
    payload: &EvaluationPayload,
    timeout: Duration,
) -> Result<EvaluationResult> {
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| ForgeError::Evaluation(format!("Adresse worker invalide '{addr}': {e}")))?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, timeout)
        .map_err(|e| ForgeError::Evaluation(format!("Connexion worker perdue ({addr}): {e}")))?;

    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| ForgeError::Evaluation(format!("Configuration timeout lecture: {e}")))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| ForgeError::Evaluation(format!("Configuration timeout écriture: {e}")))?;

    write_json_frame(&mut stream, payload)?;
    stream
        .flush()
        .map_err(|e| ForgeError::Evaluation(format!("Échec flush socket: {e}")))?;

    read_json_frame(&mut stream)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_payload_json_roundtrip() {
        let payload = EvaluationPayload {
            candidate_id: 0xABCD_1234,
            source_code: "fn main() {}".into(),
            seed: 42,
            generation: 7,
        };

        let bytes = serde_json::to_vec(&payload).expect("sérialisation");
        let recovered: EvaluationPayload = serde_json::from_slice(&bytes).expect("désérialisation");

        assert_eq!(recovered.candidate_id, payload.candidate_id);
        assert_eq!(recovered.source_code, payload.source_code);
        assert_eq!(recovered.seed, payload.seed);
        assert_eq!(recovered.generation, payload.generation);
    }

    #[test]
    fn framed_result_roundtrips() {
        let result = EvaluationResult {
            candidate_id: 12345,
            is_valid: true,
            objectives: vec![1.5, 2.7, 3.9],
            error_message: None,
        };
        let mut frame = Vec::new();
        write_json_frame(&mut frame, &result).expect("frame write");
        let recovered: EvaluationResult =
            read_json_frame(&mut Cursor::new(frame)).expect("frame read");

        assert_eq!(recovered.candidate_id, result.candidate_id);
        assert!(recovered.is_valid);
        assert_eq!(recovered.objectives, result.objectives);
        assert!(recovered.error_message.is_none());
    }

    #[test]
    fn oversized_announced_frame_is_rejected_before_payload_read() {
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes();
        let result = read_json_frame::<_, EvaluationResult>(&mut Cursor::new(oversized));
        assert!(result.is_err());
    }

    #[test]
    fn test_result_with_error_json_roundtrip() {
        let result = EvaluationResult {
            candidate_id: 999,
            is_valid: false,
            objectives: vec![],
            error_message: Some("Compilation échouée: syntax error".into()),
        };

        let bytes = serde_json::to_vec(&result).expect("sérialisation");
        let recovered: EvaluationResult = serde_json::from_slice(&bytes).expect("désérialisation");

        assert!(!recovered.is_valid);
        assert_eq!(
            recovered.error_message.unwrap(),
            "Compilation échouée: syntax error"
        );
    }

    #[test]
    fn test_dispatch_invalid_addr() {
        let payload = EvaluationPayload {
            candidate_id: 1,
            source_code: "fn main() {}".into(),
            seed: 0,
            generation: 0,
        };
        let result =
            dispatch_evaluation_to_worker("invalid-addr", &payload, Duration::from_secs(1));
        assert!(result.is_err());
    }
}
