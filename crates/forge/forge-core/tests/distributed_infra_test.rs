//! Stress-test d'intégration distribué pour forge-core.
//!
//! Ce test :
//! 1. Démarre un Worker mock (TCP listener) dans un thread d'arrière-plan
//!    qui évalue les candidats selon leur type (valide / syntax_error / loop).
//! 2. Configure le Master avec `evaluate_parallel_distributed` pointant
//!    vers ce worker local.
//! 3. Envoie une rafale de 50 candidats via Rayon pour saturer la boucle
//!    de connexion.
//! 4. Valide que 100% des réponses sont collectées sans corruption.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use forge_core::evaluate_parallel_distributed;
use forge_core::protocol::{EvaluationPayload, EvaluationResult, MAX_FRAME_BYTES};
use forge_core::{Candidate, CandidateId};
use forge_core::{Individual, Trial};
use serde::de::DeserializeOwned;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Framing identique au protocole Forge de production
// ---------------------------------------------------------------------------

fn read_json_frame<R, T>(reader: &mut R) -> std::io::Result<T>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut len_bytes = [0_u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized Forge frame",
        ));
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn write_json_frame<W, T>(writer: &mut W, value: &T) -> std::io::Result<()>
where
    W: Write,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized Forge frame",
        ));
    }
    let len = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Forge frame too large")
    })?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

// ---------------------------------------------------------------------------
// Candidat de stub pour le test
// ---------------------------------------------------------------------------

/// Candidat minimal implémentant `Candidate` pour les besoins du stress-test.
#[derive(Clone, Debug)]
struct StubCandidate {
    id: u64,
    source: String,
}

impl Candidate for StubCandidate {
    fn id(&self) -> CandidateId {
        self.id
    }
    fn repr(&self) -> String {
        self.source.clone()
    }
}

// ---------------------------------------------------------------------------
// Logique d'évaluation du Worker mock
// ---------------------------------------------------------------------------

/// Évalue un candidat reçu dans le Worker mock.
///
/// - `valid_*` → valide avec objectifs simulés
/// - `syntax_error_*` → invalide (erreur de compilation)
/// - `loop_*` → invalide (timeout / boucle infinie simulée)
fn evaluate_stub(payload: &EvaluationPayload) -> EvaluationResult {
    if payload.source_code.contains("syntax_error") {
        EvaluationResult {
            candidate_id: payload.candidate_id,
            is_valid: false,
            objectives: vec![],
            error_message: Some(format!(
                "Erreur de compilation simulée: unexpected token in '{}'",
                payload.source_code
            )),
        }
    } else if payload.source_code.contains("loop_infinite") {
        EvaluationResult {
            candidate_id: payload.candidate_id,
            is_valid: false,
            objectives: vec![],
            error_message: Some("Timeout dépassé : boucle infinie détectée, processus tué.".into()),
        }
    } else {
        let base_latency = 1000.0 + (payload.candidate_id as f64 % 100.0) * 10.0;
        EvaluationResult {
            candidate_id: payload.candidate_id,
            is_valid: true,
            objectives: vec![0.001, base_latency, 50.0],
            error_message: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Test principal
// ---------------------------------------------------------------------------

#[test]
fn test_distributed_evolution_under_stress() {
    let barrier = Arc::new(Barrier::new(2));
    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_errors = Arc::new(Mutex::new(Vec::<String>::new()));

    let b = barrier.clone();
    let s = shutdown.clone();
    let e = worker_errors.clone();

    let worker_handle = thread::spawn(move || {
        let listener = match TcpListener::bind("127.0.0.1:19999") {
            Ok(l) => l,
            Err(err) => {
                e.lock().unwrap().push(format!("bind: {err}"));
                return;
            }
        };

        listener.set_nonblocking(true).expect("set_nonblocking");
        b.wait();

        loop {
            if s.load(Ordering::Relaxed) {
                break;
            }

            match listener.accept() {
                Ok((mut stream, _peer)) => {
                    thread::spawn(move || {
                        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                        let payload: EvaluationPayload = match read_json_frame(&mut stream) {
                            Ok(payload) => payload,
                            Err(_) => return,
                        };
                        let result = evaluate_stub(&payload);
                        let _ = write_json_frame(&mut stream, &result);
                    });
                }
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => {
                    e.lock().unwrap().push(format!("accept error: {err}"));
                    break;
                }
            }
        }
    });

    barrier.wait();

    let mut population: Vec<StubCandidate> = Vec::with_capacity(50);
    for i in 0..10u64 {
        population.push(StubCandidate {
            id: i,
            source: format!("valid_fn_{i}"),
        });
    }
    for i in 10..30u64 {
        population.push(StubCandidate {
            id: i,
            source: format!("syntax_error_fn_{i}"),
        });
    }
    for i in 30..50u64 {
        population.push(StubCandidate {
            id: i,
            source: format!("loop_infinite_fn_{i}"),
        });
    }

    let workers = vec!["127.0.0.1:19999".to_string()];
    let trial = Trial {
        generation: 0,
        seed: 42,
    };
    let failure_sink = Mutex::new(Vec::new());

    let individuals: Vec<Individual<StubCandidate>> = evaluate_parallel_distributed(
        &population,
        &workers,
        &trial,
        None,
        None,
        0,
        &failure_sink,
    );

    assert_eq!(
        individuals.len(),
        50,
        "Tous les candidats doivent avoir une réponse (50 attendus)"
    );

    let valid_count = individuals.iter().filter(|i| i.score.valid).count();
    assert_eq!(
        valid_count, 10,
        "10 candidats valides attendus, trouvé {valid_count}"
    );

    let invalid_count = individuals.iter().filter(|i| !i.score.valid).count();
    assert_eq!(
        invalid_count, 40,
        "40 candidats invalides attendus, trouvé {invalid_count}"
    );

    for ind in &individuals {
        if ind.score.valid {
            assert!(
                !ind.score.objectives.is_empty(),
                "Les candidats valides doivent avoir des objectifs"
            );
            assert!(
                ind.score.objectives.iter().all(|x| x.is_finite()),
                "Les objectifs doivent être finis"
            );
            assert!(
                ind.cand.id < 10,
                "Seuls les 10 premiers candidats doivent être valides"
            );
        }
    }

    for (idx, ind) in individuals.iter().enumerate() {
        assert_eq!(
            ind.cand.id, idx as u64,
            "L'ordre des candidats doit être préservé (candidat {idx})"
        );
    }

    let failures = failure_sink.into_inner().unwrap();
    assert!(
        failures.is_empty(),
        "Aucun diagnostic d'échec réseau attendu (toutes les connexions réussissent). \
         Reçu {} échecs: {:?}",
        failures.len(),
        failures
    );

    let worker_errs = worker_errors.lock().unwrap();
    assert!(
        worker_errs.is_empty(),
        "Le Worker mock ne doit signaler aucune erreur. Reçu: {:?}",
        *worker_errs
    );

    shutdown.store(true, Ordering::Relaxed);
    let _ = worker_handle.join();
}

// ---------------------------------------------------------------------------
// Test de robustesse réseau : worker injoignable
// ---------------------------------------------------------------------------

#[test]
fn test_distributed_worker_unreachable_is_resilient() {
    let population: Vec<StubCandidate> = (0..5u64)
        .map(|i| StubCandidate {
            id: i,
            source: format!("valid_fn_{i}"),
        })
        .collect();

    let workers = vec!["127.0.0.1:19998".to_string()];
    let trial = Trial {
        generation: 0,
        seed: 42,
    };
    let failure_sink = Mutex::new(Vec::new());

    let individuals: Vec<Individual<StubCandidate>> =
        evaluate_parallel_distributed(&population, &workers, &trial, None, None, 0, &failure_sink);

    assert_eq!(individuals.len(), 5);
    for ind in &individuals {
        assert!(!ind.score.valid, "Worker injoignable → tous invalides");
    }

    let failures = failure_sink.into_inner().unwrap();
    assert!(
        !failures.is_empty(),
        "Des diagnostics d'échec réseau doivent être produits"
    );

    for diag in &failures {
        assert!(
            diag.stderr.contains("127.0.0.1:19998")
                || diag.stderr.contains("Connexion")
                || diag.stderr.contains("connection"),
            "Le diagnostic doit référencer l'adresse du worker: {}",
            diag.stderr
        );
    }
}

// ---------------------------------------------------------------------------
// Test Round-Robin sur plusieurs workers (même worker simulé)
// ---------------------------------------------------------------------------

#[test]
fn test_round_robin_distribution() {
    let barrier = Arc::new(Barrier::new(2));
    let shutdown = Arc::new(AtomicBool::new(false));

    let b = barrier.clone();
    let s = shutdown.clone();

    let _handle = thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:19997").unwrap();
        listener.set_nonblocking(true).unwrap();
        b.wait();

        loop {
            if s.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    thread::spawn(move || {
                        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                        let payload: EvaluationPayload = read_json_frame(&mut stream).unwrap();
                        let result = evaluate_stub(&payload);
                        write_json_frame(&mut stream, &result).unwrap();
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    barrier.wait();

    let population: Vec<StubCandidate> = (0..10u64)
        .map(|i| StubCandidate {
            id: i,
            source: format!("valid_fn_{i}"),
        })
        .collect();

    let workers = vec!["127.0.0.1:19997".to_string(), "127.0.0.1:19997".to_string()];
    let trial = Trial {
        generation: 0,
        seed: 42,
    };
    let failure_sink = Mutex::new(Vec::new());

    let individuals: Vec<Individual<StubCandidate>> =
        evaluate_parallel_distributed(&population, &workers, &trial, None, None, 0, &failure_sink);

    assert_eq!(individuals.len(), 10);
    assert!(individuals.iter().all(|i| i.score.valid));

    shutdown.store(true, Ordering::Relaxed);
}
