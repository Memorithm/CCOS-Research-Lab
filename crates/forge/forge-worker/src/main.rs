//! Worker d'évaluation Forge — démon réseau asynchrone Tokio.
//!
//! Le worker reçoit et renvoie des trames JSON à longueur explicite, bornées
//! par `forge_core::protocol::MAX_FRAME_BYTES`. Le framing ne dépend plus d'un
//! EOF pour terminer une requête et reste compatible avec le Master Forge.

use std::net::SocketAddr;
use std::sync::Arc;

use forge_core::domains::low_rank::{TensorCode, TensorTrainDomain};
use forge_core::domains::simd_kernel::{SimdKernelCode, SimdKernelDomain};
use forge_core::protocol::{EvaluationPayload, EvaluationResult, MAX_FRAME_BYTES};
use forge_core::{Domain, Trial};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

enum WorkerDomain {
    LowRank(TensorTrainDomain),
    SimdKernel(SimdKernelDomain),
}

impl WorkerDomain {
    fn evaluate(
        &self,
        source_code: &str,
        candidate_id: u64,
        trial: &Trial,
    ) -> (bool, Vec<f64>, Option<String>) {
        match self {
            WorkerDomain::LowRank(domain) => {
                let candidate = TensorCode {
                    raw_source: source_code.to_string(),
                    id: candidate_id,
                };
                evaluate_candidate(domain, &candidate, trial)
            }
            WorkerDomain::SimdKernel(domain) => {
                let candidate = SimdKernelCode {
                    source: source_code.to_string(),
                    id: candidate_id,
                };
                evaluate_candidate(domain, &candidate, trial)
            }
        }
    }
}

fn evaluate_candidate<D: Domain>(
    domain: &D,
    candidate: &D::Cand,
    trial: &Trial,
) -> (bool, Vec<f64>, Option<String>) {
    match domain.verify(candidate, trial) {
        Ok(true) => match domain.measure(candidate, trial) {
            Ok(objectives) => (true, objectives, None),
            Err(e) => (false, vec![], Some(format!("Échec mesure: {e}"))),
        },
        Ok(false) => (
            false,
            vec![],
            Some("Porte de vérification rejetée — échec compilation ou assertion mathématique".into()),
        ),
        Err(e) => (false, vec![], Some(format!("Erreur critique d'évaluation: {e}"))),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = std::env::var("FORGE_WORKER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9000".to_string())
        .parse()
        .map_err(|e| format!("Adresse worker invalide (FORGE_WORKER_ADDR): {e}"))?;

    let domain_kind =
        std::env::var("FORGE_WORKER_DOMAIN").unwrap_or_else(|_| "low_rank".to_string());
    let domain = init_domain(&domain_kind)
        .map_err(|e| format!("Initialisation domaine '{domain_kind}' échouée: {e}"))?;

    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Impossible de binder sur {addr}: {e}"))?;

    tracing::info!(
        "[WORKER] 🔧 Démon d'évaluation actif sur {} | domaine: {}",
        addr,
        domain_kind
    );
    tracing::info!("[WORKER] 📡 En attente de connexions Master...");

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigint =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("signal SIGINT");
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal SIGTERM");
            tokio::select! {
                _ = sigint.recv() => tracing::info!("[WORKER] ⏹️  Signal SIGINT reçu"),
                _ = sigterm.recv() => tracing::info!("[WORKER] ⏹️  Signal SIGTERM reçu"),
            }
        }

        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("[WORKER] ⏹️  Signal Ctrl+C reçu");
        }

        let _ = shutdown_tx.send(());
    });

    loop {
        tokio::select! {
            conn = listener.accept() => {
                match conn {
                    Ok((mut socket, peer)) => {
                        tracing::debug!("[WORKER] 🔗 Connexion de {peer}");
                        let domain = domain.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(domain, &mut socket).await {
                                tracing::warn!("[WORKER] ❌ Erreur traitement {peer}: {e}");
                            }
                            tracing::debug!("[WORKER] 🔌 Session {peer} terminée");
                        });
                    }
                    Err(e) => tracing::error!("[WORKER] Erreur d'acceptation: {e}"),
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("[WORKER] 🛑 Arrêt du démon demandé — drainage des connexions en cours...");
                break;
            }
        }
    }

    tracing::info!("[WORKER] ✅ Démon arrêté proprement.");
    Ok(())
}

fn init_domain(kind: &str) -> Result<Arc<WorkerDomain>, Box<dyn std::error::Error>> {
    let scratch =
        std::env::var("FORGE_WORKER_SCRATCH").unwrap_or_else(|_| "./worker_scratch".to_string());
    std::fs::create_dir_all(&scratch)
        .map_err(|e| format!("Impossible de créer le répertoire de travail '{scratch}': {e}"))?;

    match kind {
        "low_rank" => {
            let domain = TensorTrainDomain::new(&scratch);
            tracing::info!("[WORKER] Domaine chargé: Tensor Train (low_rank) — scratch: {scratch}");
            Ok(Arc::new(WorkerDomain::LowRank(domain)))
        }
        "simd_kernel" => {
            let domain = SimdKernelDomain::new(&scratch);
            tracing::info!("[WORKER] Domaine chargé: SIMD GEMM kernels — scratch: {scratch}");
            Ok(Arc::new(WorkerDomain::SimdKernel(domain)))
        }
        other => Err(format!(
            "Domaine inconnu: '{other}'. Domaines disponibles: low_rank, simd_kernel"
        )
        .into()),
    }
}

async fn read_frame(socket: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut len_bytes = [0_u8; 4];
    socket
        .read_exact(&mut len_bytes)
        .await
        .map_err(|e| format!("Échec lecture longueur de trame: {e}"))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(format!(
            "Trame Forge annoncée trop grande: {len} octets (max {MAX_FRAME_BYTES})"
        )
        .into());
    }
    let mut payload = vec![0_u8; len];
    socket
        .read_exact(&mut payload)
        .await
        .map_err(|e| format!("Trame Forge tronquée: {e}"))?;
    Ok(payload)
}

async fn write_frame(
    socket: &mut TcpStream,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(format!(
            "Trame Forge trop grande: {} octets (max {MAX_FRAME_BYTES})",
            payload.len()
        )
        .into());
    }
    let len = u32::try_from(payload.len()).map_err(|_| "Longueur de trame hors plage u32")?;
    socket
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("Échec écriture longueur de trame: {e}"))?;
    socket
        .write_all(payload)
        .await
        .map_err(|e| format!("Échec écriture payload: {e}"))?;
    socket
        .flush()
        .await
        .map_err(|e| format!("Échec flush socket: {e}"))?;
    Ok(())
}

async fn handle_connection(
    domain: Arc<WorkerDomain>,
    socket: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_bytes = read_frame(socket).await?;
    let payload: EvaluationPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("Désérialisation JSON échouée (données corrompues?): {e}"))?;

    tracing::info!(
        "[WORKER] 📦 Évaluation candidat {} | génération {}",
        payload.candidate_id,
        payload.generation
    );

    let trial = Trial {
        generation: payload.generation,
        seed: payload.seed,
    };
    let source_code = payload.source_code;
    let candidate_id = payload.candidate_id;

    let result = tokio::task::spawn_blocking(move || {
        let (is_valid, objectives, error_message) =
            domain.evaluate(&source_code, candidate_id, &trial);
        EvaluationResult {
            candidate_id,
            is_valid,
            objectives,
            error_message,
        }
    })
    .await
    .map_err(|e| {
        format!("Panique dans le thread d'évaluation bloquant (candidat {candidate_id}): {e}")
    })?;

    let response_bytes = serde_json::to_vec(&result)
        .map_err(|e| format!("Sérialisation JSON de la réponse échouée: {e}"))?;
    write_frame(socket, &response_bytes).await?;

    tracing::info!(
        "[WORKER] ✅ Candidat {} — valid={} | obj={:?}",
        result.candidate_id,
        result.is_valid,
        result.objectives
    );
    Ok(())
}
