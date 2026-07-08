//! §7bis — PORT D'AUDIT & DÉTERMINISME (journal hash-chaîné)
//!
//! Chaque pas d'auto-modification `ℳ` est enregistré dans un **journal
//! hash-chaîné** (mêmes principes que l'`EventLog` de CCOS : liens SHA-256,
//! vérification d'intégrité, *replay*). Cela rend la récursion **traçable,
//! reproductible et auditable** — propriété essentielle de sûreté d'un RSI.
//!
//! Le port [`AuditLog`] est abstrait ; le cœur fournit [`HashChainLog`]
//! (std-only, SHA-256 maison). Le journal s'exporte en JSON **ingestable par
//! CCOS** (`ExternalMemory::ingest_source`) pour la forensique/replay avancée,
//! sans imposer de dépendance.

use crate::json::Json;
use crate::sha256::sha256_hex;

/// Événement audité : un pas de la boucle RSI.
#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub t: usize,
    pub si_global: f64,
    pub si_safe: f64,
    pub risk_global: f64,
    pub max_rpn: f64,
    pub most_critical: &'static str,
    /// hash stable de la stratégie ℳ appliquée.
    pub strategy_id: u64,
    pub p_eff: f64,
}

impl AuditEvent {
    /// Charge utile canonique (déterministe) servant au calcul du hash de lien.
    // CCOS_EXTENDED (plan P3): promoted from `pub(crate)` to `pub` so the
    // CCOS-side `CcosAudit` adapter (`src/rsi_bridge.rs`, outside this crate) can
    // build the same canonical payload string when forwarding RSI steps into
    // CCOS's hash-chained `EventLog`. The string format is unchanged.
    pub fn payload(&self) -> String {
        format!(
            "t={};si={:.9};safe={:.9};risk={:.9};rpn={:.9};crit={};strat={};peff={:.9}",
            self.t,
            self.si_global,
            self.si_safe,
            self.risk_global,
            self.max_rpn,
            self.most_critical,
            self.strategy_id,
            self.p_eff,
        )
    }
}

/// Entrée chaînée du journal (schéma aligné sur CCOS `TraceEvent`).
#[derive(Clone, Debug)]
pub struct TraceEvent {
    pub sequence_number: u64,
    pub prev_hash: String,
    /// SHA-256 de `(prev_hash | seq | event_type | payload)`.
    pub hash: String,
    pub event_type: String,
    pub payload: String,
}

/// Hash de lien : `sha256( prev_hash | seq | event_type | payload )`.
fn link_hash(prev_hash: &str, seq: u64, event_type: &str, payload: &str) -> String {
    sha256_hex(&format!("{prev_hash}|{seq}|{event_type}|{payload}"))
}

/// Racine de la chaîne (hash de tête initial).
pub const GENESIS: &str = "GENESIS";

/// Journal d'audit hash-chaîné, vérifiable et rejouable.
pub trait AuditLog {
    /// Enregistre un événement et renvoie le nouveau hash de tête.
    fn record(&mut self, event: &AuditEvent) -> String;
    /// Nombre d'événements.
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Hash de tête (résumé reproductible de toute la trajectoire).
    fn head(&self) -> String;
    /// Vérifie l'intégrité de toute la chaîne (liens + non-altération).
    fn verify(&self) -> bool;
}

/// Implémentation cœur std-only : journal hash-chaîné SHA-256.
#[derive(Default)]
pub struct HashChainLog {
    events: Vec<TraceEvent>,
}

impl HashChainLog {
    pub fn new() -> Self {
        HashChainLog { events: Vec::new() }
    }

    /// Hash de tête courant (GENESIS si vide).
    fn chain_head(&self) -> String {
        self.events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string())
    }

    /// Accès aux événements (pour inspection / replay).
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Rejoue les événements de `from` (inclus) à `to` (exclu, None = fin).
    pub fn replay(&self, from: u64, to: Option<u64>) -> Vec<&TraceEvent> {
        let end = to.unwrap_or(self.events.len() as u64);
        self.events
            .iter()
            .filter(|e| e.sequence_number >= from && e.sequence_number < end)
            .collect()
    }

    /// Exporte le journal en JSON **ingestable par CCOS** (`ingest_source`).
    pub fn to_ccos_json(&self) -> String {
        let arr: Vec<Json> = self
            .events
            .iter()
            .map(|e| {
                let mut o = Json::obj();
                o.set("sequence_number", Json::Num(e.sequence_number as f64))
                    .set("prev_hash", Json::Str(e.prev_hash.clone()))
                    .set("hash", Json::Str(e.hash.clone()))
                    .set("event_type", Json::Str(e.event_type.clone()))
                    .set("payload", Json::Str(e.payload.clone()));
                o
            })
            .collect();
        let mut root = Json::obj();
        root.set("source", Json::Str("rsi://audit".into()))
            .set("events", Json::Arr(arr));
        root.to_string()
    }
}

impl AuditLog for HashChainLog {
    fn record(&mut self, event: &AuditEvent) -> String {
        let seq = self.events.len() as u64;
        let prev_hash = self.chain_head();
        let event_type = "rsi_step".to_string();
        let payload = event.payload();
        let hash = link_hash(&prev_hash, seq, &event_type, &payload);
        self.events.push(TraceEvent {
            sequence_number: seq,
            prev_hash,
            hash: hash.clone(),
            event_type,
            payload,
        });
        hash
    }

    fn len(&self) -> usize {
        self.events.len()
    }

    fn head(&self) -> String {
        self.chain_head()
    }

    fn verify(&self) -> bool {
        let mut prev = GENESIS.to_string();
        for e in &self.events {
            if e.prev_hash != prev {
                return false; // lien rompu
            }
            let recomputed = link_hash(&e.prev_hash, e.sequence_number, &e.event_type, &e.payload);
            if recomputed != e.hash {
                return false; // contenu altéré
            }
            prev = e.hash.clone();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(t: usize, si: f64) -> AuditEvent {
        AuditEvent {
            t,
            si_global: si,
            si_safe: si - 0.01,
            risk_global: 0.02,
            max_rpn: 0.1,
            most_critical: "regression_competence",
            strategy_id: 12345 + t as u64,
            p_eff: 0.5,
        }
    }

    #[test]
    fn chain_verifies() {
        let mut log = HashChainLog::new();
        for i in 0..10 {
            log.record(&ev(i, 0.1 * i as f64));
        }
        assert_eq!(log.len(), 10);
        assert!(log.verify());
        assert_eq!(log.events()[0].prev_hash, GENESIS);
        // chaînage : prev_hash[i] == hash[i-1]
        for i in 1..10 {
            assert_eq!(log.events()[i].prev_hash, log.events()[i - 1].hash);
        }
    }

    #[test]
    fn tampering_is_detected() {
        let mut log = HashChainLog::new();
        for i in 0..5 {
            log.record(&ev(i, 0.1 * i as f64));
        }
        assert!(log.verify());
        // falsification du contenu d'un événement
        log.events[2].payload.push_str("FALSIFIE");
        assert!(!log.verify());
    }

    #[test]
    fn deterministic_head_across_runs() {
        let build = || {
            let mut log = HashChainLog::new();
            for i in 0..8 {
                log.record(&ev(i, 0.1 * i as f64));
            }
            log.head()
        };
        assert_eq!(build(), build()); // même trajectoire ⇒ même hash de tête
    }

    #[test]
    fn ccos_export_parses() {
        let mut log = HashChainLog::new();
        log.record(&ev(0, 0.1));
        let json = log.to_ccos_json();
        let parsed = Json::parse(&json).unwrap();
        assert_eq!(parsed.get("events").unwrap().as_array().unwrap().len(), 1);
    }
}
