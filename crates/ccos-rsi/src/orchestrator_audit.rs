//! Hash-chained audit adapter for the CERVO-derived RSI control plane.
//!
//! The orchestrator stays transport-neutral and owns only its deterministic
//! logical event journal.  This adapter consumes that journal incrementally and
//! seals each event into the same std-only SHA-256 chain used by RSI step audit.
//! A CCOS-side bridge can later mirror the canonical payload into the real
//! `EventLog` without adding a `rsi -> ccos` dependency.

use crate::audit::{AuditLog, HashChainLog, TraceEvent};
use crate::orchestrator::{CervoOrchestrator, RejectionReason, SwarmEvent, SwarmMessage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwarmAuditError {
    SequenceGap { expected: u64, got: u64 },
}

pub struct SwarmAuditLog {
    log: HashChainLog,
    last_seq: u64,
}

impl Default for SwarmAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl SwarmAuditLog {
    pub fn new() -> Self {
        Self {
            log: HashChainLog::new(),
            last_seq: 0,
        }
    }

    /// Consume only events not seen before. The complete pending suffix is
    /// sequence-validated before the hash chain is mutated, so a gap/reordering
    /// fails closed without leaving a partially ingested batch.
    pub fn ingest(&mut self, events: &[SwarmEvent]) -> Result<usize, SwarmAuditError> {
        let last_seq = self.last_seq;
        let pending: Vec<&SwarmEvent> = events
            .iter()
            .filter(|event| event.seq > last_seq)
            .collect();

        let mut expected = last_seq.saturating_add(1);
        for event in &pending {
            if event.seq != expected {
                return Err(SwarmAuditError::SequenceGap {
                    expected,
                    got: event.seq,
                });
            }
            expected = expected.saturating_add(1);
        }

        for event in &pending {
            self.log
                .record_custom("rsi_swarm", canonical_swarm_payload(event));
        }
        if let Some(last) = pending.last() {
            self.last_seq = last.seq;
        }
        Ok(pending.len())
    }

    /// Convenience synchronization from a live orchestrator.
    pub fn sync(&mut self, orchestrator: &CervoOrchestrator) -> Result<usize, SwarmAuditError> {
        self.ingest(orchestrator.events())
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    pub fn len(&self) -> usize {
        self.log.len()
    }

    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    pub fn head(&self) -> String {
        self.log.head()
    }

    pub fn verify(&self) -> bool {
        self.log.verify()
    }

    pub fn events(&self) -> &[TraceEvent] {
        self.log.events()
    }

    pub fn to_ccos_json(&self) -> String {
        self.log.to_ccos_json()
    }
}

/// Canonical control-plane payload.  Numeric formatting is fixed so the same
/// logical swarm run produces the same chain head across replay.
pub fn canonical_swarm_payload(event: &SwarmEvent) -> String {
    let body = match &event.message {
        SwarmMessage::Health {
            from,
            t,
            si_global,
            si_safe,
            risk_global,
            max_rpn,
        } => format!(
            "kind=health;from={};t={};si={:.9};safe={:.9};risk={:.9};rpn={:.9}",
            from.0, t, si_global, si_safe, risk_global, max_rpn
        ),
        SwarmMessage::StrategyOffer {
            from,
            strategy_digest,
            si_safe,
        } => format!(
            "kind=offer;from={};strategy={};safe={:.9}",
            from.0, strategy_digest, si_safe
        ),
        SwarmMessage::StrategyAdopted {
            by,
            from,
            strategy_digest,
        } => format!(
            "kind=adopted;by={};from={};strategy={}",
            by.0, from.0, strategy_digest
        ),
        SwarmMessage::StrategyRejected { by, from, reason } => format!(
            "kind=rejected;by={};from={};reason={}",
            by.0,
            from.0,
            rejection_reason_name(*reason)
        ),
        SwarmMessage::Shutdown { unit } => {
            format!("kind=shutdown;unit={}", unit.0)
        }
    };
    format!("seq={};{body}", event.seq)
}

fn rejection_reason_name(reason: RejectionReason) -> &'static str {
    match reason {
        RejectionReason::InsufficientSafeGain => "insufficient_safe_gain",
        RejectionReason::SourceTooRisky => "source_too_risky",
        RejectionReason::IncompatibleStrategy => "incompatible_strategy",
        RejectionReason::NoProjectedGain => "no_projected_gain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::{OrchestratorConfig, UnitId};
    use crate::RSIAgent;

    fn build() -> CervoOrchestrator {
        let mut o = CervoOrchestrator::new(OrchestratorConfig {
            adoption_margin: 0.0,
            min_projected_gain: 0.0,
            risk_slack: f64::MAX,
            max_source_rpn: f64::MAX,
        })
        .unwrap();
        o.spawn(UnitId(1), RSIAgent::demo(101)).unwrap();
        o.spawn(UnitId(2), RSIAgent::demo(202)).unwrap();
        o
    }

    #[test]
    fn sync_is_incremental_and_verifiable() {
        let mut o = build();
        let mut audit = SwarmAuditLog::new();

        o.step_round();
        let first = audit.sync(&o).unwrap();
        assert!(first > 0);
        let len = audit.len();
        assert_eq!(audit.sync(&o).unwrap(), 0);
        assert_eq!(audit.len(), len);
        assert!(audit.verify());

        o.step_round();
        assert!(audit.sync(&o).unwrap() > 0);
        assert!(audit.verify());
        assert_eq!(audit.last_seq(), o.events().last().unwrap().seq);
    }

    #[test]
    fn identical_replay_has_identical_swarm_audit_head() {
        let run = || {
            let mut o = build();
            let mut audit = SwarmAuditLog::new();
            o.step_round();
            o.step_round();
            audit.sync(&o).unwrap();
            audit.head()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn sequence_gap_fails_closed_without_partial_batch() {
        let mut audit = SwarmAuditLog::new();
        let events = vec![
            SwarmEvent {
                seq: 1,
                message: SwarmMessage::Shutdown { unit: UnitId(8) },
            },
            SwarmEvent {
                seq: 3,
                message: SwarmMessage::Shutdown { unit: UnitId(9) },
            },
        ];
        assert_eq!(
            audit.ingest(&events),
            Err(SwarmAuditError::SequenceGap {
                expected: 2,
                got: 3,
            })
        );
        assert!(audit.is_empty());
        assert_eq!(audit.last_seq(), 0);
    }

    #[test]
    fn canonical_payload_is_stable() {
        let event = SwarmEvent {
            seq: 7,
            message: SwarmMessage::StrategyRejected {
                by: UnitId(3),
                from: UnitId(1),
                reason: RejectionReason::SourceTooRisky,
            },
        };
        assert_eq!(
            canonical_swarm_payload(&event),
            "seq=7;kind=rejected;by=3;from=1;reason=source_too_risky"
        );
    }
}
