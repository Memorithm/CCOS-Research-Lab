//! CCOS-side audit mirror for the CERVO-derived RSI swarm.
//!
//! `rsi::SwarmAuditLog` provides the deterministic producer-side SHA-256 proof.
//! This module is the complementary CCOS-side adapter: it consumes the same
//! canonical `SwarmEvent` stream and appends it to CCOS's primary hash-chained
//! `EventLog` as `AgentAction/Custom("rsi_swarm", ...)` records.
//!
//! It deliberately lives in the CCOS crate (behind the `rsi` feature) so the
//! circular-dependency inversion remains intact: CCOS depends on RSI; RSI never
//! depends on CCOS.

use crate::event_log::{EventLog, EventPayload, EventType};
use rsi::{canonical_swarm_payload, CervoOrchestrator, SwarmEvent};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CcosSwarmAuditError {
    SequenceGap { expected: u64, got: u64 },
}

/// Incremental mirror of an RSI swarm event stream into the primary CCOS
/// tamper-evident event log.
pub struct CcosSwarmAudit {
    log: EventLog,
    last_seq: u64,
}

impl CcosSwarmAudit {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            log: EventLog::new(session_id.into()),
            last_seq: 0,
        }
    }

    /// Pre-validate the complete unseen suffix, then append it. Sequence gaps or
    /// reordering fail closed before CCOS's log is mutated.
    pub fn ingest(&mut self, events: &[SwarmEvent]) -> Result<usize, CcosSwarmAuditError> {
        let last_seq = self.last_seq;
        let pending: Vec<&SwarmEvent> = events
            .iter()
            .filter(|event| event.seq > last_seq)
            .collect();

        let mut expected = last_seq.saturating_add(1);
        for event in &pending {
            if event.seq != expected {
                return Err(CcosSwarmAuditError::SequenceGap {
                    expected,
                    got: event.seq,
                });
            }
            expected = expected.saturating_add(1);
        }

        for event in &pending {
            self.log.append(
                EventType::AgentAction,
                EventPayload::Custom {
                    key: "rsi_swarm".to_string(),
                    value: canonical_swarm_payload(event),
                },
            );
        }
        if let Some(last) = pending.last() {
            self.last_seq = last.seq;
        }
        Ok(pending.len())
    }

    pub fn sync(
        &mut self,
        orchestrator: &CervoOrchestrator,
    ) -> Result<usize, CcosSwarmAuditError> {
        self.ingest(orchestrator.events())
    }

    pub fn event_log(&self) -> &EventLog {
        &self.log
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    pub fn len(&self) -> usize {
        self.log.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.log.events.is_empty()
    }

    pub fn head(&self) -> String {
        self.log.chain_head()
    }

    pub fn verify(&self) -> bool {
        self.log.verify_integrity().valid
    }
}

impl std::fmt::Debug for CcosSwarmAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CcosSwarmAudit")
            .field("events", &self.log.events.len())
            .field("last_seq", &self.last_seq)
            .field("head", &self.log.chain_head())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsi::{OrchestratorConfig, RSIAgent, SwarmMessage, UnitId};

    fn build() -> CervoOrchestrator {
        let mut orchestrator = CervoOrchestrator::new(OrchestratorConfig {
            adoption_margin: 0.0,
            min_projected_gain: 0.0,
            risk_slack: f64::MAX,
            max_source_rpn: f64::MAX,
        })
        .unwrap();
        orchestrator
            .spawn(UnitId(11), RSIAgent::demo(101))
            .unwrap();
        orchestrator
            .spawn(UnitId(22), RSIAgent::demo(202))
            .unwrap();
        orchestrator
    }

    #[test]
    fn swarm_events_are_mirrored_and_verified() {
        let mut orchestrator = build();
        let mut audit = CcosSwarmAudit::new("cervo-test");

        orchestrator.step_round();
        let added = audit.sync(&orchestrator).unwrap();
        assert!(added > 0);
        assert_eq!(audit.len(), added);
        assert!(audit.verify());
        assert_eq!(audit.last_seq(), orchestrator.events().last().unwrap().seq);

        let first = &audit.event_log().events[0];
        assert_eq!(first.event_type, EventType::AgentAction);
        assert!(matches!(
            &first.payload,
            EventPayload::Custom { key, value }
                if key == "rsi_swarm" && value.starts_with("seq=1;kind=health;")
        ));
    }

    #[test]
    fn duplicate_sync_is_idempotent() {
        let mut orchestrator = build();
        let mut audit = CcosSwarmAudit::new("cervo-idempotent");
        orchestrator.step_round();
        let added = audit.sync(&orchestrator).unwrap();
        assert!(added > 0);
        let head = audit.head();
        assert_eq!(audit.sync(&orchestrator).unwrap(), 0);
        assert_eq!(audit.head(), head);
    }

    #[test]
    fn gap_fails_before_primary_log_mutation() {
        let mut audit = CcosSwarmAudit::new("cervo-gap");
        let events = vec![
            SwarmEvent {
                seq: 1,
                message: SwarmMessage::Shutdown { unit: UnitId(7) },
            },
            SwarmEvent {
                seq: 3,
                message: SwarmMessage::Shutdown { unit: UnitId(8) },
            },
        ];
        assert_eq!(
            audit.ingest(&events),
            Err(CcosSwarmAuditError::SequenceGap {
                expected: 2,
                got: 3,
            })
        );
        assert!(audit.is_empty());
        assert_eq!(audit.last_seq(), 0);
    }

    #[test]
    fn same_swarm_replay_has_same_ccos_chain_head() {
        let run = || {
            let mut orchestrator = build();
            let mut audit = CcosSwarmAudit::new("same-session");
            orchestrator.step_round();
            orchestrator.step_round();
            audit.sync(&orchestrator).unwrap();
            audit.head()
        };
        // EventLog deliberately excludes random event UUIDs and wall-clock
        // timestamps from its link hash, so replay of the same canonical swarm
        // stream commits to the same head.
        assert_eq!(run(), run());
    }
}
