//! Deterministic CERVO-inspired orchestration for a living RSI swarm.
//!
//! CERVO's useful contribution was not another RSI objective; it was the
//! control-plane idea: long-lived units, health exchange, horizontal transfer
//! and a supervisor.  This module keeps that idea while preserving RSI's
//! stronger invariants:
//!
//! - no implicit RNG or UUID allocation;
//! - deterministic `UnitId` ordering and logical event sequencing;
//! - `SI_safe` is the cross-unit ranking signal;
//! - a peer strategy is transferred only when it is also non-regressing when
//!   projected on the target unit's own state;
//! - no sandbox implementation here: generated-code evaluation remains the
//!   responsibility of the host/`ccos-sandbox` boundary;
//! - counters are owned by the orchestrator, so one physical RSI step is never
//!   multiplied by the number of peers (the accounting bug present in CERVO's
//!   shared evolution tracker cannot occur here).

use std::collections::BTreeMap;

use crate::{MetaStrategy, RSIAgent, StepReport};

/// Stable identity supplied by the caller.  The orchestrator never invents a
/// random identifier, which keeps topology and replay deterministic.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnitId(pub u64);

/// Policy for horizontal strategy transfer.
#[derive(Clone, Copy, Debug)]
pub struct OrchestratorConfig {
    /// The source must beat the target by at least this `SI_safe` margin.
    pub adoption_margin: f64,
    /// The offered strategy must improve the target's projected `SI_global` by
    /// at least this amount before it may replace the target strategy.
    pub min_projected_gain: f64,
    /// A source may be at most this much riskier than the target.
    pub risk_slack: f64,
    /// Absolute source RPN ceiling for horizontal transfer.
    pub max_source_rpn: f64,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            adoption_margin: 0.01,
            min_projected_gain: 0.0,
            risk_slack: 0.0,
            max_source_rpn: f64::MAX,
        }
    }
}

impl OrchestratorConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.adoption_margin.is_finite() || self.adoption_margin < 0.0 {
            return Err("adoption_margin must be finite and >= 0");
        }
        if !self.min_projected_gain.is_finite() || self.min_projected_gain < 0.0 {
            return Err("min_projected_gain must be finite and >= 0");
        }
        if !self.risk_slack.is_finite() || self.risk_slack < 0.0 {
            return Err("risk_slack must be finite and >= 0");
        }
        if self.max_source_rpn.is_nan() || self.max_source_rpn < 0.0 {
            return Err("max_source_rpn must be >= 0");
        }
        Ok(())
    }
}

/// Deterministic, transport-neutral swarm protocol.  The first implementation
/// journals these messages in-process; a future Tokio/process/network transport
/// can carry the same semantic protocol without changing the RSI core.
#[derive(Clone, Debug, PartialEq)]
pub enum SwarmMessage {
    Health {
        from: UnitId,
        t: usize,
        si_global: f64,
        si_safe: f64,
        risk_global: f64,
        max_rpn: f64,
    },
    StrategyOffer {
        from: UnitId,
        strategy_digest: u64,
        si_safe: f64,
    },
    StrategyAdopted {
        by: UnitId,
        from: UnitId,
        strategy_digest: u64,
    },
    StrategyRejected {
        by: UnitId,
        from: UnitId,
        reason: RejectionReason,
    },
    Shutdown {
        unit: UnitId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionReason {
    InsufficientSafeGain,
    SourceTooRisky,
    IncompatibleStrategy,
    NoProjectedGain,
}

/// Logical sequence envelope.  `seq` is the reproducible replacement for
/// wall-clock timestamps in the control plane.
#[derive(Clone, Debug, PartialEq)]
pub struct SwarmEvent {
    pub seq: u64,
    pub message: SwarmMessage,
}

#[derive(Clone, Debug)]
pub struct UnitSummary {
    pub id: UnitId,
    pub t: usize,
    pub si_global: f64,
    pub si_safe: f64,
    pub risk_global: f64,
    pub max_rpn: f64,
    pub adopted: u64,
}

#[derive(Clone, Debug)]
pub struct RoundReport {
    pub round: u64,
    pub units: Vec<UnitSummary>,
    pub best: Option<UnitId>,
    pub adoptions: u64,
    pub total_steps: u64,
}

struct UnitRuntime {
    agent: RSIAgent,
    last: Option<StepReport>,
    adopted: u64,
}

/// Supervisor for a deterministic, living portfolio of RSI agents.
pub struct CervoOrchestrator {
    config: OrchestratorConfig,
    units: BTreeMap<UnitId, UnitRuntime>,
    events: Vec<SwarmEvent>,
    next_seq: u64,
    round: u64,
    total_steps: u64,
    total_adoptions: u64,
}

impl CervoOrchestrator {
    pub fn new(config: OrchestratorConfig) -> Result<Self, &'static str> {
        config.validate()?;
        Ok(Self {
            config,
            units: BTreeMap::new(),
            events: Vec::new(),
            next_seq: 1,
            round: 0,
            total_steps: 0,
            total_adoptions: 0,
        })
    }

    pub fn spawn(&mut self, id: UnitId, agent: RSIAgent) -> Result<(), &'static str> {
        if self.units.contains_key(&id) {
            return Err("duplicate unit id");
        }
        self.units.insert(
            id,
            UnitRuntime {
                agent,
                last: None,
                adopted: 0,
            },
        );
        Ok(())
    }

    pub fn kill(&mut self, id: UnitId) -> bool {
        if self.units.remove(&id).is_some() {
            self.emit(SwarmMessage::Shutdown { unit: id });
            true
        } else {
            false
        }
    }

    pub fn unit_count(&self) -> usize {
        self.units.len()
    }

    pub fn total_steps(&self) -> u64 {
        self.total_steps
    }

    pub fn total_adoptions(&self) -> u64 {
        self.total_adoptions
    }

    pub fn events(&self) -> &[SwarmEvent] {
        &self.events
    }

    pub fn agent(&self, id: UnitId) -> Option<&RSIAgent> {
        self.units.get(&id).map(|u| &u.agent)
    }

    pub fn agent_mut(&mut self, id: UnitId) -> Option<&mut RSIAgent> {
        self.units.get_mut(&id).map(|u| &mut u.agent)
    }

    /// Execute one RSI step on every unit in stable `UnitId` order, publish a
    /// health message for each result, then attempt one horizontal synchronization
    /// pass from the best `SI_safe` unit to the other units.
    pub fn step_round(&mut self) -> RoundReport {
        self.round += 1;

        let ids: Vec<UnitId> = self.units.keys().copied().collect();
        let mut health_messages = Vec::with_capacity(ids.len());
        for id in &ids {
            let unit = self
                .units
                .get_mut(id)
                .expect("id collected from the same BTreeMap");
            let report = unit.agent.step();
            self.total_steps += 1;
            health_messages.push(SwarmMessage::Health {
                from: *id,
                t: report.t,
                si_global: report.si_global,
                si_safe: report.si_safe,
                risk_global: report.risk_global,
                max_rpn: report.max_rpn,
            });
            unit.last = Some(report);
        }
        for message in health_messages {
            self.emit(message);
        }

        let best = self.best_unit();
        if let Some(source) = best {
            self.broadcast_best_strategy(source);
        }

        self.report(best)
    }

    /// Best current unit by `SI_safe`; exact ties are broken by the smallest
    /// stable `UnitId`, making selection independent of hash/random iteration.
    pub fn best_unit(&self) -> Option<UnitId> {
        self.units
            .iter()
            .filter_map(|(id, unit)| unit.last.as_ref().map(|r| (*id, r.si_safe)))
            .max_by(|(ida, a), (idb, b)| match a.total_cmp(b) {
                std::cmp::Ordering::Equal => idb.cmp(ida),
                other => other,
            })
            .map(|(id, _)| id)
    }

    fn broadcast_best_strategy(&mut self, source: UnitId) {
        let (source_strategy, source_report) = {
            let source_unit = match self.units.get(&source) {
                Some(unit) => unit,
                None => return,
            };
            let report = match source_unit.last.as_ref() {
                Some(report) => report.clone(),
                None => return,
            };
            (source_unit.agent.strategy.clone(), report)
        };

        let digest = strategy_digest(&source_strategy);
        self.emit(SwarmMessage::StrategyOffer {
            from: source,
            strategy_digest: digest,
            si_safe: source_report.si_safe,
        });

        let targets: Vec<UnitId> = self
            .units
            .keys()
            .copied()
            .filter(|id| *id != source)
            .collect();

        for target in targets {
            let decision = self.adoption_decision(target, &source_strategy, &source_report);
            match decision {
                Ok(()) => {
                    if let Some(unit) = self.units.get_mut(&target) {
                        unit.agent.strategy = source_strategy.clone();
                        unit.adopted += 1;
                        self.total_adoptions += 1;
                    }
                    self.emit(SwarmMessage::StrategyAdopted {
                        by: target,
                        from: source,
                        strategy_digest: digest,
                    });
                }
                Err(reason) => self.emit(SwarmMessage::StrategyRejected {
                    by: target,
                    from: source,
                    reason,
                }),
            }
        }
    }

    fn adoption_decision(
        &self,
        target: UnitId,
        source_strategy: &MetaStrategy,
        source_report: &StepReport,
    ) -> Result<(), RejectionReason> {
        let target_unit = self
            .units
            .get(&target)
            .ok_or(RejectionReason::IncompatibleStrategy)?;
        let target_report = target_unit
            .last
            .as_ref()
            .ok_or(RejectionReason::InsufficientSafeGain)?;

        if source_report.si_safe
            <= target_report.si_safe + self.config.adoption_margin
        {
            return Err(RejectionReason::InsufficientSafeGain);
        }
        if source_report.risk_global > target_report.risk_global + self.config.risk_slack
            || source_report.max_rpn > self.config.max_source_rpn
        {
            return Err(RejectionReason::SourceTooRisky);
        }
        if source_strategy.software_edit.len() != target_unit.agent.substrate.o.len() {
            return Err(RejectionReason::IncompatibleStrategy);
        }

        let current = target_unit.agent.si_global();
        let projected = source_strategy.projected_si(
            &target_unit.agent.state,
            &target_unit.agent.substrate,
            &target_unit.agent.surface,
        );
        if projected < current + self.config.min_projected_gain {
            return Err(RejectionReason::NoProjectedGain);
        }
        Ok(())
    }

    fn report(&self, best: Option<UnitId>) -> RoundReport {
        let units = self
            .units
            .iter()
            .filter_map(|(id, unit)| {
                unit.last.as_ref().map(|report| UnitSummary {
                    id: *id,
                    t: report.t,
                    si_global: report.si_global,
                    si_safe: report.si_safe,
                    risk_global: report.risk_global,
                    max_rpn: report.max_rpn,
                    adopted: unit.adopted,
                })
            })
            .collect();
        RoundReport {
            round: self.round,
            units,
            best,
            adoptions: self.total_adoptions,
            total_steps: self.total_steps,
        }
    }

    fn emit(&mut self, message: SwarmMessage) {
        let event = SwarmEvent {
            seq: self.next_seq,
            message,
        };
        self.next_seq = self.next_seq.saturating_add(1);
        self.events.push(event);
    }
}

/// Compact deterministic fingerprint for observability/tie-free protocol logs.
/// This is not a cryptographic identity; CCOS will seal transport/audit records
/// with its own hash chain at the integration boundary.
pub fn strategy_digest(strategy: &MetaStrategy) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let mut h = OFFSET;
    let mut feed = |bits: u64| {
        for byte in bits.to_le_bytes() {
            h ^= u64::from(byte);
            h = h.wrapping_mul(PRIME);
        }
    };
    for value in strategy.focus {
        feed(value.to_bits());
    }
    feed(strategy.gain.to_bits());
    feed(strategy.software_edit.len() as u64);
    for value in &strategy.software_edit {
        feed(value.to_bits());
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_agent_swarm() -> CervoOrchestrator {
        let mut orchestrator = CervoOrchestrator::new(OrchestratorConfig {
            adoption_margin: 0.0,
            min_projected_gain: 0.0,
            risk_slack: f64::MAX,
            max_source_rpn: f64::MAX,
        })
        .unwrap();
        orchestrator
            .spawn(UnitId(20), RSIAgent::demo(20))
            .unwrap();
        orchestrator
            .spawn(UnitId(10), RSIAgent::demo(10))
            .unwrap();
        orchestrator
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let mut o = CervoOrchestrator::new(OrchestratorConfig::default()).unwrap();
        o.spawn(UnitId(7), RSIAgent::demo(1)).unwrap();
        assert!(o.spawn(UnitId(7), RSIAgent::demo(2)).is_err());
        assert_eq!(o.unit_count(), 1);
    }

    #[test]
    fn physical_steps_are_counted_once() {
        let mut o = two_agent_swarm();
        o.step_round();
        o.step_round();
        o.step_round();
        assert_eq!(o.total_steps(), 6);
    }

    #[test]
    fn event_sequence_is_monotone_and_gap_free() {
        let mut o = two_agent_swarm();
        o.step_round();
        for (i, event) in o.events().iter().enumerate() {
            assert_eq!(event.seq, i as u64 + 1);
        }
    }

    #[test]
    fn same_seeds_replay_same_control_plane() {
        let mut a = two_agent_swarm();
        let mut b = two_agent_swarm();
        let ra = a.step_round();
        let rb = b.step_round();
        assert_eq!(ra.best, rb.best);
        assert_eq!(ra.total_steps, rb.total_steps);
        assert_eq!(ra.adoptions, rb.adoptions);
        assert_eq!(a.events(), b.events());
    }

    #[test]
    fn stable_id_breaks_exact_safe_score_ties() {
        let mut o = CervoOrchestrator::new(OrchestratorConfig::default()).unwrap();
        let mut a = RSIAgent::demo(42);
        let mut b = RSIAgent::demo(42);
        // Avoid a first-step meta revision so both copies stay exactly aligned.
        a.t = 1;
        b.t = 1;
        a.meta_interval = 1_000;
        b.meta_interval = 1_000;
        o.spawn(UnitId(9), a).unwrap();
        o.spawn(UnitId(3), b).unwrap();
        let report = o.step_round();
        assert_eq!(report.best, Some(UnitId(3)));
    }

    #[test]
    fn killing_a_unit_is_observable() {
        let mut o = two_agent_swarm();
        assert!(o.kill(UnitId(10)));
        assert_eq!(o.unit_count(), 1);
        assert!(matches!(
            o.events().last().map(|e| &e.message),
            Some(SwarmMessage::Shutdown { unit: UnitId(10) })
        ));
    }

    #[test]
    fn digest_is_stable_and_sensitive() {
        let a = MetaStrategy::neutral(4);
        let mut b = a.clone();
        assert_eq!(strategy_digest(&a), strategy_digest(&a));
        b.gain += 0.01;
        assert_ne!(strategy_digest(&a), strategy_digest(&b));
    }
}
