//! ⚙️ Loop Engineering — **L8 : parallélisme & portefeuille de boucles**.
//!
//! Exécute un **essaim** d'agents indépendants (graines distinctes) en
//! **parallèle** (threads `std`, sans dépendance) et sélectionne le meilleur du
//! portefeuille (par `SI_safe`). Chaque agent est construit *dans* son thread
//! par une closure `build(seed)`, donc l'agent ne traverse jamais les threads —
//! seuls les résultats scalaires reviennent. Déterministe par graine.

use crate::agent::RSIAgent;

/// Résultat d'un membre de l'essaim.
#[derive(Clone, Copy, Debug)]
pub struct SwarmMember {
    pub seed: u64,
    pub si_global: f64,
    pub si_safe: f64,
}

/// Résultat agrégé d'un essaim.
#[derive(Clone, Debug)]
pub struct SwarmResult {
    pub members: Vec<SwarmMember>,
    pub best_index: usize,
}

impl SwarmResult {
    pub fn best(&self) -> SwarmMember {
        self.members[self.best_index]
    }
}

/// Exécute `size` boucles en parallèle ; `build(seed)` construit chaque agent
/// (graines `base_seed..base_seed+size`), chacune avancée de `steps` pas. Le
/// meilleur membre est sélectionné par `SI_safe`.
pub fn run_swarm<F>(size: usize, base_seed: u64, steps: usize, build: F) -> SwarmResult
where
    F: Fn(u64) -> RSIAgent + Sync,
{
    let size = size.max(1);
    // Membre marqué invalide (jamais sélectionné, `SI_safe = -∞`) : sert de
    // repli quand un membre panique ou ne produit aucun rapport.
    let invalid = |seed: u64| SwarmMember { seed, si_global: 0.0, si_safe: f64::NEG_INFINITY };
    let members: Vec<SwarmMember> = std::thread::scope(|scope| {
        let handles: Vec<(u64, _)> = (0..size)
            .map(|i| {
                let seed = base_seed + i as u64;
                let build = &build;
                let handle = scope.spawn(move || {
                    let mut agent = build(seed);
                    let reports = agent.run(steps);
                    match reports.last() {
                        Some(last) => {
                            SwarmMember { seed, si_global: last.si_global, si_safe: last.si_safe }
                        }
                        // run(0) ⇒ aucun rapport : membre invalide plutôt que panic.
                        None => invalid(seed),
                    }
                });
                (seed, handle)
            })
            .collect();
        // Un membre qui panique est *isolé* (marqué invalide) au lieu de faire
        // s'effondrer tout l'essaim via `join().unwrap()`.
        handles
            .into_iter()
            .map(|(seed, h)| h.join().unwrap_or_else(|_| invalid(seed)))
            .collect()
    });

    let best_index = members
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.si_safe.partial_cmp(&b.si_safe).unwrap())
        .map(|(i, _)| i)
        .unwrap_or(0);

    SwarmResult { members, best_index }
}

/// Essaim de démonstration (agents `RSIAgent::demo`) — pratique pour benchmark.
pub fn run_swarm_demo(size: usize, base_seed: u64, steps: usize) -> SwarmResult {
    run_swarm(size, base_seed, steps, RSIAgent::demo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swarm_runs_and_selects_best() {
        let res = run_swarm_demo(6, 100, 30);
        assert_eq!(res.members.len(), 6);
        let best = res.best();
        // le meilleur a bien le SI_safe maximal
        assert!(res.members.iter().all(|m| m.si_safe <= best.si_safe + 1e-12));
        assert!(best.si_global > 0.0);
    }

    #[test]
    fn swarm_is_deterministic() {
        let a = run_swarm_demo(4, 42, 20);
        let b = run_swarm_demo(4, 42, 20);
        assert_eq!(a.best_index, b.best_index);
        for (x, y) in a.members.iter().zip(&b.members) {
            assert_eq!(x.seed, y.seed);
            assert!((x.si_global - y.si_global).abs() < 1e-12);
        }
    }

    #[test]
    fn swarm_with_zero_steps_does_not_panic() {
        // run(0) ⇒ aucun rapport : les membres sont marqués invalides
        // (SI_safe = -∞) au lieu de faire paniquer l'essaim via `unwrap()`.
        let res = run_swarm_demo(3, 7, 0);
        assert_eq!(res.members.len(), 3);
        assert!(res.members.iter().all(|m| m.si_safe == f64::NEG_INFINITY));
    }
}
