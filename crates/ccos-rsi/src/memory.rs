//! Mémoire contextuelle réelle pour la composante `C` (Phase 3).
//!
//! Le trait [`ContextMemory`] abstrait un magasin épisodique : l'agent y écrit
//! un *embedding* de son état à chaque pas et peut **rappeler** les contextes
//! passés les plus proches. Le cœur fournit une implémentation `std`-only
//! ([`LinearContextMemory`], k-NN exact par balayage) ; la feature `octasoma`
//! fournit un backend fractal indexé (cf. `octasoma_memory`).
//!
//! La mémoire est *attachée* à l'agent sans entrer dans la dynamique de
//! `SI_global` : elle enrichit `C` (épisodique, interrogeable) sans toucher aux
//! garde-fous de stabilité (§4).

/// Magasin de mémoire contextuelle : écriture d'embeddings + rappel k-NN.
pub trait ContextMemory {
    /// Mémorise un embedding et sa charge utile (payload sérialisé).
    fn remember(&mut self, embedding: &[f32], payload: &[u8]);
    /// Rappelle les `k` payloads dont l'embedding est le plus proche de `query`.
    fn recall(&self, query: &[f32], k: usize) -> Vec<Vec<u8>>;
    /// Nombre d'éléments mémorisés.
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Mémoire contextuelle `std`-only : k-NN exact par balayage linéaire
/// (distance euclidienne). Simple, sans dépendance ; convient comme défaut et
/// comme référence face au backend OctaSoma.
#[derive(Default)]
pub struct LinearContextMemory {
    items: Vec<(Vec<f32>, Vec<u8>)>,
}

impl LinearContextMemory {
    pub fn new() -> Self {
        LinearContextMemory { items: Vec::new() }
    }
}

impl ContextMemory for LinearContextMemory {
    fn remember(&mut self, embedding: &[f32], payload: &[u8]) {
        self.items.push((embedding.to_vec(), payload.to_vec()));
    }

    fn recall(&self, query: &[f32], k: usize) -> Vec<Vec<u8>> {
        let dist2 = |v: &[f32]| -> f32 {
            v.iter()
                .zip(query)
                .map(|(a, b)| (a - b) * (a - b))
                .sum::<f32>()
        };
        let mut scored: Vec<(f32, &Vec<u8>)> =
            self.items.iter().map(|(e, p)| (dist2(e), p)).collect();
        scored.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().take(k).map(|(_, p)| p.clone()).collect()
    }

    fn len(&self) -> usize {
        self.items.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recall_returns_nearest() {
        let mut m = LinearContextMemory::new();
        m.remember(&[0.0, 0.0], b"origin");
        m.remember(&[10.0, 10.0], b"far");
        m.remember(&[1.0, 1.0], b"near");
        assert_eq!(m.len(), 3);
        let r = m.recall(&[0.9, 0.9], 1);
        assert_eq!(r[0], b"near");
        let r2 = m.recall(&[0.0, 0.0], 2);
        assert_eq!(r2[0], b"origin");
    }
}
