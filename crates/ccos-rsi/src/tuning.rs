//! Domaine **configuration** : optimiser des hyperparamètres (JSON) contre un
//! objectif déterministe. C'est le 2ᵉ point du spectre texte → **config** → code
//! du design spike (P1.3), et il démontre la **généralité** de
//! [`crate::llm::LlmRefineTask`] : ici le candidat `Cand` est un objet JSON
//! validé par schéma, pas une expression.
//!
//! ## Sandbox / sûreté
//! Aucune exécution : un candidat est une configuration (nombres) **validée par
//! bornes** (`safety_check`). L'objectif (`score`) est un stand-in *synthétique*
//! déterministe d'une métrique de qualité (p. ex. précision d'un retriever),
//! avec un optimum caché — il modélise « la qualité mesurée sur un benchmark »
//! sans dépendre d'un vrai LLM/jeu de données. Un jeu **held-out** (optimum
//! légèrement décalé) mesure la généralisation (anti-Goodhart, §3 du spike).

use crate::ascent::RefineTask;
use crate::json::Json;
use crate::llm::{LlmRefineTask, SafetyViolation};

// Bornes de validité (schéma) des hyperparamètres.
const TOP_K_LO: f64 = 1.0;
const TOP_K_HI: f64 = 100.0;
const CHUNK_LO: f64 = 16.0;
const CHUNK_HI: f64 = 4096.0;
const THRESH_LO: f64 = 0.0;
const THRESH_HI: f64 = 1.0;

/// Configuration candidate (hyperparamètres d'un retriever, à titre d'exemple).
#[derive(Clone, Debug, PartialEq)]
pub struct TuneConfig {
    pub top_k: f64,
    pub chunk: f64,
    pub threshold: f64,
}

impl TuneConfig {
    /// Coordonnées normalisées dans [0,1]³ (pour l'objectif lisse).
    fn normalized(&self) -> [f64; 3] {
        [
            (self.top_k - TOP_K_LO) / (TOP_K_HI - TOP_K_LO),
            (self.chunk - CHUNK_LO) / (CHUNK_HI - CHUNK_LO),
            (self.threshold - THRESH_LO) / (THRESH_HI - THRESH_LO),
        ]
    }

    /// Représentation JSON compacte (pour le prompt / le log).
    pub fn to_json_string(&self) -> String {
        let mut o = Json::obj();
        o.set("top_k", Json::Num(self.top_k))
            .set("chunk", Json::Num(self.chunk))
            .set("threshold", Json::Num(self.threshold));
        o.to_string()
    }

    /// Parse une configuration JSON (clés `top_k`, `chunk`, `threshold` requises),
    /// avec message d'erreur — pour le rapport par-proposition côté MCP.
    pub fn parse(s: &str) -> Result<TuneConfig, String> {
        let j = Json::parse(s).map_err(|e| format!("JSON invalide: {e}"))?;
        TuneConfig::from_json(&j)
            .ok_or_else(|| "clés requises: top_k, chunk, threshold (nombres)".to_string())
    }

    /// Parse une configuration depuis une valeur JSON (clés requises).
    fn from_json(j: &Json) -> Option<TuneConfig> {
        Some(TuneConfig {
            top_k: j.get("top_k")?.as_f64()?,
            chunk: j.get("chunk")?.as_f64()?,
            threshold: j.get("threshold")?.as_f64()?,
        })
    }
}

/// Tâche de réglage : objectif lisse à optimum caché, avec held-out décalé.
pub struct ConfigTuning {
    /// optimum d'entraînement (espace normalisé).
    opt_train: [f64; 3],
    /// optimum held-out (légèrement décalé → généralisation imparfaite).
    opt_heldout: [f64; 3],
    sigma: f64,
}

impl Default for ConfigTuning {
    fn default() -> Self {
        ConfigTuning {
            opt_train: [0.5, 0.25, 0.4],
            opt_heldout: [0.55, 0.25, 0.4],
            sigma: 0.25,
        }
    }
}

impl ConfigTuning {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configuration initiale (volontairement loin de l'optimum).
    pub fn seed_candidate(&self) -> TuneConfig {
        TuneConfig {
            top_k: 1.0,
            chunk: 16.0,
            threshold: 0.0,
        }
    }

    /// Objectif gaussien lisse ∈ (0,1], maximal (=1) à l'optimum donné.
    fn objective(&self, cfg: &TuneConfig, opt: &[f64; 3]) -> f64 {
        let n = cfg.normalized();
        let d2: f64 = (0..3).map(|i| (n[i] - opt[i]).powi(2)).sum();
        (-d2 / (2.0 * self.sigma * self.sigma)).exp()
    }
}

impl RefineTask for ConfigTuning {
    type Cand = TuneConfig;

    fn score(&self, cand: &TuneConfig) -> f64 {
        self.objective(cand, &self.opt_train)
    }

    /// Générateur de repli (chemin non-LLM) : nudge déterministe d'une
    /// coordonnée. Le domaine vise le chemin LLM ; ceci satisfait le supertrait.
    fn refine(&mut self, cand: &TuneConfig, iter: usize) -> TuneConfig {
        let mut out = cand.clone();
        match iter % 3 {
            0 => out.top_k = (out.top_k + 1.0).clamp(TOP_K_LO, TOP_K_HI),
            1 => out.chunk = (out.chunk + 16.0).clamp(CHUNK_LO, CHUNK_HI),
            _ => out.threshold = (out.threshold + 0.05).clamp(THRESH_LO, THRESH_HI),
        }
        out
    }
}

impl LlmRefineTask for ConfigTuning {
    fn describe(&self, incumbent: &TuneConfig) -> String {
        format!(
            "Tâche : régler les hyperparamètres d'un retriever pour maximiser la \
             qualité. Bornes : top_k∈[{TOP_K_LO},{TOP_K_HI}], \
             chunk∈[{CHUNK_LO},{CHUNK_HI}], threshold∈[{THRESH_LO},{THRESH_HI}].\n\
             Config actuelle : {}\n\
             Score (qualité ∈ [0,1]) : {:.3}\n\
             Réponds avec une config JSON améliorée par ligne, p. ex. \
             {{\"top_k\":50,\"chunk\":1024,\"threshold\":0.4}}",
            incumbent.to_json_string(),
            self.score(incumbent)
        )
    }

    fn parse_proposals(&self, raw: &[String]) -> Vec<TuneConfig> {
        raw.iter()
            .filter_map(|s| Json::parse(s).ok().as_ref().and_then(TuneConfig::from_json))
            .collect()
    }

    fn score_heldout(&self, cand: &TuneConfig) -> f64 {
        self.objective(cand, &self.opt_heldout)
    }

    /// Validation de schéma : rejette toute config hors bornes.
    fn safety_check(&self, cand: &TuneConfig) -> Result<(), SafetyViolation> {
        let check = |name: &str, v: f64, lo: f64, hi: f64| -> Result<(), SafetyViolation> {
            if !v.is_finite() || v < lo || v > hi {
                Err(SafetyViolation(format!(
                    "{name}={v} hors bornes [{lo},{hi}]"
                )))
            } else {
                Ok(())
            }
        };
        check("top_k", cand.top_k, TOP_K_LO, TOP_K_HI)?;
        check("chunk", cand.chunk, CHUNK_LO, CHUNK_HI)?;
        check("threshold", cand.threshold, THRESH_LO, THRESH_HI)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{ascend_llm, LlmGuard, LlmStop, MockLlmClient};

    #[test]
    fn objective_peaks_at_optimum() {
        let t = ConfigTuning::new();
        // config à l'optimum train normalisé [0.5, 0.25, 0.4]
        let at_opt = TuneConfig {
            top_k: TOP_K_LO + 0.5 * (TOP_K_HI - TOP_K_LO),
            chunk: CHUNK_LO + 0.25 * (CHUNK_HI - CHUNK_LO),
            threshold: 0.4,
        };
        assert!((t.score(&at_opt) - 1.0).abs() < 1e-9);
        // la graine (coin) est nettement moins bonne
        assert!(t.score(&t.seed_candidate()) < 0.5);
    }

    #[test]
    fn parse_proposals_filters_malformed_and_missing_keys() {
        let t = ConfigTuning::new();
        let raw = vec![
            "{\"top_k\":50,\"chunk\":1024,\"threshold\":0.4}".to_string(), // ok
            "{\"top_k\":50,\"chunk\":1024}".to_string(),                   // clé manquante
            "pas du json".to_string(),                                     // non parsable
        ];
        let cands = t.parse_proposals(&raw);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].top_k, 50.0);
    }

    #[test]
    fn llm_path_tunes_via_mock() {
        let mut task = ConfigTuning::new();
        // mock : propose une config médiocre puis une quasi-optimale (JSON)
        let client = MockLlmClient::new(|_p, _k| {
            vec![
                "{\"top_k\":10,\"chunk\":200,\"threshold\":0.1}".to_string(),
                "{\"top_k\":50,\"chunk\":1036,\"threshold\":0.4}".to_string(),
            ]
        });
        let guard = LlmGuard {
            target: Some(0.95),
            patience: 3,
            max_iters: 20,
            ..LlmGuard::default()
        };
        let seed = task.seed_candidate();
        let (best, report) = ascend_llm(&mut task, seed, &client, &guard);

        assert!(report.is_monotone());
        assert!(report.accepted > 0);
        assert!(task.score(&best) > 0.95, "score={}", task.score(&best));
        // held-out élevé (optimum proche) mais distinct du train
        assert!(report.best_heldout() > 0.9);
        assert_eq!(report.stop, LlmStop::Target);
    }

    #[test]
    fn safety_check_rejects_out_of_bounds_config() {
        let mut task = ConfigTuning::new();
        let client = MockLlmClient::new(|_p, _k| {
            vec![
                "{\"top_k\":9999,\"chunk\":1024,\"threshold\":0.4}".to_string(), // top_k hors bornes
                "{\"top_k\":50,\"chunk\":1036,\"threshold\":0.4}".to_string(),   // valide
            ]
        });
        let guard = LlmGuard {
            max_iters: 5,
            patience: 2,
            ..LlmGuard::default()
        };
        let seed = task.seed_candidate();
        let (best, report) = ascend_llm(&mut task, seed, &client, &guard);
        assert!(report.rejected_unsafe > 0, "config hors bornes non rejetée");
        // l'incumbent adopté reste dans les bornes
        assert!(task.safety_check(&best).is_ok());
    }
}
