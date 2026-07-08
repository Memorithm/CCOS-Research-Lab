//! Export de la trajectoire de simulation (CSV / JSON), sans dépendance.
//!
//! La trajectoire est une `&[StepReport]` produite par [`crate::RSIAgent::run`].
//! Les sérialiseurs sont écrits à la main pour rester 100 % std-only.

use std::io;
use std::path::Path;

use crate::agent::StepReport;

/// Sérialise la trajectoire au format CSV (une ligne d'en-tête + une par pas).
pub fn to_csv(reports: &[StepReport]) -> String {
    let mut s = String::new();
    s.push_str(
        "t,si_global,delta_si,p_eff,state_norm,meta_delta_norm,\
appr_si_before,appr_si_after,appr_delta_norm,clamped_to_lambda,backtracks,step_factor,\
frac_limited_by_substrate,risk_global,max_rpn,most_critical,si_safe,mitigation,D,M,R,A,C,V\n",
    );
    for r in reports {
        s.push_str(&format!(
            "{},{:.6},{:.6},{:.6},{:.6},{:.6},\
{:.6},{:.6},{:.6},{},{},{:.6},\
{:.6},{:.6},{:.6},{},{:.6},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}\n",
            r.t,
            r.si_global,
            r.delta_si,
            r.p_eff,
            r.state_norm,
            r.meta_delta_norm,
            r.appr.si_before,
            r.appr.si_after,
            r.appr.delta_norm,
            r.appr.clamped_to_lambda,
            r.appr.backtracks,
            r.appr.step_factor,
            r.frac_limited_by_substrate,
            r.risk_global,
            r.max_rpn,
            r.most_critical,
            r.si_safe,
            r.mitigation,
            r.capabilities[0],
            r.capabilities[1],
            r.capabilities[2],
            r.capabilities[3],
            r.capabilities[4],
            r.capabilities[5],
        ));
    }
    s
}

/// Sérialise la trajectoire en JSON (tableau d'objets imbriqués).
pub fn to_json(reports: &[StepReport]) -> String {
    let mut s = String::from("[\n");
    for (i, r) in reports.iter().enumerate() {
        let comma = if i + 1 < reports.len() { "," } else { "" };
        s.push_str(&format!(
            "  {{\"t\":{},\"si_global\":{:.6},\"delta_si\":{:.6},\
\"p_eff\":{:.6},\"state_norm\":{:.6},\"meta_delta_norm\":{:.6},\
\"appr\":{{\"si_before\":{:.6},\"si_after\":{:.6},\"delta_norm\":{:.6},\
\"clamped_to_lambda\":{},\"backtracks\":{},\"step_factor\":{:.6}}},\
\"frac_limited_by_substrate\":{:.6},\
\"risk_global\":{:.6},\"max_rpn\":{:.6},\"most_critical\":{:?},\"si_safe\":{:.6},\
\"mitigation\":{:?},\
\"capabilities\":{{\"D\":{:.6},\"M\":{:.6},\"R\":{:.6},\"A\":{:.6},\"C\":{:.6},\"V\":{:.6}}}}}{}\n",
            r.t,
            r.si_global,
            r.delta_si,
            r.p_eff,
            r.state_norm,
            r.meta_delta_norm,
            r.appr.si_before,
            r.appr.si_after,
            r.appr.delta_norm,
            r.appr.clamped_to_lambda,
            r.appr.backtracks,
            r.appr.step_factor,
            r.frac_limited_by_substrate,
            r.risk_global,
            r.max_rpn,
            r.most_critical,
            r.si_safe,
            r.mitigation,
            r.capabilities[0],
            r.capabilities[1],
            r.capabilities[2],
            r.capabilities[3],
            r.capabilities[4],
            r.capabilities[5],
            comma,
        ));
    }
    s.push_str("]\n");
    s
}

/// Écrit la trajectoire CSV dans un fichier.
pub fn write_csv<P: AsRef<Path>>(reports: &[StepReport], path: P) -> io::Result<()> {
    std::fs::write(path, to_csv(reports))
}

/// Écrit la trajectoire JSON dans un fichier.
pub fn write_json<P: AsRef<Path>>(reports: &[StepReport], path: P) -> io::Result<()> {
    std::fs::write(path, to_json(reports))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RSIAgent;

    #[test]
    fn csv_has_header_and_rows() {
        let mut agent = RSIAgent::demo(1);
        let reports = agent.run(10);
        let csv = to_csv(&reports);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 11); // 1 en-tête + 10 pas
        assert!(lines[0].starts_with("t,si_global"));
        // 19 d'origine + 4 criticité + mitigation = 24
        let header_cols = lines[0].split(',').count();
        assert_eq!(header_cols, 24);
        assert_eq!(lines[1].split(',').count(), header_cols);
    }

    #[test]
    fn json_is_well_formed_array() {
        let mut agent = RSIAgent::demo(1);
        let reports = agent.run(5);
        let json = to_json(&reports);
        assert!(json.trim_start().starts_with('['));
        assert!(json.trim_end().ends_with(']'));
        // 5 objets ⇒ 4 virgules de séparation entre objets
        let obj_count = json.matches("\"t\":").count();
        assert_eq!(obj_count, 5);
    }
}
