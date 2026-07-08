//! **Premium MCP namespaces** (CCOS_EXTENDED, plan P5) — the `slha.*`, `octa.*`
//! and `rsi.*` tool families multiplexed into the single CCOS MCP server
//! (`src/mcp.rs`), each behind its cargo feature and — for every capability that
//! touches a premium kernel — the offline Pro license gate of its bridge module.
//!
//! One server, four namespaces:
//!
//! - `ccos.*` — the core memory tools (always compiled; see [`crate::mcp`]).
//! - `slha.*` (`slhav2-full`) — the REAL `ccos-scirust` attention kernel:
//!   self-audit, codec-parameterised compression (INT4 / grouped / NF4 / mixed /
//!   TQ3), score-vs-exact error probe, and host throughput. Gated by
//!   [`FullSlhaAccess`](crate::slha_full::FullSlhaAccess) (except `slha.explain`,
//!   which is inert prose).
//! - `octa.*` (`octacore`) — the validated causal-narrow → semantic-rerank
//!   cascade over the live session memory, gated by
//!   [`CausalCascadeAccess`](crate::octacore_bridge::CausalCascadeAccess).
//! - `rsi.*` (`rsi`) — self-improvement tier *status and documentation only*.
//!   **The DGM loop is deliberately NOT exposed over MCP**: it edits files and
//!   runs a build/test subprocess, so its only entry points are the explicit,
//!   allowlisted [`GuardedDgm`](crate::rsi_bridge::GuardedDgm) API and the CLI —
//!   a remote MCP client must never be able to trigger self-modification.
//!
//! Every gate refusal is a *visible* `isError` tool result naming the tier —
//! never a silent downgrade and never a protocol error (the free `ccos.*`
//! surface keeps working regardless of tier).
//!
//! ## Replay boundary
//!
//! All tools here are **read-only** with respect to the event-sourced session
//! (nothing is journaled, nothing checkpoints): they compute over derived or
//! synthetic state. `slha.benchmark` reports wall-clock timings (measurement,
//! not memory state) and the `slha.*` kernels are the documented SIMD
//! REPLAY-RELAX; `octa.cascade_recall` follows its embedder — the deterministic
//! [`HashEmbedder`](octasoma::HashEmbedder) used here keeps it bit-replayable.
//! The journaled premium recall path stays the `recall` tool's `octa-semantic`
//! strategy (see [`crate::mcp`]).

#![cfg(any(feature = "slhav2-full", feature = "octacore", feature = "rsi"))]

use crate::agent_session::AgentSession;
use serde_json::{json, Value};

/// True iff `name` belongs to a premium namespace **compiled into this build**.
/// A namespace that is not compiled falls through to the core dispatcher's
/// `unknown tool` error — the catalogue never advertised it.
pub fn is_premium_tool(name: &str) -> bool {
    let mut known = false;
    #[cfg(feature = "slhav2-full")]
    {
        known = known || name.starts_with("slha.");
    }
    #[cfg(feature = "octacore")]
    {
        known = known || name.starts_with("octa.");
    }
    #[cfg(feature = "rsi")]
    {
        known = known || name.starts_with("rsi.");
    }
    known
}

/// The premium tool catalogue for this build, appended to `tools/list` by
/// [`crate::mcp`]. Same never-promise-what-this-build-cannot-execute rule as the
/// core catalogue: a namespace appears only when its feature is compiled in.
pub fn tool_specs() -> Vec<Value> {
    #[allow(unused_mut)]
    let mut tools: Vec<Value> = Vec::new();
    #[cfg(feature = "slhav2-full")]
    tools.extend([
        json!({
            "name": "slha.explain",
            "description": "Explain SLHA v2 (the 128-byte KV tile, the selectable latent codecs incl. the TurboQuant TQ3 port, the hybrid attention score) and how the full kernel integrates as a CCOS memory backend. Prose; no license required.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
        json!({
            "name": "slha.audit",
            "description": "Run the SLHA v2 self-audit (tile layout, live SIMD-vs-scalar equivalence, CPU features/caches, output fidelity vs full attention, CCOS budget invariant, determinism). Pro tier.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
        json!({
            "name": "slha.compress",
            "description": "Quantize a 128-dim key vector into the 64-byte latent of a 128-byte tile and report the compression vs FP32. Optional `codec` selects the latent quantizer (default int4). Pro tier.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": {"type": "array", "items": {"type": "number"}, "description": "128 numbers (the key vector)"},
                    "codec": {"type": "string", "enum": ["int4", "grouped", "nf4", "mixed", "tq3"],
                              "description": "latent codec (default int4: uniform INT4, single scale). grouped = per-group MX scales; nf4 = normal-float codebook; mixed = 8 dims @8-bit + 112 @4-bit; tq3 = TurboQuant port, 3-bit grid + 1-bit sign-correction plane."}
                },
                "required": ["key"]
            }
        }),
        json!({
            "name": "slha.score",
            "description": "Build a tile from `key` and compute the SLHA coarse score for `query`, vs the exact dot product — shows the INT4 reconstruction error. Pro tier.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": {"type": "array", "items": {"type": "number"}, "description": "128 numbers (the context key)"},
                    "query": {"type": "array", "items": {"type": "number"}, "description": "128 numbers (the query)"}
                },
                "required": ["key", "query"]
            }
        }),
        json!({
            "name": "slha.benchmark",
            "description": "Measure SLHA score throughput on this host (scores/sec, ns/score, dispatched SIMD path). Optional `n` = iteration count. Pro tier.",
            "inputSchema": {
                "type": "object",
                "properties": {"n": {"type": "integer", "description": "iterations (default 200000)"}}
            }
        }),
    ]);
    #[cfg(feature = "octacore")]
    tools.extend([
        json!({
            "name": "octa.explain",
            "description": "Explain the OctaCore cascade (CCOS causal narrow -> OctaSoma exact-cosine rerank) and how it differs from the journaled `recall` strategy 'octa-semantic'. Prose; no license required.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
        json!({
            "name": "octa.cascade_recall",
            "description": "Semantic recall through the validated cascade: the free-text query is causally narrowed by CCOS, then reranked by OctaSoma's exact cosine over a deterministic offline embedder. Read-only (a derived index over the live graph; the op is NOT journaled — use `recall` strategy 'octa-semantic' for the journaled, replay-exact path). Pro tier.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "free-text query"},
                    "k": {"type": "integer", "description": "top-k items to rerank (default 8)"},
                    "budget": {"type": "integer", "description": "token budget for the window (default 2048)"}
                },
                "required": ["text"]
            }
        }),
    ]);
    #[cfg(feature = "rsi")]
    tools.extend([
        json!({
            "name": "rsi.explain",
            "description": "Explain the RSI (recursive self-improvement) tier: the deterministic std-only core, the hard-sandboxed DGM loop, and why DGM execution is CLI-only (never reachable over MCP). Prose; no license required.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
        json!({
            "name": "rsi.status",
            "description": "Report the RSI tier's compiled capabilities (dgm/llm sub-features) and the runtime license gates (RsiSelfImprovement, RsiDgm) for this session — unlocked or the visible refusal. Read-only, deterministic; performs no self-improvement step.",
            "inputSchema": {"type": "object", "properties": {}}
        }),
    ]);
    tools
}

/// Wrap a payload string as MCP tool-call content (mirrors `mcp::content`).
fn content(text: String) -> Value {
    json!({ "content": [{ "type": "text", "text": text }] })
}

/// A visible tool-level refusal (`isError`), the no-silent-downgrade shape every
/// Pro gate in the core server uses.
fn refusal(text: String) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": true })
}

/// Dispatch a premium `tools/call`. Only called for names where
/// [`is_premium_tool`] returned `true`.
pub fn call_tool(
    session: &mut AgentSession,
    name: &str,
    args: &Value,
) -> Result<Value, (i64, String)> {
    #[cfg(not(all(feature = "slhav2-full", feature = "octacore", feature = "rsi")))]
    let _ = (session as &AgentSession, args); // silence per-feature unused warnings
    match name {
        #[cfg(feature = "slhav2-full")]
        n if n.starts_with("slha.") => slha::call(session, n, args),
        #[cfg(feature = "octacore")]
        n if n.starts_with("octa.") => octa::call(session, n, args),
        #[cfg(feature = "rsi")]
        n if n.starts_with("rsi.") => rsi_ns::call(session, n, args),
        other => Err((-32602, format!("unknown tool: {other}"))),
    }
}

/// `slha.*` — the SLHAv2 full kernel, mirrored from the standalone `slha-mcp`
/// server so agents see the same contract whether they speak to the fused CCOS
/// server or the upstream one — plus the CCOS-side Pro gate.
#[cfg(feature = "slhav2-full")]
mod slha {
    use super::{content, refusal, AgentSession};
    use crate::slha_full::FullSlhaAccess;
    use ccos_scirust::attention::slha_v2::{
        quantize_latent, quantize_latent_grouped, quantize_latent_mixed, quantize_latent_nf4,
        quantize_latent_tq3, FLAG_HOT, FLAG_MIXED, FLAG_NF4, FLAG_TQ3, N_GROUPS,
    };
    use ccos_scirust::metrics::dot;
    use ccos_scirust::scenario::{build_tile, generate, ContextToken, Projection};
    use ccos_scirust::D_C;
    use serde_json::{json, Value};

    const DIMS: usize = D_C;

    pub fn call(
        session: &mut AgentSession,
        name: &str,
        args: &Value,
    ) -> Result<Value, (i64, String)> {
        if name == "slha.explain" {
            return Ok(content(explain()));
        }
        // Every kernel-touching tool goes through the same Pro gate as the
        // `ScirustBackend` — visible refusal, free tiers unaffected.
        let _access = match FullSlhaAccess::unlock(session.licensing(), crate::license::now_unix())
        {
            Ok(a) => a,
            Err(e) => {
                return Ok(refusal(format!(
                    "{name} is part of the Pro SLHAv2 full-kernel tier — {e}. The core \
                         ccos.* tools (and the distilled `slhav2` backend) remain fully \
                         functional."
                )))
            }
        };
        match name {
            "slha.audit" => Ok(content(ccos_scirust::audit::run().to_pretty())),
            "slha.compress" => compress(args),
            "slha.score" => score(args),
            "slha.benchmark" => Ok(content(benchmark(args))),
            other => Err((-32602, format!("unknown tool: {other}"))),
        }
    }

    fn explain() -> String {
        "SLHA v2 (Sub-Low-rank Hybrid Attention) compresses each transformer KV entry \
         into a 128-byte, cache-line-aware tile so long-context inference fits in CPU \
         cache instead of GPU VRAM. Each tile stores a 64-byte low-rank latent (128 \
         dims), a 32-byte 1-bit sign-LSH residual, and metadata. The latent codec is \
         selectable, same 64-byte budget: uniform INT4 (single or per-group scales), an \
         NF4 codebook, a mixed 8/4-bit layout, or TQ3 — a port of the TurboQuant KV \
         codec (3-bit grid + a separable per-dim 1-bit sign-correction plane). The \
         attention score fuses a continuous dot product over the dequantized latent \
         with a branchless popcount term over the residual; SIMD paths \
         (AVX2/AVX-512/NEON) are runtime-dispatched with a scalar reference proven \
         equivalent.\n\nIn CCOS_EXTENDED this kernel is the Pro `slhav2-full` memory \
         backend (`ScirustBackend`: HOT/WARM/COLD elastic soft-paging with informed \
         H2O/sink eviction) plus the `LatentSafetyGuard` pre-dequantisation injection \
         filter. Enabling it is a documented REPLAY-RELAX; the default and distilled \
         `slhav2` builds stay bit-replayable. Use `slha.audit` for live invariants, \
         `slha.compress`/`slha.score` to exercise the kernel, `slha.benchmark` for \
         host throughput."
            .to_string()
    }

    fn f32_dims(args: &Value, key: &str) -> Result<[f32; DIMS], (i64, String)> {
        let arr = args.get(key).and_then(Value::as_array).ok_or((
            -32602,
            format!("missing number array '{key}' (expected {DIMS} values)"),
        ))?;
        if arr.len() != DIMS {
            return Err((
                -32602,
                format!("'{key}' must have {DIMS} numbers, got {}", arr.len()),
            ));
        }
        let mut out = [0.0f32; DIMS];
        for (i, v) in arr.iter().enumerate() {
            out[i] = v
                .as_f64()
                .ok_or((-32602, format!("'{key}[{i}]' is not a number")))?
                as f32;
        }
        Ok(out)
    }

    fn compress(args: &Value) -> Result<Value, (i64, String)> {
        let key = f32_dims(args, "key")?;
        let codec = match args.get("codec") {
            None => "int4",
            Some(v) => v
                .as_str()
                .ok_or((-32602, "'codec' must be a string".to_string()))?,
        };
        // Same codec -> (quantizer, FLAG_*) mapping as the standalone slha-mcp
        // server and `LearnedModel::encode_with`.
        let (latent, scale, group_scales, flags) = match codec {
            "int4" => {
                let (l, s) = quantize_latent(&key);
                (l, s, [255u8; N_GROUPS], FLAG_HOT)
            }
            "grouped" => {
                let (l, s, gs) = quantize_latent_grouped(&key);
                (l, s, gs, FLAG_HOT)
            }
            "nf4" => {
                let (l, s, gs) = quantize_latent_nf4(&key);
                (l, s, gs, FLAG_NF4)
            }
            "mixed" => {
                let (l, s, gs) = quantize_latent_mixed(&key);
                (l, s, gs, FLAG_MIXED)
            }
            "tq3" => {
                let (l, s, gs) = quantize_latent_tq3(&key);
                (l, s, gs, FLAG_TQ3)
            }
            other => {
                return Err((
                    -32602,
                    format!("unknown codec '{other}': expected int4 | grouped | nf4 | mixed | tq3"),
                ))
            }
        };
        let payload = json!({
            "input_dims": DIMS,
            "input_bytes_f32": DIMS * 4,
            "tile_bytes": 128,
            "latent_bytes": latent.len(),
            "codec": codec,
            "flags": flags,
            "compression_ratio_vs_fp32_key": (DIMS * 4) as f64 / 128.0,
            "scale": scale,
            "group_scales": group_scales.to_vec(),
            "latent_first_8_bytes": latent.iter().take(8).copied().collect::<Vec<u8>>(),
        });
        Ok(content(payload.to_string()))
    }

    fn score(args: &Value) -> Result<Value, (i64, String)> {
        let key = f32_dims(args, "key")?;
        let query = f32_dims(args, "query")?;
        let proj = Projection::new(0x5C04E);
        // Treat the key as captured exactly (residual e = 0): isolates INT4
        // latent error (same probe as the standalone slha-mcp server).
        let tok = ContextToken {
            k_coarse: key,
            e: [0.0f32; DIMS],
            k_real: key,
        };
        let tile = build_tile(&proj, &tok, 0, false);
        let qs = proj.sign_bits(&query);
        let slha = tile.compute_score(&query, &qs);
        let truth = dot(&query, &key);
        let payload = json!({
            "slha_score": slha,
            "true_dot": truth,
            "abs_err": (slha - truth).abs(),
            "rel_err": (slha - truth).abs() / (1.0 + truth.abs()),
            "note": "residual e=0 here, so this isolates the INT4 latent reconstruction error",
        });
        Ok(content(payload.to_string()))
    }

    fn benchmark(args: &Value) -> String {
        let n = args
            .get("n")
            .and_then(Value::as_u64)
            .unwrap_or(200_000)
            .clamp(1_000, 5_000_000) as usize;
        let proj = Projection::new(0xB0001);
        let (q, toks) = generate(0xB0001, 64, 0.3);
        let qs = proj.sign_bits(&q);
        let tiles: Vec<_> = toks
            .iter()
            .enumerate()
            .map(|(i, t)| build_tile(&proj, t, i as u32, false))
            .collect();
        let mut acc = 0.0f32;
        let t0 = std::time::Instant::now();
        for i in 0..n {
            acc += tiles[i % tiles.len()].compute_score(&q, &qs);
        }
        let secs = t0.elapsed().as_secs_f64();
        std::hint::black_box(acc);
        json!({
            "scores": n,
            "seconds": secs,
            "scores_per_sec": n as f64 / secs.max(1e-12),
            "ns_per_score": secs * 1e9 / n as f64,
            "arch": std::env::consts::ARCH,
        })
        .to_string()
    }
}

/// `octa.*` — the OctaCore cascade over the live session memory.
#[cfg(feature = "octacore")]
mod octa {
    use super::{content, refusal, AgentSession};
    use crate::external_memory::{CcosMemory, ExternalMemory, Recall};
    use crate::octacore_bridge::CausalCascadeAccess;
    use octacore::{Cascade, CausalScope, ScopeItem};
    use serde_json::{json, Value};

    /// A *borrowed* CCOS memory dressed as an `octacore::CausalScope` — the MCP
    /// twin of [`crate::octacore_bridge::CcosScope`] (which owns its memory; a
    /// tool call only ever borrows the session's).
    struct SessionScope<'a> {
        mem: &'a CcosMemory,
    }

    impl CausalScope for SessionScope<'_> {
        fn scope(&self, query: &str, budget_tokens: usize) -> Vec<ScopeItem> {
            self.mem
                .recall(&Recall::task(query), budget_tokens)
                .items
                .into_iter()
                .map(|it| ScopeItem {
                    uri: it.uri,
                    content: it.content,
                })
                .collect()
        }
    }

    pub fn call(
        session: &mut AgentSession,
        name: &str,
        args: &Value,
    ) -> Result<Value, (i64, String)> {
        match name {
            "octa.explain" => Ok(content(explain())),
            "octa.cascade_recall" => {
                let text = args.get("text").and_then(Value::as_str).unwrap_or("");
                if text.is_empty() {
                    return Err((-32602, "octa.cascade_recall requires 'text'".into()));
                }
                let _access = match CausalCascadeAccess::unlock(
                    session.licensing(),
                    crate::license::now_unix(),
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        return Ok(refusal(format!(
                            "octa.cascade_recall is part of the Pro semantic-memory tier — {e}. \
                             The free recall strategies (around/task/semantic/hybrid/\
                             working_set) remain fully functional."
                        )))
                    }
                };
                let k = args.get("k").and_then(Value::as_u64).unwrap_or(8) as usize;
                let budget = args.get("budget").and_then(Value::as_u64).unwrap_or(2048) as usize;
                // Deterministic offline embedder: the cascade stays bit-replayable
                // (the replay boundary is the embedder — module docs).
                let scope = SessionScope {
                    mem: session.memory(),
                };
                let cascade = Cascade::new(scope, octasoma::HashEmbedder::new(128));
                match cascade.recall(text, k, budget) {
                    Ok(win) => {
                        let items: Vec<Value> = win
                            .items
                            .iter()
                            .map(
                                |i| json!({ "uri": i.uri, "score": i.score, "content": i.content }),
                            )
                            .collect();
                        Ok(content(
                            json!({ "strategy": "octa-cascade", "items": items }).to_string(),
                        ))
                    }
                    Err(e) => Ok(refusal(format!("cascade recall failed: {e}"))),
                }
            }
            other => Err((-32602, format!("unknown tool: {other}"))),
        }
    }

    fn explain() -> String {
        "The OctaCore cascade is the validated two-stage semantic recall: CCOS first \
         narrows the query to a causally-coherent region (cheap, graph-native), then \
         OctaSoma reranks that shortlist by exact cosine over real embeddings. \
         `octa.cascade_recall` runs it read-only over the live session graph with a \
         deterministic offline embedder (bit-replayable, nothing journaled). For the \
         journaled, event-sourced premium recall — the one that lands in the timeline \
         and replays exactly — use the `recall` tool with strategy 'octa-semantic' \
         (plus `octa_feedback` to calibrate its conformal anchor gate). Both are Pro \
         capabilities behind the same license feature; the free recall strategies are \
         untouched."
            .to_string()
    }
}

/// `rsi.*` — status/documentation only. Execution stays out of MCP by design.
#[cfg(feature = "rsi")]
mod rsi_ns {
    use super::{content, AgentSession};
    use crate::license::{Feature, Licensing};
    use serde_json::{json, Value};

    pub fn call(
        session: &mut AgentSession,
        name: &str,
        _args: &Value,
    ) -> Result<Value, (i64, String)> {
        match name {
            "rsi.explain" => Ok(content(explain())),
            "rsi.status" => Ok(content(status(session.licensing()))),
            other => Err((-32602, format!("unknown tool: {other}"))),
        }
    }

    /// Gate probe: "unlocked" or the license error text (visible, deterministic).
    fn gate(licensing: &Licensing, f: Feature) -> String {
        match licensing.require(f, crate::license::now_unix()) {
            Ok(()) => "unlocked".to_string(),
            Err(e) => e.to_string(),
        }
    }

    fn status(licensing: &Licensing) -> String {
        json!({
            "compiled": {
                "rsi": true,
                "rsi_dgm": cfg!(feature = "rsi-dgm"),
                "rsi_llm_proposer": cfg!(feature = "rsi-full"),
            },
            "gates": {
                "rsi_self_improvement": gate(licensing, Feature::RsiSelfImprovement),
                "rsi_dgm": gate(licensing, Feature::RsiDgm),
            },
            "posture": "DGM execution is API-only — the typed GuardedDgm API with an \
                        explicit editable-file allowlist (GuardLayer sanitation, \
                        air-gapped `cargo --offline --frozen` evaluator, hash-chain \
                        audit). No MCP tool and no CLI one-liner can trigger \
                        self-modification.",
        })
        .to_string()
    }

    fn explain() -> String {
        "The RSI tier vendors the CERVO/RSI engine as `ccos-rsi` (a pure leaf crate — \
         the circular dependency was inverted; the CCOS-side bridge lives in \
         `src/rsi_bridge.rs`). Two capabilities, two gates: (1) `rsi` — the \
         deterministic std-only self-improvement core whose audit trail lands in \
         CCOS's hash-chained EventLog via `CcosAudit` (replay == live); (2) `rsi-dgm` \
         — the Darwin–Gödel-Machine loop, hard-sandboxed by `GuardedDgm`: an \
         editable-file allowlist decides what may ever be patched, proposals are \
         sanitized through the GuardLayer, candidates are evaluated by an air-gapped \
         `cargo --offline --frozen` subprocess (bounded output + timeout + kill), and \
         every step — accepted, refused or blocked — is recorded as a tamper-evident \
         `SelfModify`/`RsiMutation` event. DGM is a documented REPLAY-RELAX and is \
         deliberately unreachable over MCP and the CLI: only the typed GuardedDgm \
         API (which forces an explicit allowlist) can run it. `rsi.status` reports \
         what this build compiled and what this session's license unlocks."
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn premium_namespaces_match_compiled_features() {
        assert_eq!(is_premium_tool("slha.audit"), cfg!(feature = "slhav2-full"));
        assert_eq!(
            is_premium_tool("octa.cascade_recall"),
            cfg!(feature = "octacore")
        );
        assert_eq!(is_premium_tool("rsi.status"), cfg!(feature = "rsi"));
        assert!(!is_premium_tool("ingest"));
        assert!(!is_premium_tool("recall"));
    }

    #[test]
    fn catalogue_only_advertises_compiled_namespaces() {
        let names: Vec<String> = tool_specs()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            names.iter().any(|n| n.starts_with("slha.")),
            cfg!(feature = "slhav2-full")
        );
        assert_eq!(
            names.iter().any(|n| n.starts_with("octa.")),
            cfg!(feature = "octacore")
        );
        assert_eq!(
            names.iter().any(|n| n.starts_with("rsi.")),
            cfg!(feature = "rsi")
        );
        // Every advertised premium tool is dispatchable.
        for n in &names {
            assert!(
                is_premium_tool(n),
                "catalogue advertises undispatchable {n}"
            );
        }
    }
}
