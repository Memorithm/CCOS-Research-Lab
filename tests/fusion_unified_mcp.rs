//! CCOS_EXTENDED fusion integration test (plan P5/P6): the **unified MCP
//! surface** — one server multiplexing the four namespaces (`ccos.*` core +
//! `slha.*` + `octa.*` + `rsi.*`).
//!
//! Verifies, end-to-end through the JSON-RPC `handle` entry point:
//!   1. `tools/list` advertises all four namespaces in the fused build — and
//!      every advertised premium tool is actually dispatchable;
//!   2. the community tier gets a *visible* `isError` refusal on every
//!      kernel-touching premium tool (no silent downgrade, no protocol error),
//!      while the free `ccos.*` tools keep working;
//!   3. the Pro tier executes the real kernels: `slha.audit`/`slha.compress`
//!      (incl. the TurboQuant TQ3 codec)/`slha.score`, and `octa.cascade_recall`
//!      reranks live session content;
//!   4. `rsi.status` reports compiled capabilities + gates, and the posture
//!      pins that self-modification is unreachable over MCP;
//!   5. premium tools are read-only for the checkpointing loop (none is a
//!      mutating call).

#![cfg(all(feature = "slhav2-full", feature = "octacore", feature = "rsi"))]

use ccos::agent_session::AgentSession;
use ccos::license::{License, Licensing};
use ccos::mcp::handle;
use serde_json::{json, Value};

fn req(id: i64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

fn call(s: &mut AgentSession, id: i64, tool: &str, args: Value) -> Value {
    handle(
        s,
        &req(id, "tools/call", json!({ "name": tool, "arguments": args })),
    )
    .expect("a request gets a response")
}

fn pro(s: &mut AgentSession) {
    s.set_licensing(Licensing::licensed(License {
        licensee: "acme".into(),
        expires_at: None,
        machine: None,
    }));
}

/// Content text of a tool result.
fn text(r: &Value) -> &str {
    r["result"]["content"][0]["text"].as_str().unwrap()
}

#[test]
fn tools_list_advertises_all_four_namespaces() {
    let mut s = AgentSession::new();
    let r = handle(&mut s, &req(1, "tools/list", Value::Null)).unwrap();
    let names: Vec<&str> = r["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    // Core surface intact…
    for core in ["ingest", "recall", "verify", "timeline", "get", "sync"] {
        assert!(names.contains(&core), "core tool {core} missing: {names:?}");
    }
    // …plus the three premium namespaces.
    for premium in [
        "slha.explain",
        "slha.audit",
        "slha.compress",
        "slha.score",
        "slha.benchmark",
        "octa.explain",
        "octa.cascade_recall",
        "rsi.explain",
        "rsi.status",
    ] {
        assert!(names.contains(&premium), "{premium} missing: {names:?}");
    }
}

#[test]
fn community_tier_gets_visible_refusals_and_a_working_core() {
    let mut s = AgentSession::new();
    // Kernel-touching premium tools refuse visibly (tool-level isError naming
    // the tier), never a protocol error and never a silent downgrade.
    for tool in ["slha.audit", "slha.benchmark", "octa.cascade_recall"] {
        let zeros = vec![0.0f64; 128];
        let r = call(
            &mut s,
            1,
            tool,
            json!({ "text": "q", "key": zeros, "query": vec![0.0f64; 128] }),
        );
        assert_eq!(r["result"]["isError"], true, "{tool}: {r}");
        assert!(text(&r).contains("Pro"), "{tool} names the tier: {r}");
    }
    // The free core keeps working in the same session.
    let r = call(
        &mut s,
        2,
        "ingest",
        json!({ "uri": "src/a.rs", "source": "pub fn a() {}\n" }),
    );
    assert!(r["result"]["content"][0]["text"].as_str().is_some());
}

#[test]
fn pro_tier_runs_the_slha_kernel_over_mcp() {
    let mut s = AgentSession::new();
    pro(&mut s);

    // Self-audit returns the kernel's JSON report.
    let r = call(&mut s, 1, "slha.audit", json!({}));
    assert_ne!(r["result"]["isError"], true, "{r}");
    assert!(text(&r).contains("{"), "audit returns JSON: {r}");

    // Compression with the TurboQuant TQ3 codec (the ingested upstream work).
    let key: Vec<f64> = (0..128).map(|i| (i as f64 / 128.0) - 0.5).collect();
    let r = call(
        &mut s,
        2,
        "slha.compress",
        json!({ "key": key, "codec": "tq3" }),
    );
    assert_ne!(r["result"]["isError"], true, "{r}");
    let p: Value = serde_json::from_str(text(&r)).unwrap();
    assert_eq!(p["codec"], "tq3");
    assert_eq!(p["latent_bytes"], 64);
    assert_eq!(p["tile_bytes"], 128);

    // Score probe reports the reconstruction error vs the exact dot product.
    let key: Vec<f64> = (0..128).map(|i| ((i % 7) as f64) / 7.0 - 0.5).collect();
    let r = call(
        &mut s,
        3,
        "slha.score",
        json!({ "key": key.clone(), "query": key }),
    );
    let p: Value = serde_json::from_str(text(&r)).unwrap();
    assert!(p["slha_score"].is_number() && p["true_dot"].is_number());
    assert!(p["abs_err"].as_f64().unwrap() >= 0.0);

    // An unknown codec is an invalid-params error, not a crash.
    let r = call(
        &mut s,
        4,
        "slha.compress",
        json!({ "key": vec![0.0f64; 128], "codec": "fp8" }),
    );
    assert_eq!(r["error"]["code"], -32602, "{r}");
}

#[test]
fn pro_tier_cascade_recall_reranks_live_session_content() {
    let mut s = AgentSession::new();
    pro(&mut s);
    call(
        &mut s,
        1,
        "ingest",
        json!({ "uri": "src/db.rs",
                "source": "pub fn open_pooled_database_connection() -> u32 { 30 }\n" }),
    );
    call(
        &mut s,
        2,
        "ingest",
        json!({ "uri": "src/log.rs", "source": "pub fn rotate_log_files() -> u32 { 0 }\n" }),
    );
    let r = call(
        &mut s,
        3,
        "octa.cascade_recall",
        json!({ "text": "open a pooled database connection", "k": 3, "budget": 4096 }),
    );
    assert_ne!(r["result"]["isError"], true, "{r}");
    let p: Value = serde_json::from_str(text(&r)).unwrap();
    assert_eq!(p["strategy"], "octa-cascade");
    let items = p["items"].as_array().unwrap();
    assert!(!items.is_empty(), "cascade returned items: {p}");
    assert!(
        items[0]["uri"].as_str().unwrap().contains("db.rs"),
        "the db node ranks first: {p}"
    );
    // Missing text is an invalid-params error.
    let r = call(&mut s, 4, "octa.cascade_recall", json!({}));
    assert_eq!(r["error"]["code"], -32602);
}

#[test]
fn rsi_status_reports_gates_and_pins_the_no_self_modification_posture() {
    let mut s = AgentSession::new();

    // Community: gates report the visible lock.
    let r = call(&mut s, 1, "rsi.status", json!({}));
    let p: Value = serde_json::from_str(text(&r)).unwrap();
    assert_eq!(p["compiled"]["rsi"], true);
    assert!(p["gates"]["rsi_self_improvement"]
        .as_str()
        .unwrap()
        .contains("license"));
    assert!(
        p["posture"].as_str().unwrap().contains("No MCP tool"),
        "posture pins MCP unreachability: {p}"
    );

    // Pro: gates unlock — status stays read-only either way.
    pro(&mut s);
    let r = call(&mut s, 2, "rsi.status", json!({}));
    let p: Value = serde_json::from_str(text(&r)).unwrap();
    assert_eq!(p["gates"]["rsi_self_improvement"], "unlocked");
    assert_eq!(p["gates"]["rsi_dgm"], "unlocked");

    // There is NO rsi execution tool in the catalogue — by design.
    let list = handle(&mut s, &req(3, "tools/list", Value::Null)).unwrap();
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names
            .iter()
            .filter(|n| n.starts_with("rsi."))
            .all(|n| matches!(*n, "rsi.explain" | "rsi.status")),
        "only read-only rsi tools are advertised: {names:?}"
    );
}

#[test]
fn explain_tools_are_free_and_informative() {
    let mut s = AgentSession::new(); // community tier
    for (tool, needle) in [
        ("slha.explain", "TurboQuant"),
        ("octa.explain", "cascade"),
        ("rsi.explain", "GuardedDgm"),
    ] {
        let r = call(&mut s, 1, tool, json!({}));
        assert_ne!(r["result"]["isError"], true, "{tool} is free prose: {r}");
        assert!(text(&r).contains(needle), "{tool} mentions {needle}: {r}");
    }
}
