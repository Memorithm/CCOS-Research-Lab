use ccos::benchmark::BenchmarkHarness;
use serde::Serialize;

#[derive(Serialize)]
struct ReproducibleReport {
    schema: &'static str,
    commit: String,
    dataset: &'static str,
    dataset_version: String,
    seed: &'static str,
    configuration: Configuration,
    result: ccos::benchmark::BenchmarkReport,
}

#[derive(Serialize)]
struct Configuration {
    cycles: usize,
    paging_cap: usize,
    files: usize,
    sample_every: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cycles = std::env::args()
        .nth(1)
        .ok_or("missing cycle count")?
        .parse::<usize>()?;
    if !(1..=10_000_000).contains(&cycles) {
        return Err("cycle count must be in 1..=10,000,000".into());
    }
    let commit = std::env::var("CCOS_BENCH_COMMIT")?;
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("CCOS_BENCH_COMMIT must be a 40-character Git commit".into());
    }

    let harness = BenchmarkHarness::new().with_paging_cap(200);
    let result = harness.run(cycles);
    let report = ReproducibleReport {
        schema: "ccos.benchmark/v1",
        dataset: "synthetic-edit-cycle-v1",
        dataset_version: format!("repository@{commit}"),
        seed: "deterministic-cycle-index",
        commit,
        configuration: Configuration {
            cycles,
            paging_cap: harness.paging_cap,
            files: harness.files,
            sample_every: harness.sample_every,
        },
        result,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
