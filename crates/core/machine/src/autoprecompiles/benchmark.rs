//! Exporter for apc-optimizer benchmark sets.
//!
//! Produces a `Sp1Benchmarks/<name>/` directory in the same layout the
//! [apc-optimizer](https://github.com/powdr-labs/apc-optimizer) repo expects for
//! `OpenVmBenchmarks/<name>/`:
//!
//! * `apc_<rank>_pc<pc>.json`           – the unoptimized APC (apc-optimizer input)
//! * `apc_<rank>_pc<pc>.powdr_opt.json` – powdr's optimized APC, the reference the
//!   apc-optimizer is compared against
//! * `manifest.json`                    – ranking + per-case stats
//! * `apc_candidates.json`              – powdr's full candidate dump (assembly view)
//!
//! The `.json` files are gzipped to `.json.gz` by the orchestrating shell script
//! (`scripts/gen_sp1_benchmarks.sh`); the manifest already refers to the
//! `.json.gz` names.
//!
//! # `is_valid`-free powdr snapshots
//!
//! The raw per-block candidate export writes the *final* APC, i.e. after
//! [`powdr_autoprecompiles::build`] has run `add_guards`, so it carries an
//! `is_valid` guard column. Here we instead re-run powdr's [`optimize`] directly
//! on the same unoptimized machine `build` feeds it and serialize the result
//! *before* `add_guards`, so the powdr_opt snapshot has no `is_valid` column.
//! This matches the openvm-eth benchmark set. Everything below `optimize` is
//! public powdr API, so no fork/patch is required.

use std::{fs, path::Path, sync::Arc};

use itertools::Itertools;
use powdr_autoprecompiles::{
    export::ExportOptions, optimizer::optimize, symbolic_machine::SymbolicMachine, ColumnAllocator,
    PgoData, PgoType,
};
use powdr_number::KoalaBearField;
use serde_json::{json, Map, Value};
use sp1_core_executor::Program;

use crate::{
    autoprecompiles::{
        bus_interaction_handler::Sp1BusInteractionHandler, bus_map::sp1_bus_map,
        execution_profile_from_program, memory_bus_interaction::Sp1MemoryBusInteraction,
        sp1_configs, CompiledProgram, DEFAULT_DEGREE_BOUND,
    },
    io::SP1Stdin,
};

/// The size measures the manifest records for a machine.
fn machine_stats(machine: &SymbolicMachine<KoalaBearField>) -> Value {
    json!({
        "main_columns": machine.main_columns().count(),
        "constraints": machine.constraints.len(),
        "bus_interactions": machine.bus_interactions.len(),
    })
}

/// Generate an apc-optimizer benchmark set for `elf` executed on `stdin`, writing
/// it to `out_dir`.
///
/// `top_n` selects the top-ranked candidates by cell PGO (matching what a proving
/// run with `--autoprecompiles top_n --pgo cell` would enable). `note` is
/// recorded in the manifest `source` block.
///
/// This does not gzip the `.json` files — the orchestrating shell script does
/// that — but the manifest refers to their final `.json.gz` names.
pub fn export_benchmark_set(elf: &[u8], stdin: SP1Stdin, out_dir: &Path, top_n: u64, note: &str) {
    fs::create_dir_all(out_dir).expect("create out_dir");
    let raw_dir = out_dir.join("_candidates_raw");

    // 1. Cell PGO execution profile for `stdin`.
    let program = Arc::new(Program::from(elf).expect("parse elf"));
    let execution_profile = execution_profile_from_program(program, stdin);

    // 2. Build + rank all candidates, dumping powdr's per-block exports into
    //    `raw_dir` (the unoptimized machines we re-optimize below live there).
    let (generate, select) = sp1_configs(top_n, 0, PgoType::Cell);
    let generate = generate.with_apc_candidates_dir(&raw_dir);
    let pgo_data = PgoData::Cell(execution_profile, None);
    let compiled = CompiledProgram::new(elf, generate, select, pgo_data);

    let candidates_available = fs::read_dir(&raw_dir)
        .expect("read raw_dir")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with("_000_unopt.json"))
        .count();

    // 3. For each ranked candidate emit unopt + (guard-free) powdr_opt + manifest entry.
    let bus_map = sp1_bus_map();
    let mut entries = Vec::new();

    for (i, aws) in compiled.apcs_and_stats.into_iter().enumerate() {
        let rank = i + 1;
        let (apc, _pgo_stats, eval) = aws.into_parts();
        let start_pcs = apc.start_pcs();
        let pc0 = start_pcs[0];
        let base = format!("apc_{rank:03}_pc0x{pc0:x}");

        // The unoptimized machine powdr fed to `optimize` was dumped here by `build`.
        let stem = format!("apc_candidate_{}", start_pcs.iter().join("_"));
        let unopt_path = raw_dir.join(format!("{stem}_000_unopt.json"));
        let unopt_bytes =
            fs::read(&unopt_path).unwrap_or_else(|e| panic!("read {}: {e}", unopt_path.display()));
        let unopt_val: Value = serde_json::from_slice(&unopt_bytes).expect("parse unopt json");
        let machine: SymbolicMachine<KoalaBearField> =
            serde_json::from_value(unopt_val["machine"].clone()).expect("parse unopt machine");
        // Reuse the exact bus_map serialization from the unopt export.
        let bus_map_val = unopt_val["bus_map"].clone();

        // Re-run powdr's optimizer, snapshotting *before* add_guards (no is_valid).
        // Same optimization `build` runs, with the same degree bound.
        let column_allocator = ColumnAllocator::from_max_poly_id_of_machine(&machine);
        let (opt_machine, _) = optimize::<KoalaBearField, _, _, Sp1MemoryBusInteraction<_>>(
            machine.clone(),
            Sp1BusInteractionHandler::default(),
            DEFAULT_DEGREE_BOUND,
            &bus_map,
            column_allocator,
            &mut ExportOptions::default(),
        )
        .expect("powdr optimize");

        // Unopt file: verbatim (block/subs/optimistic_constraints/machine/bus_map).
        fs::write(out_dir.join(format!("{base}.json")), &unopt_bytes).expect("write unopt");

        // powdr_opt file: {machine, bus_map} — all the apc-optimizer reader needs.
        let mut opt_obj = Map::new();
        opt_obj.insert(
            "machine".to_string(),
            serde_json::to_value(&opt_machine).expect("serialize opt machine"),
        );
        opt_obj.insert("bus_map".to_string(), bus_map_val);
        fs::write(
            out_dir.join(format!("{base}.powdr_opt.json")),
            serde_json::to_vec(&Value::Object(opt_obj)).expect("serialize powdr_opt"),
        )
        .expect("write powdr_opt");

        entries.push(json!({
            "rank": rank,
            "start_pcs": start_pcs,
            "start_pcs_hex": start_pcs.iter().map(|p| format!("0x{p:x}")).collect::<Vec<_>>(),
            "files": {
                "unopt": format!("{base}.json.gz"),
                "powdr_opt": format!("{base}.powdr_opt.json.gz"),
            },
            // before/after come from powdr's own evaluation (after == post-guard APC).
            "stats": {
                "before": serde_json::to_value(&eval.before).expect("before stats"),
                "after": serde_json::to_value(&eval.after).expect("after stats"),
            },
            // The guard-free powdr-optimized machine we actually ship as `.powdr_opt`.
            "powdr_opt_stats": machine_stats(&opt_machine),
        }));
    }

    let exported = entries.len();
    let manifest = json!({
        "version": 1,
        "source": {
            "note": note,
            "top": top_n,
            "exported": exported,
            "candidates_available": candidates_available,
            "powdr_opt_stage": "after optimize(), before add_guards (no is_valid guards)",
            "field": "KoalaBear",
        },
        "entries": entries,
    });
    fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    // Keep powdr's full candidate dump (used for the HTML report's assembly view),
    // drop the rest of the bulky per-block exports.
    let candidates_json = raw_dir.join("apc_candidates.json");
    if candidates_json.exists() {
        fs::copy(&candidates_json, out_dir.join("apc_candidates.json"))
            .expect("copy apc_candidates.json");
    }
    fs::remove_dir_all(&raw_dir).expect("cleanup raw_dir");

    println!(
        "[bench] {note}: wrote {exported} case(s) (of {candidates_available} candidates) to {}",
        out_dir.display()
    );
}
