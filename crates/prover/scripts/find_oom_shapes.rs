#![allow(clippy::print_stdout)]

use std::{collections::BTreeMap, path::PathBuf};

use clap::Parser;
use sp1_core_executor::{rv32im_costs, RiscvAirId};
use sp1_core_machine::utils::setup_logger;
use sp1_stark::shape::Shape;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    maximal_shapes_json: Option<PathBuf>,
    #[arg(short, long)]
    small_shapes_json: Option<PathBuf>,
    #[arg(short, long)]
    lde_threshold_bytes: usize,
}

fn main() {
    // Setup logger.
    setup_logger();

    // Parse arguments.
    let args = Args::parse();

    // Load the costs.
    let costs = rv32im_costs();

    if let Some(maximal_shapes_json) = args.maximal_shapes_json {
        // Load the maximal shapes, indexed by log shard size.
        let maximal_shapes: BTreeMap<usize, Vec<Shape<RiscvAirId>>> = serde_json::from_slice(
            &std::fs::read(&maximal_shapes_json).expect("failed to read maximal shapes"),
        )
        .expect("failed to deserialize maximal shapes");

        // For each maximal shape, check if it is OOM.
        for (_, shapes) in maximal_shapes.iter() {
            for shape in shapes.iter() {
                let lde_size = shape.estimate_lde_size(&costs);
                if lde_size > args.lde_threshold_bytes {
                    println!("maximal shape: {:?}, lde_size: {}", shape, lde_size);
                }
            }
        }
    }

    if let Some(small_shapes_json) = args.small_shapes_json {
        // Load the small shapes.
        let small_shapes: Vec<Shape<RiscvAirId>> = serde_json::from_slice(
            &std::fs::read(&small_shapes_json).expect("failed to read small shapes"),
        )
        .expect("failed to deserialize small shapes");

        // For each small shape, check if it is OOM.
        for shape in small_shapes.iter() {
            let lde_size = shape.estimate_lde_size(&costs);
            if lde_size > args.lde_threshold_bytes {
                println!("small shape: {:?}, lde_size: {}", shape, lde_size);
            }
        }
    }
}
