use std::{cmp::Ordering, collections::BTreeMap, path::PathBuf, sync::mpsc};

use clap::Parser;
use p3_baby_bear::BabyBear;
use sp1_core_executor::{Executor, Program, RiscvAirId, SP1Context};
use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir, utils::setup_logger};
use sp1_stark::{shape::Shape, SP1CoreOpts};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_delimiter = ' ')]
    list: Vec<String>,
    #[arg(short, long, value_delimiter = ' ')]
    shard_sizes: Vec<usize>,
    #[arg(short, long)]
    initial: Option<PathBuf>,
    #[arg(short, long, default_value = "maximal_shapes.json")]
    output: Option<PathBuf>,
}

fn collect_maximal_shapes(
    elf: &[u8],
    stdin: &SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context,
) -> Vec<Shape<RiscvAirId>> {
    // Setup the executor.
    let program = Program::from(elf).unwrap();
    let mut executor = Executor::with_context(program, opts, context);
    executor.write_vecs(&stdin.buffer);
    for (proof, vkey) in stdin.proofs.iter() {
        executor.write_proof(proof.clone(), vkey.clone());
    }

    // Use this to make sure we don't collect too many shapes that will just OOM out of the box.
    if opts.shard_size == 1 << 22 {
        executor.lde_size_check = true;
        executor.lde_size_threshold = 14 * 1_000_000_000;
    }

    // Collect the maximal shapes.
    let mut maximal_shapes = Vec::new();
    let mut finished = false;
    while !finished {
        let (records, f) = executor.execute_record(true).unwrap();
        finished = f;
        for mut record in records {
            if record.contains_cpu() {
                let _ = record.defer();
                let core_shape: Shape<RiscvAirId> = RiscvAir::<BabyBear>::core_heights(&record)
                    .into_iter()
                    .filter(|&(_, height)| (height != 0))
                    .map(|(air, height)| (air, height.next_power_of_two().ilog2() as usize))
                    .collect();

                maximal_shapes.push(core_shape);
            }
        }
    }

    maximal_shapes
}

fn insert(inner: &mut Vec<Shape<RiscvAirId>>, element: Shape<RiscvAirId>) {
    let mut to_remove = vec![];
    for (i, maximal_element) in inner.iter().enumerate() {
        match PartialOrd::partial_cmp(&element, maximal_element) {
            Some(Ordering::Greater) => {
                to_remove.push(i);
            }
            Some(Ordering::Less | Ordering::Equal) => {
                return;
            }
            None => {}
        }
    }
    for i in to_remove.into_iter().rev() {
        inner.remove(i);
    }
    inner.push(element);
}

fn main() {
    // Setup logger.
    setup_logger();

    // Parse arguments.
    let args = Args::parse();

    // Setup the options.
    let mut opts = SP1CoreOpts { shard_batch_size: 1, ..Default::default() };

    // Load the initial maximal shapes.
    let mut all_maximal_shapes: BTreeMap<usize, Vec<Shape<RiscvAirId>>> =
        if let Some(initial) = args.initial {
            let initial = if !initial.to_string_lossy().ends_with(".json") {
                initial.with_extension("json")
            } else {
                initial
            };

            serde_json::from_slice(
                &std::fs::read(&initial).expect("failed to read initial maximal shapes"),
            )
            .expect("failed to deserialize initial maximal shapes")
        } else {
            BTreeMap::new()
        };

    // Print the initial maximal shapes.
    for log_shard_size in args.shard_sizes.iter() {
        tracing::info!(
            "there are {} initial maximal shapes for log shard size {}",
            all_maximal_shapes.get(log_shard_size).map_or(0, |x| x.len()),
            log_shard_size
        );
    }

    // For each program, collect the maximal shapes.
    let (tx, rx) = mpsc::sync_channel(10);
    let program_list = args.list;
    for s3_path in program_list {
        // Download program and stdin files from S3.
        tracing::info!("download elf and input for {}", s3_path);

        // Download program.bin.
        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://sp1-testing-suite/{}/program.bin", s3_path),
                "program.bin",
            ])
            .status()
            .expect("Failed to execute aws s3 cp command for program.bin");
        if !status.success() {
            panic!("Failed to download program.bin from S3");
        }

        // Download stdin.bin.
        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://sp1-testing-suite/{}/stdin.bin", s3_path),
                "stdin.bin",
            ])
            .status()
            .expect("Failed to execute aws s3 cp command for stdin.bin");
        if !status.success() {
            panic!("Failed to download stdin.bin from S3");
        }

        // Read the program and stdin.
        let elf = std::fs::read("program.bin").expect("failed to read program");
        let stdin = std::fs::read("stdin.bin").expect("failed to read stdin");
        let stdin: SP1Stdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");

        // Collect the maximal shapes for each shard size.
        for &log_shard_size in args.shard_sizes.iter() {
            let tx = tx.clone();
            let elf = elf.clone();
            let stdin = stdin.clone();
            let new_context = SP1Context::default();
            let s3_path = s3_path.clone();
            rayon::spawn(move || {
                opts.shard_size = 1 << log_shard_size;
                let maximal_shapes = collect_maximal_shapes(&elf, &stdin, opts, new_context);
                tracing::info!(
                    "there are {} maximal shapes for {} for log shard size {}",
                    maximal_shapes.len(),
                    s3_path,
                    log_shard_size
                );
                tx.send((log_shard_size, s3_path, maximal_shapes)).unwrap();
            });
        }

        std::fs::remove_file("program.bin").expect("failed to remove program.bin");
        std::fs::remove_file("stdin.bin").expect("failed to remove stdin.bin");
    }
    drop(tx);

    // As the shapes are collected, update the maximal shapes.
    for (log_shard_size, s3_path, collected_maximal_shapes) in rx {
        let current_maximal_shapes = all_maximal_shapes.entry(log_shard_size).or_default();
        for shape in collected_maximal_shapes {
            insert(current_maximal_shapes, shape);
        }

        let new_len = all_maximal_shapes.get(&log_shard_size).map_or(0, |x| x.len());
        tracing::info!(
            "added shapes from {}, now there are {} maximal shapes for log shard size {}",
            s3_path,
            new_len,
            log_shard_size
        );
    }

    // Print the total number of maximal shapes.
    for log_shard_size in args.shard_sizes {
        tracing::info!(
            "there are {} maximal shapes in total for log shard size {}",
            all_maximal_shapes.get(&log_shard_size).map_or(0, |x| x.len()),
            log_shard_size
        );
    }

    // Write the maximal shapes to the output file.
    if let Some(output) = args.output {
        let output = if !output.to_string_lossy().ends_with(".json") {
            output.with_extension("json")
        } else {
            output
        };

        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).expect("failed to create output directory");
        }

        std::fs::write(
            &output,
            serde_json::to_string_pretty(&all_maximal_shapes)
                .expect("failed to serialize maximal shapes"),
        )
        .unwrap();
    }
}
