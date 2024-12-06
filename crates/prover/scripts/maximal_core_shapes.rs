use std::{collections::BTreeMap, path::PathBuf, sync::mpsc};

use clap::Parser;
use p3_baby_bear::BabyBear;
use sp1_core_executor::{CoreShape, Executor, Maximal, MaximalShapes, Program, SP1Context};
use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir, utils::setup_logger};
use sp1_stark::SP1CoreOpts;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_delimiter = ',')]
    list: Vec<PathBuf>,
    #[clap(short, long, value_delimiter = ',')]
    shard_sizes: Vec<usize>,
    #[clap(short, long, default_value = "crates/core/machine/maximal_shapes.json")]
    initial: Option<PathBuf>,
    #[clap(short, long, default_value = "crates/core/machine/maximal_shapes.json")]
    output: Option<PathBuf>,
    #[clap(short, long, default_value = "false")]
    reset: bool,
}

pub fn get_maximal_core_shapes(
    elf: &[u8],
    stdin: &SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context,
) -> Maximal<CoreShape> {
    let program = Program::from(elf).unwrap();
    let mut runtime = Executor::with_context(program, opts, context);
    runtime.write_vecs(&stdin.buffer);
    for (proof, vkey) in stdin.proofs.iter() {
        runtime.write_proof(proof.clone(), vkey.clone());
    }

    let mut maximal_core_shapes = Maximal::new();

    let mut finished = false;
    while !finished {
        let (records, f) = runtime.execute_record(true).unwrap();
        finished = f;
        for mut record in records {
            if record.contains_cpu() {
                let _ = record.defer();
                let core_shape: CoreShape = RiscvAir::<BabyBear>::core_heights(&record)
                    .into_iter()
                    .filter_map(|(air, height)| {
                        (height != 0).then(|| (air, height.next_power_of_two().ilog2() as usize))
                    })
                    .collect();

                maximal_core_shapes.insert(core_shape);
            }
        }
    }

    maximal_core_shapes
}

fn main() {
    setup_logger();
    let args = Args::parse();

    let mut opts = SP1CoreOpts::default();

    let mut all_maximal_shapes: MaximalShapes = if let Some(initial) = args.initial {
        // Verify or append .json extension
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
        MaximalShapes { shard_map: BTreeMap::new() }
    };

    if args.reset {
        for log_shard_size in args.shard_sizes.iter() {
            if let Some(m) = all_maximal_shapes.shard_map.get_mut(&log_shard_size) {
                m.clear();
            }
        }
    }

    for log_shard_size in args.shard_sizes.iter() {
        tracing::info!(
            "there are {} initial maximal shapes for log shard size {}",
            all_maximal_shapes.shard_map.get(log_shard_size).map_or(0, |x| x.len()),
            log_shard_size
        );
    }

    let (tx, rx) = mpsc::channel();
    let program_list = args.list;
    for s3_path in program_list {
        // Download program and stdin files from S3
        let s3_path = s3_path.to_string_lossy().into_owned();

        tracing::info!("download elf and input for {}", s3_path);

        // Download program.bin
        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://sp1-testing-suite/{}/program.bin", s3_path),
                "/tmp/program.bin",
            ])
            .status()
            .expect("Failed to execute aws s3 cp command for program.bin");

        if !status.success() {
            panic!("Failed to download program.bin from S3");
        }

        // Download stdin.bin
        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://sp1-testing-suite/{}/stdin.bin", s3_path),
                "/tmp/stdin.bin",
            ])
            .status()
            .expect("Failed to execute aws s3 cp command for stdin.bin");

        if !status.success() {
            panic!("Failed to download stdin.bin from S3");
        }

        let elf = std::fs::read("/tmp/program.bin").expect("failed to read program");
        let stdin = std::fs::read("/tmp/stdin.bin").expect("failed to read stdin");
        let stdin: SP1Stdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");

        for &log_shard_size in args.shard_sizes.iter() {
            let tx = tx.clone();
            let elf = elf.clone();
            let stdin = stdin.clone();
            let new_context = SP1Context::default();
            let s3_path = s3_path.clone();
            rayon::spawn(move || {
                opts.set_shard_size(1 << log_shard_size);
                let maximal_shapes = get_maximal_core_shapes(&elf, &stdin, opts, new_context);
                tracing::info!(
                    "there are {} maximal shapes for {} for log shard size {}",
                    maximal_shapes.len(),
                    s3_path,
                    log_shard_size
                );
                tx.send((log_shard_size, s3_path, maximal_shapes)).unwrap();
            });
        }

        std::fs::remove_file("/tmp/program.bin").expect("failed to remove program.bin");
        std::fs::remove_file("/tmp/stdin.bin").expect("failed to remove stdin.bin");
    }

    drop(tx);

    for (log_shard_size, s3_path, maximal_shapes) in rx {
        if let Some(current_maximal_shapes) = all_maximal_shapes.shard_map.get_mut(&log_shard_size)
        {
            current_maximal_shapes.extend(maximal_shapes);
        } else {
            all_maximal_shapes.shard_map.insert(log_shard_size, maximal_shapes);
        }
        let new_len = all_maximal_shapes.shard_map.get(&log_shard_size).map_or(0, |x| x.len());
        tracing::info!(
            "added shapes from {}, now there are {} maximal shapes for log shard size {}",
            s3_path,
            new_len,
            log_shard_size
        );
    }

    for log_shard_size in args.shard_sizes {
        tracing::info!(
            "there are {} maximal shapes in total for log shard size {}",
            all_maximal_shapes.shard_map.get(&log_shard_size).map_or(0, |x| x.len()),
            log_shard_size
        );
    }

    if let Some(output) = args.output {
        // Verify or append .json extension
        let output = if !output.to_string_lossy().ends_with(".json") {
            output.with_extension("json")
        } else {
            output
        };
        // Create parent directories if they don't exist
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
