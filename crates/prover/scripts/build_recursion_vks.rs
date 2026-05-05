use std::{fs::File, path::PathBuf};

use clap::Parser;
use either::Either;
use sp1_core_machine::{riscv::RiscvAir, utils::setup_logger};
use sp1_prover::worker::{cpu_worker_builder_with_machine, SP1LocalNodeBuilder};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
    #[clap(short, long)]
    start: Option<usize>,
    #[clap(short, long)]
    end: Option<usize>,
    #[clap(short, long, default_value_t = 4)]
    chunk_size: usize,
}
#[tokio::main]
async fn main() {
    setup_logger();
    let args = Args::parse();

    let build_dir = args.build_dir;
    let start = args.start;
    let end = args.end;
    let chunk_size = args.chunk_size;

    let maybe_range = start.and_then(|s| end.map(|e| (s..e).collect::<Vec<usize>>()));
    let maybe_either = maybe_range.map(Either::Left);
    let machine = RiscvAir::machine();
    let node =
        SP1LocalNodeBuilder::from_worker_client_builder(cpu_worker_builder_with_machine(machine))
            .build()
            .await
            .unwrap();
    let result = node.build_vks(maybe_either, chunk_size).await.unwrap();

    // Create the file to store the vk map.
    let mut file = File::create(build_dir.join("vk_map.bin")).unwrap();

    bincode::serialize_into(&mut file, &result.vk_map).unwrap();
}
