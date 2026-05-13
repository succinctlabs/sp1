use std::path::PathBuf;

use clap::Parser;
use rsp_client_executor::{io::ClientExecutorInput, CHAIN_ID_ETH_MAINNET};
use sp1_sdk::prelude::*;

const ELF: Elf = include_elf!("rsp-program");

const DEFAULT_BLOCK_NUMBER: u64 = 21740164;

/// Dumps the ELF and bincode-serialized `SP1Stdin` for the `core_u64` RSP scenario
/// into files consumable by `sp1-perf-executor --local`.
#[derive(Parser, Debug)]
struct Args {
    /// Block number to load from `./input/<chain_id>/<block_number>.bin`.
    #[arg(long, default_value_t = DEFAULT_BLOCK_NUMBER)]
    block_number: u64,
    /// Chain ID for the cache lookup.
    #[arg(long, default_value_t = CHAIN_ID_ETH_MAINNET)]
    chain_id: u64,
    /// Output directory. Defaults to `<repo>/crates/perf/inputs/rsp-core-u64/`.
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

fn default_out_dir(chain_id: u64, block_number: u64) -> PathBuf {
    // CARGO_MANIFEST_DIR is `<repo>/examples/rsp/script` at compile time.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../../crates/perf/inputs/rsp-core-u64/{chain_id}/{block_number}"))
}

fn load_input_from_cache(chain_id: u64, block_number: u64) -> ClientExecutorInput {
    let cache_path = PathBuf::from(format!("./input/{}/{}.bin", chain_id, block_number));
    let mut cache_file = std::fs::File::open(&cache_path)
        .unwrap_or_else(|e| panic!("opening {}: {e}", cache_path.display()));
    bincode::deserialize_from(&mut cache_file).unwrap()
}

fn main() {
    let args = Args::parse();
    let out_dir =
        args.out_dir.unwrap_or_else(|| default_out_dir(args.chain_id, args.block_number));
    std::fs::create_dir_all(&out_dir).expect("create out_dir");

    let client_input = load_input_from_cache(args.chain_id, args.block_number);
    let mut stdin = SP1Stdin::default();
    stdin.write_vec(bincode::serialize(&client_input).unwrap());

    let program_path = out_dir.join("program.bin");
    let stdin_path = out_dir.join("stdin.bin");

    std::fs::write(&program_path, &*ELF).expect("write program.bin");
    std::fs::write(&stdin_path, bincode::serialize(&stdin).unwrap()).expect("write stdin.bin");

    println!("wrote {}", program_path.display());
    println!("wrote {}", stdin_path.display());
}
