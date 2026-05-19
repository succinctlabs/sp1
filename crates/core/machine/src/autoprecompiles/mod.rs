pub mod adapter;
pub mod air_to_symbolic_machine;
pub mod bus_interaction_handler;
pub mod bus_map;
pub mod candidate;
pub mod chip;
pub mod instruction;
pub mod instruction_handler;
pub mod interaction_builder;
pub mod memory_bus_interaction;
pub mod program;

use powdr_autoprecompiles::{
    adapter::{detect_blocks, select_apcs, AdapterApcWithStats, PgoAdapter},
    blocks::collect_basic_blocks,
    empirical_constraints::EmpiricalConstraints,
    execution_profile::ExecutionProfile,
    pgo::{CellPgo, InstructionPgo, NonePgo},
    DegreeBound, PgoConfig, PowdrConfig,
};
use serde::{Deserialize, Serialize};
use sp1_build::BuildArgs;
use sp1_core_executor::{execute_for_frequency_map, Program};
use sp1_primitives::SP1Field;
use std::{collections::BTreeMap, sync::Arc};

use crate::{
    autoprecompiles::{
        adapter::Sp1ApcAdapter,
        bus_interaction_handler::Sp1BusInteractionHandler,
        bus_map::{sp1_bus_map, Sp1SpecificBuses},
        candidate::Sp1Candidate,
        instruction::Sp1Instruction,
        instruction_handler::Sp1InstructionHandler,
        program::Sp1Program,
    },
    io::SP1Stdin,
};

const SP1_DEGREE_BOUND: usize = 3;
const DEFAULT_DEGREE_BOUND: DegreeBound =
    DegreeBound { identities: SP1_DEGREE_BOUND, bus_interactions: 1 };

pub type VmConfig<'a> = powdr_autoprecompiles::VmConfig<
    'a,
    Sp1InstructionHandler<SP1Field>,
    Sp1BusInteractionHandler,
    Sp1SpecificBuses,
>;
pub type Sp1Apc<F> = powdr_autoprecompiles::Apc<F, Sp1Instruction, u8, u64>;

pub fn sp1_powdr_config(apc: u64, skip: u64) -> PowdrConfig {
    let mut config = PowdrConfig::new(apc, skip, DEFAULT_DEGREE_BOUND);
    config.apc_max_instructions = 1000;
    config
}

pub fn sp1_vm_config<'a>(handler: &'a Sp1InstructionHandler<SP1Field>) -> VmConfig<'a> {
    // Need to pass in a handler due to VmConfig lifetime OR return a static lifetime VmConfig
    VmConfig {
        instruction_handler: handler,
        bus_interaction_handler: Sp1BusInteractionHandler::default(),
        bus_map: sp1_bus_map(),
    }
}

pub fn build_elf(guest_path: &str) -> Vec<u8> {
    let build_args = powdr_default_build_args();
    let elf_path = build_elf_path(guest_path, build_args);
    std::fs::read(elf_path).unwrap()
}

pub fn build_elf_path(guest_path: &str, build_args: BuildArgs) -> String {
    let guest_path = std::path::Path::new(guest_path).to_path_buf();
    // Currently we only take the first elf path built from the given `guest_path`, assuming that
    // there's only one binary in `guest_path` TODO: add a filter input argument and assert only
    // one elf is left after filtering
    let elf_path =
        sp1_build::execute_build_program(&build_args, Some(guest_path)).unwrap()[0].1.clone();
    elf_path.to_string()
}

pub fn compile_guest(
    guest_path: &str,
    config: PowdrConfig,
    pgo_config: PgoConfig,
) -> CompiledProgram {
    let elf = build_elf(guest_path);
    CompiledProgram::new(&elf, config, pgo_config)
}

pub fn execution_profile_from_guest(guest_path: &str, stdin: SP1Stdin) -> ExecutionProfile {
    let elf = build_elf(guest_path);

    let program = Arc::new(Program::from(&elf).unwrap());

    execution_profile_from_program(program, stdin)
}

pub fn execution_profile_from_program(program: Arc<Program>, stdin: SP1Stdin) -> ExecutionProfile {
    execute_for_frequency_map(&program, stdin.buffer.iter().map(|v| v.as_slice())).unwrap()
}

pub fn powdr_default_build_args() -> BuildArgs {
    BuildArgs::default()
}

#[derive(Serialize, Deserialize)]
pub struct CompiledProgram {
    pub apcs_and_stats: Vec<AdapterApcWithStats<Sp1ApcAdapter>>,
}

impl CompiledProgram {
    pub fn new(elf: &[u8], config: PowdrConfig, pgo_config: PgoConfig) -> Self {
        let program = Sp1Program::from(Arc::new(Program::from(elf).unwrap()));
        let jumpdests = powdr_riscv_elf::rv64::compute_jumpdests_from_buffer(elf).jumpdests;

        let airs = Sp1InstructionHandler::<SP1Field>::new();
        let vm_config = sp1_vm_config(&airs);

        // Currently we don't support the max_total_apc_columns option for cell PGO
        assert!(!matches!(pgo_config, PgoConfig::Cell(_, Some(_))));

        // Collect basic blocks
        let blocks = collect_basic_blocks::<Sp1ApcAdapter>(&program, &jumpdests);
        tracing::info!("Got {} basic blocks from `collect_basic_blocks`", blocks.len());

        // Create pgo adapter based on the config
        let pgo_adapter: Box<dyn PgoAdapter<Adapter = Sp1ApcAdapter>> = match pgo_config {
            PgoConfig::Cell(pgo_data, max_total_apc_columns) => {
                Box::new(CellPgo::<_, Sp1Candidate>::with_pgo_data_and_max_columns(
                    pgo_data,
                    max_total_apc_columns,
                ))
            }
            PgoConfig::Instruction(pgo_data) => Box::new(InstructionPgo::with_pgo_data(pgo_data)),
            PgoConfig::None => Box::new(NonePgo::default()),
        };

        // Build + rank, then trim. Mirrors the old fused
        // `filter_blocks_and_create_apcs_with_pgo` behavior: cap the build at
        // `autoprecompiles + skip` (so instruction/none don't build candidates
        // they'll never select), then take `autoprecompiles` past `skip`.
        let mut config = config;
        if config.apc_candidates.is_none() {
            config.apc_candidates = Some(config.autoprecompiles + config.skip_autoprecompiles);
        }
        let exec_blocks = detect_blocks(pgo_adapter.as_ref(), blocks, &config);
        let ranked = pgo_adapter.generate_apcs(
            exec_blocks,
            &config,
            vm_config,
            BTreeMap::new(),
            EmpiricalConstraints::default(),
        );
        let apcs_and_stats = select_apcs::<Sp1ApcAdapter>(
            ranked,
            config.autoprecompiles as usize,
            config.skip_autoprecompiles as usize,
        );

        Self { apcs_and_stats }
    }
}
