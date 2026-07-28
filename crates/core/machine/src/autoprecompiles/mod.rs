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
    pgo::{CellPgo, InstructionPgo, NonePgo, PgoType},
    DegreeBound, GenerateConfig, PgoData, SelectConfig,
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

/// Build the `(generate, select)` config pair for an sp1 compilation.
///
/// The `apc_candidates` cap is resolved here via
/// [`GenerateConfig::with_select_defaults`] (it depends on `pgo`), so the
/// returned configs are complete — callers hand them straight to
/// [`CompiledProgram::new`] with no further defaulting step to remember.
pub fn sp1_configs(
    autoprecompiles: u64,
    skip: u64,
    pgo: PgoType,
) -> (GenerateConfig, SelectConfig) {
    let select = SelectConfig::new(autoprecompiles, skip);
    let generate = GenerateConfig::new(DEFAULT_DEGREE_BOUND)
        .with_apc_max_instructions(1000)
        .with_select_defaults(pgo, select);
    (generate, select)
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
    generate: GenerateConfig,
    select: SelectConfig,
    pgo_data: PgoData,
) -> CompiledProgram {
    let elf = build_elf(guest_path);
    CompiledProgram::new(&elf, generate, select, pgo_data)
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
    /// Build + rank candidates from the elf, then trim to `select`. `generate`
    /// must already have its `apc_candidates` cap resolved — build the pair via
    /// [`sp1_configs`], which applies [`GenerateConfig::with_select_defaults`].
    /// The caller supplies the [`PgoData`] directly (an already-computed
    /// [`ExecutionProfile`], or [`PgoData::None`]).
    pub fn new(
        elf: &[u8],
        generate: GenerateConfig,
        select: SelectConfig,
        pgo_data: PgoData,
    ) -> Self {
        let program = Sp1Program::from(Arc::new(Program::from(elf).unwrap()));
        let jumpdests = powdr_riscv_elf::rv64::compute_jumpdests_from_buffer(elf).jumpdests;

        let airs = Sp1InstructionHandler::<SP1Field>::new();
        let vm_config = sp1_vm_config(&airs);

        // Currently we don't support the max_total_apc_columns option for cell PGO
        assert!(!matches!(pgo_data, PgoData::Cell(_, Some(_))));

        let blocks = collect_basic_blocks::<Sp1ApcAdapter>(&program, &jumpdests);
        tracing::info!("Got {} basic blocks from `collect_basic_blocks`", blocks.len());

        let pgo_adapter: Box<dyn PgoAdapter<Adapter = Sp1ApcAdapter>> = match pgo_data {
            PgoData::Cell(profile, max_total_apc_columns) => {
                Box::new(CellPgo::<_, Sp1Candidate>::with_pgo_data_and_max_columns(
                    profile,
                    max_total_apc_columns,
                ))
            }
            PgoData::Instruction(profile) => Box::new(InstructionPgo::with_pgo_data(profile)),
            PgoData::None => Box::new(NonePgo::default()),
        };

        // Build + rank, then trim to `select`.
        let exec_blocks = detect_blocks(pgo_adapter.as_ref(), blocks, &generate);
        let ranked = pgo_adapter.create_apcs_with_pgo(
            exec_blocks,
            &generate,
            vm_config,
            BTreeMap::new(),
            EmpiricalConstraints::default(),
        );
        let apcs_and_stats = select_apcs::<Sp1ApcAdapter>(ranked, select);

        Self { apcs_and_stats }
    }
}
