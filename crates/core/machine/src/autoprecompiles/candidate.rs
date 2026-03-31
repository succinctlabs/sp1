use crate::autoprecompiles::{adapter::Sp1ApcAdapter, instruction::Sp1Instruction};
use powdr_autoprecompiles::{
    adapter::AdapterApcWithStats, blocks::BasicBlock, evaluation::EvaluationResult,
    pgo::ApcCandidate,
};

use serde::{Deserialize, Serialize};

/// A candidate for the SP1 autoprecompiles.
pub struct Sp1Candidate {
    apc_with_stats: AdapterApcWithStats<Sp1ApcAdapter>,
}

impl ApcCandidate<Sp1ApcAdapter> for Sp1Candidate {
    fn create(apc_with_stats: AdapterApcWithStats<Sp1ApcAdapter>) -> Self {
        Self { apc_with_stats }
    }

    fn inner(&self) -> &AdapterApcWithStats<Sp1ApcAdapter> {
        &self.apc_with_stats
    }

    fn into_inner(self) -> AdapterApcWithStats<Sp1ApcAdapter> {
        self.apc_with_stats
    }

    fn cost_before_opt(&self) -> usize {
        self.apc_with_stats.evaluation_result().before.main_columns
    }

    fn cost_after_opt(&self) -> usize {
        self.apc_with_stats.evaluation_result().after.main_columns
    }

    fn value_per_use(&self) -> usize {
        // TODO: Figure out a better cost model & take #constraints and #bus_interactions into
        // account too.
        self.cost_before_opt() - self.cost_after_opt()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Sp1ApcCandidateJsonExport {
    // start_pc
    start_pc: u64,
    // execution_frequency
    execution_frequency: usize,
    // original instructions
    original_block: BasicBlock<Sp1Instruction>,
    // before and after optimization stats
    stats: EvaluationResult,
    // path to the apc candidate file
    apc_candidate_file: String,
}
