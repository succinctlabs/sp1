use serde::{Deserialize, Serialize};

use crate::{
    instruction::{HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction},
    program::RawProgram,
    BasicBlock, RecursionAirEventCount, SeqBlock,
};

/// An instruction that has been analyzed to find where it should insert its events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedInstruction<F> {
    pub(crate) inner: Instruction<F>,
    pub(crate) offset: usize,
}

impl<F> AnalyzedInstruction<F> {
    pub const fn new(inner: Instruction<F>, offset: usize) -> Self {
        Self { inner, offset }
    }

    pub const fn inner(&self) -> &Instruction<F> {
        &self.inner
    }
}

impl<F> RawProgram<Instruction<F>> {
    /// Analyze the program to link an instruction to its corresponding event count.
    ///
    /// This allows the executor to preallocate the correct number of events and avoid copies
    /// across blocks.
    ///
    /// This method is not unsafe, but the correctness of this method is a safety condition of
    /// [`crate::Runtime::execute_raw`].
    pub fn analyze(self) -> (RawProgram<AnalyzedInstruction<F>>, RecursionAirEventCount) {
        fn analyze_block<T>(
            block: SeqBlock<Instruction<T>>,
            counts: &mut RecursionAirEventCount,
        ) -> SeqBlock<AnalyzedInstruction<T>> {
            /// Increment a counter and return the previous value.
            fn incr(num: &mut usize, amt: usize) -> usize {
                let start = *num;
                *num += amt;

                start
            }

            match block {
                SeqBlock::Basic(instrs) => {
                    let analyzed = instrs
                        .instrs
                        .into_iter()
                        .map(|instr| {
                            let start_offset = match &instr {
                                Instruction::BaseAlu(_) => incr(&mut counts.base_alu_events, 1),
                                Instruction::ExtAlu(_) => incr(&mut counts.ext_alu_events, 1),
                                Instruction::Mem(_) => incr(&mut counts.mem_const_events, 1),
                                Instruction::ExtFelt(_) => {
                                    incr(&mut counts.ext_felt_conversion_events, 1)
                                }
                                Instruction::Poseidon2(_) => {
                                    incr(&mut counts.poseidon2_wide_events, 1)
                                }
                                Instruction::Poseidon2LinearLayer(_) => {
                                    incr(&mut counts.poseidon2_linear_layer_events, 1)
                                }
                                Instruction::Poseidon2SBox(_) => {
                                    incr(&mut counts.poseidon2_sbox_events, 1)
                                }
                                Instruction::Select(_) => incr(&mut counts.select_events, 1),
                                Instruction::Hint(HintInstr { output_addrs_mults })
                                | Instruction::HintBits(HintBitsInstr {
                                    output_addrs_mults,
                                    input_addr: _, // No receive interaction for the hint operation
                                }) => incr(&mut counts.mem_var_events, output_addrs_mults.len()),
                                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                                    output_addrs_mults,
                                    input_addr: _, // No receive interaction for the hint operation
                                }) => incr(&mut counts.mem_var_events, output_addrs_mults.len()),
                                Instruction::HintAddCurve(instr) => incr(
                                    &mut counts.mem_var_events,
                                    instr.output_x_addrs_mults.len()
                                        + instr.output_y_addrs_mults.len(),
                                ),
                                Instruction::CommitPublicValues(_) => {
                                    incr(&mut counts.commit_pv_hash_events, 1)
                                }
                                // Just return 0 as a place holder, the executor code will not
                                // create any events on these types anyway.
                                Instruction::Print(_) | Instruction::DebugBacktrace(_) => 0,
                            };

                            AnalyzedInstruction::new(instr, start_offset)
                        })
                        .collect();

                    SeqBlock::Basic(BasicBlock { instrs: analyzed })
                }
                SeqBlock::Parallel(par_blocks) => {
                    let analyzed = par_blocks
                        .into_iter()
                        .map(|basic_blocks| {
                            let analyzed: Vec<_> = basic_blocks
                                .seq_blocks
                                .into_iter()
                                .map(|block| analyze_block(block, counts))
                                .collect();

                            RawProgram { seq_blocks: analyzed }
                        })
                        .collect();

                    SeqBlock::Parallel(analyzed)
                }
            }
        }

        let mut counts = RecursionAirEventCount::default();
        let analyzed_blocks =
            self.seq_blocks.into_iter().map(|block| analyze_block(block, &mut counts)).collect();

        (RawProgram { seq_blocks: analyzed_blocks }, counts)
    }
}
