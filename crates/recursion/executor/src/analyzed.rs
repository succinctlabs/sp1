use serde::{Deserialize, Serialize};

use crate::{
    instruction::Instruction, program::RawProgram, BasicBlock, RecursionAirEventCount, SeqBlock,
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

    pub fn inner_mut(&mut self) -> &mut Instruction<F> {
        &mut self.inner
    }

    /// Shifts the event offset. Used by the compiler to relocate `Mem` events after the
    /// number of interned constants (which occupy the first offsets) becomes known.
    pub fn shift_offset(&mut self, by: usize) {
        self.offset += by;
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
            match block {
                SeqBlock::Basic(instrs) => {
                    let analyzed = instrs
                        .instrs
                        .into_iter()
                        .map(|instr| {
                            let start_offset = counts.claim_offset(&instr);
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
