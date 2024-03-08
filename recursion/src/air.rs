use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;

use crate::ExecutionRecord;
use sp1_core::air::MachineAir;
use sp1_core::air::SP1AirBuilder;
use sp1_core::operations::IsZeroOperation;

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Word<T>(pub [T; 4]);

#[derive(Default)]
pub struct CpuChip<F> {
    _phantom: std::marker::PhantomData<F>,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct MemoryReadCols<T> {
    pub value: Word<T>,
    pub prev_timestamp: T,
    pub curr_timestamp: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct MemoryWriteCols<T> {
    pub prev_value: Word<T>,
    pub curr_value: Word<T>,
    pub prev_timestamp: T,
    pub curr_timestamp: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct InstructionCols<T> {
    pub opcode: T,
    pub op_a: T,
    pub op_b: T,
    pub op_c: T,
    pub imm_b: T,
    pub imm_c: T,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T> {
    pub clk: T,
    pub pc: T,
    pub fp: T,

    pub a: MemoryWriteCols<T>,
    pub b: MemoryReadCols<T>,
    pub c: MemoryReadCols<T>,

    pub instruction: InstructionCols<T>,

    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub is_div: T,
    pub is_lw: T,
    pub is_sw: T,
    pub is_beq: T,
    pub is_bne: T,
    pub is_jal: T,
    pub is_jalr: T,

    // c = a + b;
    pub add_scratch: T,

    // c = a - b;
    pub sub_scratch: T,

    // c = a * b;
    pub mul_scratch: T,

    // c = a / b;
    pub div_scratch: T,

    // ext(c) = ext(a) + ext(b);
    pub add_ext_scratch: [T; 4],

    // ext(c) = ext(a) - ext(b);
    pub sub_ext_scratch: [T; 4],

    // ext(c) = ext(a) * ext(b);
    pub mul_ext_scratch: [T; 4],

    // ext(c) = ext(a) / ext(b);
    pub div_ext_scratch: [T; 4],

    // c = a == b;
    pub a_eq_b: IsZeroOperation<T>,
}

impl<F: PrimeField> MachineAir<F> for CpuChip<F> {
    type Record = ExecutionRecord<F>;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let rows = input
            .cpu_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_CPU_COLS];
                let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                cols.clk = event.clk;
                cols.pc = event.pc;
                cols.fp = event.fp;
                cols.instruction.opcode = F::from_canonical_u32(event.instruction.opcode as u32);
                cols.instruction.op_a = event.instruction.op_a;
                cols.instruction.op_b = event.instruction.op_b;
                cols.instruction.op_c = event.instruction.op_c;
                cols.instruction.imm_b = F::from_canonical_u32(event.instruction.imm_b as u32);
                cols.instruction.imm_c = F::from_canonical_u32(event.instruction.imm_c as u32);
                row
            })
            .collect::<Vec<_>>();

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_CPU_COLS, F>(&mut trace.values);

        trace
    }
}

impl<F: Send + Sync> BaseAir<F> for CpuChip<F> {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

impl<AB> Air<AB> for CpuChip<AB::F>
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let _: &CpuCols<AB::Var> = main.row_slice(0).borrow();
        let _: &CpuCols<AB::Var> = main.row_slice(1).borrow();
    }
}

#[cfg(test)]
mod tests {
    use crate::air::CpuChip;
    use crate::ExecutionRecord;
    use crate::Instruction;
    use crate::Opcode;
    use crate::Program;
    use crate::Runtime;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core::air::MachineAir;
    use sp1_core::utils::uni_stark_prove;
    use sp1_core::utils::{BabyBearPoseidon2, StarkUtils};

    #[test]
    fn prove_babybear() {
        let program = Program::<BabyBear> {
            instructions: vec![
                // .main
                Instruction::new(Opcode::SW, 0, 1, 0, true, true),
                Instruction::new(Opcode::SW, 1, 1, 0, true, true),
                Instruction::new(Opcode::SW, 2, 10, 0, true, true),
                // .body:
                Instruction::new(Opcode::ADD, 3, 0, 1, false, false),
                Instruction::new(Opcode::SW, 0, 1, 0, false, true),
                Instruction::new(Opcode::SW, 1, 3, 0, false, true),
                Instruction::new(Opcode::SUB, 2, 2, 1, false, true),
                Instruction::new(Opcode::BNE, 2, 0, 3, true, true),
            ],
        };
        let mut runtime = Runtime::<BabyBear> {
            clk: BabyBear::zero(),
            program,
            fp: BabyBear::zero(),
            pc: BabyBear::zero(),
            memory: vec![BabyBear::zero(); 1024 * 1024],
            record: ExecutionRecord::<BabyBear>::default(),
        };
        runtime.run();

        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let chip = CpuChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&runtime.record, &mut ExecutionRecord::default());
        uni_stark_prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);
    }
}
