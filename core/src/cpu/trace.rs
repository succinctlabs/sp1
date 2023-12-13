use super::air::{CpuCols, CPU_COL_MAP, NUM_CPU_COLS};
use super::CpuEvent;
use crate::lookup::{Interaction, IsRead};
use crate::utils::Chip;
use core::mem::transmute;
use p3_air::{BaseAir, VirtualPairCol};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::runtime::{Opcode, Runtime};

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

pub struct CpuChip;

impl CpuChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for CpuChip {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        let rows = runtime
            .cpu_events
            .par_iter()
            .map(|op| self.event_to_row(*op))
            .collect::<Vec<_>>();

        let trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        // TODO: pad to a power of 2.
        // Self::pad_to_power_of_two(&mut trace.values);

        trace
    }

    fn global_sends(&self) -> Vec<Interaction<F>> {
        let mut interactions = Vec::new();

        // lookup (clk, op_a, op_a_val, is_read=reg_a_read) in the register table with multiplicity 1.
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.instruction.op_a,
            CPU_COL_MAP.op_a_val,
            IsRead::Expr(VirtualPairCol::single_main(
                CPU_COL_MAP.selectors.reg_a_read,
            )),
            VirtualPairCol::constant(F::one()),
        ));
        // lookup (clk, op_c, op_c_val, is_read=true) in the register table with multiplicity 1-imm_c
        // lookup (clk, op_b, op_b_val, is_read=true) in the register table with multiplicity 1-imm_b
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.instruction.op_c,
            CPU_COL_MAP.op_c_val,
            IsRead::Bool(true),
            VirtualPairCol::new_main(vec![(CPU_COL_MAP.selectors.imm_c, F::neg_one())], F::one()), // 1-imm_c
        ));
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.instruction.op_b,
            CPU_COL_MAP.op_b_val,
            IsRead::Bool(true),
            VirtualPairCol::new_main(vec![(CPU_COL_MAP.selectors.imm_b, F::neg_one())], F::one()), // 1-imm_b
        ));
        interactions.push(Interaction::add(
            CPU_COL_MAP.op_a_val,
            CPU_COL_MAP.op_b_val,
            CPU_COL_MAP.op_c_val,
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.register_instruction),
        ));

        //// For both load and store instructions, we must constraint mem_val to be a lookup of [addr]
        //// For load instructions
        // To constraint addr, we add op_b_val + op_c_val
        // lookup (clk, op_b_val, op_c_val, addr) in the "add" table with multiplicity load_instruction
        interactions.push(Interaction::add(
            CPU_COL_MAP.addr,
            CPU_COL_MAP.op_b_val,
            CPU_COL_MAP.op_c_val,
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.load_instruction),
        ));
        // To constraint mem_val, we lookup [addr] in the memory table
        // lookup (clk, addr, mem_val, is_read=true) in the memory table with multiplicity load_instruction
        interactions.push(Interaction::lookup_memory(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.addr,
            CPU_COL_MAP.mem_val,
            IsRead::Bool(true),
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.load_instruction),
        ));
        // Now we must constraint mem_val and op_a_val
        // We bus this to a "match_word" table with a combination of s/u and h/b/w
        // TODO: lookup (clk, mem_val, op_a_val, byte, half, word, unsigned) in the "match_word" table with multiplicity load_instruction

        //// For store instructions
        // To constraint addr, we add op_a_val + op_c_val
        // lookup (clk, op_a_val, op_c_val, addr) in the "add" table with multiplicity store_instruction
        interactions.push(Interaction::add(
            CPU_COL_MAP.addr,
            CPU_COL_MAP.op_a_val,
            CPU_COL_MAP.op_c_val,
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.store_instruction),
        ));
        // To constraint mem_val, we lookup [addr] in the memory table
        // lookup (clk, addr, mem_val, is_read=false) in the memory table with multiplicity store_instruction
        interactions.push(Interaction::lookup_memory(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.addr,
            CPU_COL_MAP.mem_val,
            IsRead::Bool(false),
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.store_instruction),
        ));
        // Now we must constraint mem_val and op_b_val
        // TODO: lookup (clk, mem_val, op_b_val, byte, half, word, unsigned) in the "match_word" table with multiplicity store_instruction

        // Constraining the memory
        // TODO: there is likely some optimization to be done here making the is_read column a VirtualPair.
        // Constraint the memory in the case of a load instruction.
        interactions.push(Interaction::lookup_memory(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.addr,
            CPU_COL_MAP.mem_val,
            IsRead::Bool(true),
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.load_instruction),
        ));

        // Constraint the memory in the case of a store instruction.
        interactions.push(Interaction::lookup_memory(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.addr,
            CPU_COL_MAP.mem_val,
            IsRead::Bool(false),
            VirtualPairCol::single_main(CPU_COL_MAP.selectors.store_instruction),
        ));
        interactions
    }
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

impl CpuChip {
    fn event_to_row<F: PrimeField>(&self, event: CpuEvent) -> [F; NUM_CPU_COLS] {
        let mut row = [F::zero(); NUM_CPU_COLS];
        let cols: &mut CpuCols<F> = unsafe { transmute(&mut row) };
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);

        cols.instruction.populate(event.instruction);
        cols.selectors.populate(event.instruction);

        cols.op_a_val = event.a.into();
        cols.op_b_val = event.b.into();
        cols.op_c_val = event.c.into();

        self.populate_memory(cols, event);
        self.populate_branch(cols, event);
        row
    }

    fn populate_memory<F: PrimeField>(&self, cols: &mut CpuCols<F>, event: CpuEvent) {
        match event.instruction.opcode {
            Opcode::LB
            | Opcode::LH
            | Opcode::LW
            | Opcode::LBU
            | Opcode::LHU
            | Opcode::SB
            | Opcode::SH
            | Opcode::SW => {
                let memory_value = event.a;
                let memory_addr = event.b.wrapping_add(event.c);
                cols.mem_val = memory_value.into();
                cols.addr = memory_addr.into();
            }
            _ => {}
        }
    }

    fn populate_branch<F: PrimeField>(&self, cols: &mut CpuCols<F>, event: CpuEvent) {
        let branch_condition = match event.instruction.opcode {
            Opcode::BEQ => Some(event.a == event.b),
            Opcode::BNE => Some(event.a != event.b),
            Opcode::BLT => Some((event.a as i32) < (event.b as i32)),
            Opcode::BGE => Some((event.a as i32) >= (event.b as i32)),
            Opcode::BLTU => Some(event.a < event.b),
            Opcode::BGEU => Some(event.a >= event.b),
            _ => None,
        };
        if let Some(branch_condition) = branch_condition {
            cols.branch_cond_val = (branch_condition as u32).into();
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use crate::runtime::Instruction;

    use super::*;
    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program);
        runtime.cpu_events = vec![CpuEvent {
            clk: 6,
            pc: 1,
            instruction: Instruction {
                opcode: Opcode::ADD,
                op_a: 0,
                op_b: 1,
                op_c: 2,
            },
            a: 1,
            b: 2,
            c: 3,
        }];
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }
}
