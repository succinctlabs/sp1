use super::air::{CpuCols, CPU_COL_MAP, NUM_CPU_COLS};
use super::CpuEvent;
use crate::lookup::{Interaction, IsRead};
use crate::utils::Chip;
use core::mem::transmute;
use p3_air::VirtualPairCol;

use crate::air::Word;
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
        let mut rows = runtime
            .cpu_events
            .iter() // TODO make this a par_iter
            .enumerate()
            .map(|(n, op)| self.event_to_row(*op))
            .collect::<Vec<_>>();

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        // TODO: pad to a power of 2.
        // Self::pad_to_power_of_two(&mut trace.values);

        trace
    }

    fn sends(&self) -> Vec<Interaction<F>> {
        let mut interactions = Vec::new();

        // lookup (clk, op_a, op_a_val, is_read=reg_a_read) in the register table with multiplicity 1.
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.op_a,
            CPU_COL_MAP.op_a_val,
            IsRead::Expr(VirtualPairCol::single_main(CPU_COL_MAP.reg_a_read)),
            VirtualPairCol::constant(F::one()),
        ));
        // lookup (clk, op_c, op_c_val, is_read=true) in the register table with multiplicity 1-imm_c
        // lookup (clk, op_b, op_b_val, is_read=true) in the register table with multiplicity 1-imm_b
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.op_c,
            CPU_COL_MAP.op_c_val,
            IsRead::Bool(true),
            VirtualPairCol::new_main(vec![(CPU_COL_MAP.imm_c, F::neg_one())], F::one()), // 1-imm_c
        ));
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.op_b,
            CPU_COL_MAP.op_b_val,
            IsRead::Bool(true),
            VirtualPairCol::new_main(vec![(CPU_COL_MAP.imm_b, F::neg_one())], F::one()), // 1-imm_b
        ));
        interactions.push(Interaction::add(
            CPU_COL_MAP.op_a_val,
            CPU_COL_MAP.op_b_val,
            CPU_COL_MAP.op_c_val,
            VirtualPairCol::single_main(CPU_COL_MAP.register_instruction),
        ));

        //// For both load and store instructions, we must constraint mem_val to be a lookup of [addr]
        //// For load instructions
        // To constraint addr, we add op_b_val + op_c_val
        // lookup (clk, op_b_val, op_c_val, addr) in the "add" table with multiplicity load_instruction
        interactions.push(Interaction::add(
            CPU_COL_MAP.addr,
            CPU_COL_MAP.op_b_val,
            CPU_COL_MAP.op_c_val,
            VirtualPairCol::single_main(CPU_COL_MAP.load_instruction),
        ));
        // To constraint mem_val, we lookup [addr] in the memory table
        // lookup (clk, addr, mem_val, is_read=true) in the memory table with multiplicity load_instruction
        interactions.push(Interaction::lookup_memory(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.addr,
            CPU_COL_MAP.mem_val,
            IsRead::Bool(true),
            VirtualPairCol::single_main(CPU_COL_MAP.load_instruction),
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
            VirtualPairCol::single_main(CPU_COL_MAP.store_instruction),
        ));
        // To constraint mem_val, we lookup [addr] in the memory table
        // lookup (clk, addr, mem_val, is_read=false) in the memory table with multiplicity store_instruction
        interactions.push(Interaction::lookup_memory(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.addr,
            CPU_COL_MAP.mem_val,
            IsRead::Bool(false),
            VirtualPairCol::single_main(CPU_COL_MAP.store_instruction),
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
            VirtualPairCol::single_main(CPU_COL_MAP.load_instruction),
        ));

        // Constraint the memory in the case of a store instruction.
        interactions.push(Interaction::lookup_memory(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.addr,
            CPU_COL_MAP.mem_val,
            IsRead::Bool(false),
            VirtualPairCol::single_main(CPU_COL_MAP.store_instruction),
        ));
        interactions
    }

    fn receives(&self) -> Vec<Interaction<F>> {
        // The CPU table does not receive from anybody.
        vec![]
    }
}

impl CpuChip {
    fn event_to_row<F: PrimeField>(&self, event: CpuEvent) -> [F; NUM_CPU_COLS] {
        let mut row = [F::zero(); NUM_CPU_COLS];
        let cols: &mut CpuCols<F> = unsafe { transmute(&mut row) };
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);
        println!("rows: {:?}", row);
        cols.opcode = F::from_canonical_u32(event.opcode as u32);
        cols.op_a = F::from_canonical_u32(event.a);
        cols.op_b = F::from_canonical_u32(event.b);
        cols.op_c = F::from_canonical_u32(event.c);
        // TODO: based on the instruction, populate the relevant flags.
        match event.opcode {
            Opcode::ADD | Opcode::SUB | Opcode::AND => {}
            Opcode::ADDI | Opcode::ANDI => {
                cols.imm_c = F::one();
            }
            Opcode::JAL => {
                cols.JAL = F::one();
                cols.imm_b = F::one();
                cols.jump_instruction = F::one();
            }
            Opcode::JALR => {
                cols.JALR = F::one();
                cols.jump_instruction = F::one();
            }
            Opcode::AUIPC => {
                cols.imm_b = F::one();
                cols.AUIPC = F::one();
            }
            _ => {}
        }
        // TODO: make Into for Iter<F> to Word and use that here.
        cols.op_a_val = Word(
            event
                .a
                .to_le_bytes()
                .iter()
                .map(|v| F::from_canonical_u8(*v))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        cols.op_b_val = Word(
            event
                .b
                .to_le_bytes()
                .iter()
                .map(|v| F::from_canonical_u8(*v))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        cols.op_c_val = Word(
            event
                .c
                .to_le_bytes()
                .iter()
                .map(|v| F::from_canonical_u8(*v))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        row
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;
    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program);
        runtime.cpu_events = vec![CpuEvent {
            clk: 6,
            pc: 1,
            opcode: Opcode::ADD,
            op_a: 0,
            op_b: 1,
            op_c: 2,
            a: 1,
            b: 2,
            c: 3,
        }];
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }
}
