
<<<<<<< Updated upstream
=======
use crate::air::Word;
use crate::runtime::chip::Chip;
use crate::runtime::{Opcode, Runtime};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

pub struct CpuChip<F: PrimeField> {
    pub _phantom: core::marker::PhantomData<F>,
}

impl<F: PrimeField> Chip<F> for CpuChip<F> {
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
            IsRead::Expr(VirtualPairCol::single_main(
                CPU_COL_MAP.selectors.reg_a_read,
            )),
            VirtualPairCol::constant(F::one()),
        ));
        // lookup (clk, op_c, op_c_val, is_read=true) in the register table with multiplicity 1-imm_c
        // lookup (clk, op_b, op_b_val, is_read=true) in the register table with multiplicity 1-imm_b
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.op_c,
            CPU_COL_MAP.op_c_val,
            IsRead::Bool(true),
            VirtualPairCol::new_main(vec![(CPU_COL_MAP.selectors.imm_c, F::neg_one())], F::one()), // 1-imm_c
        ));
        interactions.push(Interaction::lookup_register(
            CPU_COL_MAP.clk,
            CPU_COL_MAP.op_b,
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

    fn receives(&self) -> Vec<Interaction<F>> {
        // The CPU table does not receive from anybody.
        vec![]
    }
}

impl<F: PrimeField> CpuChip<F> {
    fn event_to_row(&self, event: CpuEvent) -> [F; NUM_CPU_COLS] {
        let mut row = [F::zero(); NUM_CPU_COLS];
        let cols: &mut CpuCols<F> = unsafe { transmute(&mut row) };
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);
        cols.opcode = F::from_canonical_u32(event.instruction.opcode as u32);
        cols.op_a = F::from_canonical_u32(event.instruction.a as u32);
        cols.op_b = F::from_canonical_u32(event.instruction.b as u32);
        cols.op_c = F::from_canonical_u32(event.instruction.c as u32);

        self.populate_selectors(cols, event.instruction.opcode);

        cols.op_a_val = event.operands[0].into();
        cols.op_b_val = event.operands[1].into();
        cols.op_c_val = event.operands[2].into();
        row
    }

    fn populate_selectors(&self, cols: &mut CpuCols<F>, opcode: Opcode) {
        match opcode {
            Opcode::ADD | Opcode::SUB | Opcode::AND => {}
            Opcode::ADDI | Opcode::ANDI => {
                cols.selectors.imm_c = F::one();
            }
            Opcode::JAL => {
                cols.selectors.JAL = F::one();
                cols.selectors.imm_b = F::one();
                cols.selectors.jump_instruction = F::one();
            }
            Opcode::JALR => {
                cols.selectors.JALR = F::one();
                cols.selectors.jump_instruction = F::one();
            }
            Opcode::AUIPC => {
                cols.selectors.imm_b = F::one();
                cols.selectors.AUIPC = F::one();
            }
            _ => {}
        }
    }

    fn populate_address(&self, cols: &mut CpuCols<F>, event: CpuEvent) {
        todo!();
    }

    fn populate_branch(&self, cols: &mut CpuCols<F>, event: CpuEvent) {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::Instruction;
    use p3_baby_bear::BabyBear;

    use super::*;
    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program);
        let events = vec![CpuEvent {
            clk: 6,
            pc: 1,
            instruction: Instruction {
                opcode: Opcode::ADD,
                a: 0,
                b: 1,
                c: 2,
            },
            operands: [1, 2, 3],
        }];
        let chip = CpuChip::<BabyBear> {
            _phantom: Default::default(),
        };
        runtime.cpu_events = events;
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }
}
>>>>>>> Stashed changes
