use super::air::{CpuCols, CPU_COL_MAP, NUM_CPU_COLS};
use super::CpuEvent;
use crate::runtime::{Opcode, Runtime};
use crate::utils::Chip;

use core::mem::transmute;

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

pub struct CpuChip;

impl CpuChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for CpuChip {
    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        let rows = runtime
            .cpu_events
            .iter() // TODO: change this back to par_iter
            .map(|op| self.event_to_row(*op))
            .collect::<Vec<_>>();

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        Self::pad_to_power_of_two::<F>(&mut trace.values);

        trace
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
            Opcode::LB | Opcode::LH | Opcode::LW | Opcode::LBU | Opcode::LHU => {
                let memory_addr = event.b.wrapping_add(event.c);
                cols.mem_val = event
                    .memory_value
                    .expect("Memory value should be present")
                    .into();
                let memory_offset = memory_addr % 4;
                let memory_aligned = memory_addr - memory_offset;
                cols.addr = memory_aligned.into();
                cols.addr_offset = memory_offset.into();
                // TODO: we have to populate cols.mem_scratch with cols.mem_val >> cols.addr_offset
                // TODO: populate cols.mem_bit_decomp depending on which byte of the memory we want to grab the top bit of
            }
            Opcode::SB | Opcode::SH | Opcode::SW => {
                let memory_addr = event.b.wrapping_add(event.c);
                cols.mem_val = event
                    .memory_value
                    .expect("Memory value should be present")
                    .into();
                let memory_offset = memory_addr % 4;
                let memory_aligned = memory_addr - memory_offset;
                cols.addr = memory_aligned.into();
                cols.addr_offset = memory_offset.into();
                // But we also have to populate mem_scratch because in this case it's the memory result that we'll connect.
                cols.mem_scratch = event
                    .memory_store_value
                    .expect("Memory store value should be present")
                    .into();
                // TODO: populate cols.mem_mask based on is_word, is_half, is_byte, addr_offset
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

    fn pad_to_power_of_two<F: PrimeField>(values: &mut Vec<F>) {
        let len: usize = values.len();
        let n_real_rows = values.len() / NUM_CPU_COLS;

        let last_row = &values[len - NUM_CPU_COLS..];
        let pc = last_row[CPU_COL_MAP.pc];
        let clk = last_row[CPU_COL_MAP.clk];

        values.resize(n_real_rows.next_power_of_two() * NUM_CPU_COLS, F::zero());

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };

        rows[n_real_rows..]
            .iter_mut() // TODO: can be replaced with par_iter_mut
            .enumerate()
            .for_each(|(n, padded_row)| {
                padded_row[CPU_COL_MAP.pc] = pc;
                padded_row[CPU_COL_MAP.clk] = clk + F::from_canonical_u32(n as u32 + 1);
                padded_row[CPU_COL_MAP.selectors.noop] = F::one();
                padded_row[CPU_COL_MAP.selectors.imm_b] = F::one();
                padded_row[CPU_COL_MAP.selectors.imm_c] = F::one();
                // The operands will default by 0, so this will be a no-op anyways.
            });
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::{tests::get_simple_program, Instruction};

    use p3_baby_bear::BabyBear;

    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use p3_uni_stark::{prove, verify, StarkConfigImpl};
    use rand::thread_rng;

    use crate::utils::Chip;
    use p3_commit::ExtensionMmcs;

    use super::*;
    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program, 0);
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
            memory_value: None,
            memory_store_value: None,
        }];
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values);
        // println!(
        //     "{:?} {:?} {:?} {:?} {:?}",
        //     cols.clk, cols.pc, cols.op_a_val, cols.op_b_val, cols.op_c_val
        // );
    }

    #[test]
    fn generate_trace_simple_program() {
        let program = get_simple_program();
        let mut runtime = Runtime::new(program, 0);
        runtime.run();
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_trace() {
        type Val = BabyBear;
        type Domain = Val;
        type Challenge = BinomialExtensionField<Val, 4>;
        type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

        type MyMds = CosetMds<Val, 16>;
        let mds = MyMds::default();

        type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
        let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

        type MyHash = SerializingHasher32<Keccak256Hash>;
        let hash = MyHash::new(Keccak256Hash {});

        type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
        let compress = MyCompress::new(hash);

        type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
        let val_mmcs = ValMmcs::new(hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel;
        let dft = Dft {};

        type Challenger = DuplexChallenger<Val, Perm, 16>;

        type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
        type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
        let fri_config = MyFriConfig::new(40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);
        let mut challenger = Challenger::new(perm.clone());

        let program = get_simple_program();
        let mut runtime = Runtime::new(program, 0);
        runtime.run();
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        trace.rows().for_each(|row| println!("{:?}", row));

        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
