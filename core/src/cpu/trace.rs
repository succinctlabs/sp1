use super::air::{
    AUIPCColumns, BranchColumns, CpuCols, JumpColumns, MemoryAccessCols, MemoryColumns,
    CPU_COL_MAP, NUM_CPU_COLS,
};
use super::{CpuEvent, MemoryRecord};

use crate::alu::{self, AluEvent};
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::disassembler::WORD_SIZE;
use crate::runtime::{Opcode, Segment};
use crate::utils::Chip;

use core::mem::transmute;
use std::collections::HashMap;

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

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut new_blu_events = Vec::new();
        let mut new_alu_events = HashMap::new();

        let rows = segment
            .cpu_events
            .iter() // TODO: change this back to par_iter
            .map(|op| self.event_to_row(*op, &mut new_alu_events, &mut new_blu_events))
            .collect::<Vec<_>>();

        segment.add_alu_events(new_alu_events);
        segment.add_byte_lookup_events(new_blu_events);

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        Self::pad_to_power_of_two::<F>(&mut trace.values);

        trace
    }
}

impl CpuChip {
    fn event_to_row<F: PrimeField>(
        &self,
        event: CpuEvent,
        new_alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) -> [F; NUM_CPU_COLS] {
        let mut row = [F::zero(); NUM_CPU_COLS];
        let cols: &mut CpuCols<F> = unsafe { transmute(&mut row) };
        cols.segment = F::from_canonical_u32(event.segment);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);

        cols.instruction.populate(event.instruction);
        cols.selectors.populate(event.instruction);

        self.populate_access(&mut cols.op_a_access, event.a, event.a_record);
        self.populate_access(&mut cols.op_b_access, event.b, event.b_record);
        self.populate_access(&mut cols.op_c_access, event.c, event.c_record);

        // If there is a memory record, then event.memory should be set and vice-versa.
        assert_eq!(event.memory_record.is_some(), event.memory.is_some());

        let memory_columns: &mut MemoryColumns<F> =
            unsafe { transmute(&mut cols.opcode_specific_columns) };
        if let Some(memory) = event.memory {
            self.populate_access(
                &mut memory_columns.memory_access,
                memory,
                event.memory_record,
            )
        }

        self.populate_memory(cols, event, new_alu_events, new_blu_events);
        self.populate_branch(cols, event, new_alu_events);
        self.populate_jump(cols, event, new_alu_events);
        self.populate_auipc(cols, event, new_alu_events);

        if matches!(event.instruction.opcode, Opcode::SH) {
            println!("cols: {:?}", cols);
            println!("memory_columns: {:?}", memory_columns);
        }

        cols.is_real = F::one();

        row
    }

    fn populate_access<F: PrimeField>(
        &self,
        cols: &mut MemoryAccessCols<F>,
        value: u32,
        record: Option<MemoryRecord>,
    ) {
        cols.value = value.into();
        // If `imm_b` or `imm_c` is set, then the record won't exist since we're not accessing from memory.
        if let Some(record) = record {
            cols.prev_value = record.value.into();
            cols.segment = F::from_canonical_u32(record.segment);
            cols.timestamp = F::from_canonical_u32(record.timestamp);
        }
    }

    fn populate_memory<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        new_alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
        if matches!(
            event.instruction.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
        ) {
            let memory_addr = event.b.wrapping_add(event.c);

            let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
            // bit little endian representation of addr_offset
            let addr_offset_bits = [addr_offset & 1, addr_offset & 2];

            let mut bit_decomp = [0; 8];
            let signed_opcode = matches!(event.instruction.opcode, Opcode::LBU | Opcode::LHU);
            let mut is_neg = false;
            let mut max_value = 0u32;
            if signed_opcode {
                // bit decompose the most significant byte of the memory address to be used
                // to check if the loaded value is negative.

                let most_sig_mem_value_byte: u8;
                if matches!(event.instruction.opcode, Opcode::LBU) {
                    max_value = 256;
                    most_sig_mem_value_byte = event.memory_record.unwrap().value.to_le_bytes()[0];
                } else {
                    // LHU case
                    max_value = 65536;
                    most_sig_mem_value_byte = event.memory_record.unwrap().value.to_le_bytes()[1];
                };

                bit_decomp = [
                    most_sig_mem_value_byte & 1,
                    most_sig_mem_value_byte & 2,
                    most_sig_mem_value_byte & 4,
                    most_sig_mem_value_byte & 8,
                    most_sig_mem_value_byte & 16,
                    most_sig_mem_value_byte & 32,
                    most_sig_mem_value_byte & 64,
                    most_sig_mem_value_byte & 128,
                ];

                is_neg = bit_decomp[7] == 1;
            }

            //// Populate memory columns.
            let memory_columns: &mut MemoryColumns<F> =
                unsafe { transmute(&mut cols.opcode_specific_columns) };

            memory_columns.addr_word = memory_addr.into();
            memory_columns.addr_aligned =
                F::from_canonical_u32(memory_addr - memory_addr % WORD_SIZE as u32);
            memory_columns.addr_offset = F::from_canonical_u8(addr_offset);

            memory_columns.offset_bit_decomp[0] = F::from_canonical_u8(addr_offset_bits[0]);
            memory_columns.offset_bit_decomp[1] = F::from_canonical_u8(addr_offset_bits[1]);
            memory_columns.bit_product =
                F::from_canonical_u8(addr_offset_bits[0] * addr_offset_bits[1]);

            memory_columns.most_sig_byte_decomp = bit_decomp.map(F::from_canonical_u8);

            //// Add events to other tables.
            // Add event to ALU check to check that addr == b + c
            let add_event = AluEvent {
                clk: event.clk,
                opcode: Opcode::ADD,
                a: memory_addr,
                b: max_value,
                c: event.c,
            };

            new_alu_events
                .entry(Opcode::ADD)
                .and_modify(|op_new_events| op_new_events.push(add_event))
                .or_insert(vec![add_event]);

            // If it's a signed_opcode and the a value is negative, then send an event to the SUB chip.
            if signed_opcode && is_neg {
                let sub_event = AluEvent {
                    clk: event.clk,
                    opcode: Opcode::SUB,
                    a: event.a,
                    b: max_value,
                    c: event.memory_record.unwrap().value,
                };

                new_alu_events
                    .entry(Opcode::SUB)
                    .and_modify(|op_new_events| op_new_events.push(sub_event))
                    .or_insert(vec![sub_event]);
            }

            // Add event to byte lookup for byte range checking each byte in the memory addr
            let addr_bytes = memory_addr.to_le_bytes();
            for byte_pair in addr_bytes.chunks_exact(2) {
                new_blu_events.push(ByteLookupEvent {
                    opcode: ByteOpcode::Range,
                    a1: 0,
                    a2: 0,
                    b: byte_pair[0],
                    c: byte_pair[1],
                });
            }
        }
    }

    fn populate_branch<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
    ) {
        if event.instruction.is_branch_instruction() {
            let branch_columns: &mut BranchColumns<F> =
                unsafe { transmute(&mut cols.opcode_specific_columns) };

            let a_eq_b = event.a == event.b;

            let use_signed_comparison =
                matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);

            let a_lt_b = if use_signed_comparison {
                (event.a as i32) < (event.b as i32)
            } else {
                event.a < event.b
            };
            let a_gt_b = if use_signed_comparison {
                (event.a as i32) > (event.b as i32)
            } else {
                event.a > event.b
            };

            let alu_op_code = if use_signed_comparison {
                Opcode::SLT
            } else {
                Opcode::SLTU
            };
            // Add the ALU events for the comparisons
            let lt_comp_event = AluEvent {
                clk: event.clk,
                opcode: alu_op_code,
                a: a_lt_b as u32,
                b: event.a,
                c: event.b,
            };

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(lt_comp_event))
                .or_insert(vec![lt_comp_event]);

            let gt_comp_event = AluEvent {
                clk: event.clk,
                opcode: alu_op_code,
                a: a_gt_b as u32,
                b: event.b,
                c: event.a,
            };

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(gt_comp_event))
                .or_insert(vec![gt_comp_event]);

            branch_columns.a_eq_b = F::from_bool(a_eq_b);
            branch_columns.a_lt_b = F::from_bool(a_lt_b);
            branch_columns.a_gt_b = F::from_bool(a_gt_b);

            let branching = match event.instruction.opcode {
                Opcode::BEQ => a_eq_b,
                Opcode::BNE => !a_eq_b,
                Opcode::BLT | Opcode::BLTU => a_lt_b,
                Opcode::BGE | Opcode::BGEU => a_gt_b,
                _ => unreachable!(),
            };

            if branching {
                let next_pc = event.pc.wrapping_add(event.c);

                cols.branching = F::one();
                branch_columns.pc = event.pc.into();
                branch_columns.next_pc = next_pc.into();

                let add_event = AluEvent {
                    clk: event.clk,
                    opcode: Opcode::ADD,
                    a: next_pc,
                    b: event.pc,
                    c: event.c,
                };

                alu_events
                    .entry(Opcode::ADD)
                    .and_modify(|op_new_events| op_new_events.push(add_event))
                    .or_insert(vec![add_event]);
            }
        }
    }

    fn populate_jump<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
    ) {
        if event.instruction.is_jump_instruction() {
            let jump_columns: &mut JumpColumns<F> =
                unsafe { transmute(&mut cols.opcode_specific_columns) };

            match event.instruction.opcode {
                Opcode::JAL => {
                    let next_pc = event.pc.wrapping_add(event.b);
                    jump_columns.pc = event.pc.into();
                    jump_columns.next_pc = next_pc.into();

                    let add_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.pc,
                        c: event.b,
                    };

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                Opcode::JALR => {
                    let next_pc = event.b.wrapping_add(event.c);
                    jump_columns.next_pc = next_pc.into();

                    let add_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.b,
                        c: event.c,
                    };

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                _ => unreachable!(),
            }
        }
    }

    fn populate_auipc<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
    ) {
        if matches!(event.instruction.opcode, Opcode::AUIPC) {
            let auipc_columns: &mut AUIPCColumns<F> =
                unsafe { transmute(&mut cols.opcode_specific_columns) };

            auipc_columns.pc = event.pc.into();

            let add_event = AluEvent {
                clk: event.clk,
                opcode: Opcode::ADD,
                a: event.a,
                b: event.pc,
                c: event.b,
            };

            alu_events
                .entry(Opcode::ADD)
                .and_modify(|op_new_events| op_new_events.push(add_event))
                .or_insert(vec![add_event]);
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
                padded_row[CPU_COL_MAP.clk] = clk + F::from_canonical_u32((n as u32 + 1) * 4);
                padded_row[CPU_COL_MAP.selectors.is_noop] = F::one();
                padded_row[CPU_COL_MAP.selectors.imm_b] = F::one();
                padded_row[CPU_COL_MAP.selectors.imm_c] = F::one();
                // The operands will default by 0, so this will be a no-op anyways.
            });
    }
}

#[cfg(test)]
mod tests {

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

    use crate::{
        runtime::{tests::simple_program, Instruction, Runtime, Segment},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::*;
    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.cpu_events = vec![CpuEvent {
            segment: 1,
            clk: 6,
            pc: 1,
            instruction: Instruction {
                opcode: Opcode::ADD,
                op_a: 0,
                op_b: 1,
                op_c: 2,
                imm_b: false,
                imm_c: false,
            },
            a: 1,
            a_record: None,
            b: 2,
            b_record: None,
            c: 3,
            c_record: None,
            memory: None,
            memory_record: None,
        }];
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values);
    }

    #[test]
    fn generate_trace_simple_program() {
        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime.segment);
        for cpu_event in runtime.segment.cpu_events {
            println!("{:?}", cpu_event);
        }
        println!("{:?}", trace.values)
    }

    #[test]
    fn test_signed() {
        let value = 200u8;
        println!("value is {}", value);

        let mut signed_value = value as i8;
        println!("signed value is {}", signed_value);

        let signed_value: i32 = signed_value as i32;
        println!("signed value is {}", signed_value);

        let signed_value: u32 = signed_value as u32;
        println!("signed value is {}", signed_value);
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

        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let chip = CpuChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime.segment);
        trace.rows().for_each(|row| println!("{:?}", row));

        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
