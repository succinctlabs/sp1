use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::{izip, Itertools};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program, DEFAULT_PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{BaseAirBuilder, MachineAir, SP1AirBuilder},
    Word,
};

use crate::utils::{next_power_of_two, zeroed_f_vec};

/// The number of main trace columns for `LtChip`.
pub const NUM_LT_COLS: usize = size_of::<LtCols<u8>>();

/// A chip that implements bitwise operations for the opcodes SLT and SLTU.
#[derive(Default)]
pub struct LtChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct LtCols<T> {
    /// The program counter.
    pub pc: T,

    /// If the opcode is SLT.
    pub is_slt: T,

    /// If the opcode is SLTU.
    pub is_sltu: T,

    /// The output operand.
    pub a: T,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Whether the first operand is not register 0.
    pub op_a_not_0: T,

    /// Boolean flag to indicate which byte pair differs if the operands are not equal.
    pub byte_flags: [T; 4],

    /// The masking b\[3\] & 0x7F.
    pub b_masked: T,
    /// The masking c\[3\] & 0x7F.
    pub c_masked: T,
    /// An inverse of differing byte if c_comp != b_comp.
    pub not_eq_inv: T,

    /// The most significant bit of operand b.
    pub msb_b: T,
    /// The most significant bit of operand c.
    pub msb_c: T,
    /// The multiplication msb_b * is_slt.
    pub bit_b: T,
    /// The multiplication msb_c * is_slt.
    pub bit_c: T,

    /// The result of the intermediate SLTU operation `b_comp < c_comp`.
    pub sltu: T,
    /// A bollean flag for an intermediate comparison.
    pub is_comp_eq: T,
    /// A boolean flag for comparing the sign bits.
    pub is_sign_eq: T,
    /// The comparison bytes to be looked up.
    pub comparison_bytes: [T; 2],
    /// Boolean fags to indicate which byte differs between the perands `b_comp`, `c_comp`.
    pub byte_equality_check: [T; 4],
}

impl LtCols<u32> {
    pub fn from_trace_row<F: PrimeField32>(row: &[F]) -> Self {
        let sized: [u32; NUM_LT_COLS] =
            row.iter().map(|x| x.as_canonical_u32()).collect::<Vec<u32>>().try_into().unwrap();
        *sized.as_slice().borrow()
    }
}

impl<F: PrimeField32> MachineAir<F> for LtChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Lt".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let nb_rows = input.lt_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_LT_COLS);
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        values.chunks_mut(chunk_size * NUM_LT_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_LT_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut LtCols<F> = row.borrow_mut();

                    if idx < nb_rows {
                        let mut byte_lookup_events = Vec::new();
                        let event = &input.lt_events[idx];
                        self.event_to_row(event, cols, &mut byte_lookup_events);
                    }
                });
            },
        );

        // Convert the trace to a row major matrix.

        RowMajorMatrix::new(values, NUM_LT_COLS)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.lt_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .lt_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_LT_COLS];
                    let cols: &mut LtCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.lt_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl LtChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &AluEvent,
        cols: &mut LtCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();

        cols.pc = F::from_canonical_u32(event.pc);

        cols.a = F::from_canonical_u8(a[0]);
        cols.b = Word(b.map(F::from_canonical_u8));
        cols.c = Word(c.map(F::from_canonical_u8));
        cols.op_a_not_0 = F::from_bool(!event.op_a_0);

        // If this is SLT, mask the MSB of b & c before computing cols.bits.
        let masked_b = b[3] & 0x7f;
        let masked_c = c[3] & 0x7f;
        cols.b_masked = F::from_canonical_u8(masked_b);
        cols.c_masked = F::from_canonical_u8(masked_c);

        // Send the masked interaction.
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a1: masked_b as u16,
            a2: 0,
            b: b[3],
            c: 0x7f,
        });
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a1: masked_c as u16,
            a2: 0,
            b: c[3],
            c: 0x7f,
        });

        let mut b_comp = b;
        let mut c_comp = c;
        if event.opcode == Opcode::SLT {
            b_comp[3] = masked_b;
            c_comp[3] = masked_c;
        }
        cols.sltu = F::from_bool(b_comp < c_comp);
        cols.is_comp_eq = F::from_bool(b_comp == c_comp);

        // Set the byte equality flags.
        for (b_byte, c_byte, flag) in
            izip!(b_comp.iter().rev(), c_comp.iter().rev(), cols.byte_flags.iter_mut().rev())
        {
            if c_byte != b_byte {
                *flag = F::one();
                cols.sltu = F::from_bool(b_byte < c_byte);
                let b_byte = F::from_canonical_u8(*b_byte);
                let c_byte = F::from_canonical_u8(*c_byte);
                cols.not_eq_inv = (b_byte - c_byte).inverse();
                cols.comparison_bytes = [b_byte, c_byte];
                break;
            }
        }

        cols.msb_b = F::from_canonical_u8((b[3] >> 7) & 1);
        cols.msb_c = F::from_canonical_u8((c[3] >> 7) & 1);
        cols.is_sign_eq = if event.opcode == Opcode::SLT {
            F::from_bool((b[3] >> 7) == (c[3] >> 7))
        } else {
            F::one()
        };

        cols.is_slt = F::from_bool(event.opcode == Opcode::SLT);
        cols.is_sltu = F::from_bool(event.opcode == Opcode::SLTU);

        cols.bit_b = cols.msb_b * cols.is_slt;
        cols.bit_c = cols.msb_c * cols.is_slt;

        assert_eq!(cols.a, cols.bit_b * (F::one() - cols.bit_c) + cols.is_sign_eq * cols.sltu);

        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::LTU,
            a1: cols.sltu.as_canonical_u32() as u16,
            a2: 0,
            b: cols.comparison_bytes[0].as_canonical_u32() as u8,
            c: cols.comparison_bytes[1].as_canonical_u32() as u8,
        });
    }
}

impl<F> BaseAir<F> for LtChip {
    fn width(&self) -> usize {
        NUM_LT_COLS
    }
}

impl<AB> Air<AB> for LtChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &LtCols<AB::Var> = (*local).borrow();

        let is_real = local.is_slt + local.is_sltu;

        // We can compute the signed set-less-than as follows:
        // SLT (signed) = b_s * (1 - c_s) + (b_s == c_s) * SLTU(b_<s, c_<s)
        // Source: Jolt 5.3: Set Less Than (https://people.cs.georgetown.edu/jthaler/Jolt-paper.pdf)

        // We will compute SLTU(b_comp, c_comp) where `b_comp` and `c_comp` where:
        // * if the operation is `STLU`, `b_comp = b` and `c_comp = c`
        // * if the operation is `STL`, `b_comp = b & 0x7FFFFFFF` and `c_comp = c & 0x7FFFFFFF``
        //
        // We will set booleans `b_bit` and `c_bit` so that:
        // * If the operation is `SLTU`, then `b_bit = 0` and `c_bit = 0`.
        // * If the operation is `SLT`, then `b_bit`, `c_bit` are the most significant bits of `b`
        //   and `c` respectively.
        //
        // Then, we will compute the answer as:
        // SLT = b_bit * (1 - c_bit) + (b_bit == c_bit) * SLTU(b_comp, c_comp)

        // First, we set up the values of `b_comp` and `c_comp`.
        let mut b_comp: Word<AB::Expr> = local.b.map(|x| x.into());
        let mut c_comp: Word<AB::Expr> = local.c.map(|x| x.into());

        b_comp[3] = local.b[3] * local.is_sltu + local.b_masked * local.is_slt;
        c_comp[3] = local.c[3] * local.is_sltu + local.c_masked * local.is_slt;

        // Constrain the `masked_b` and `masked_c` values via lookup.
        //
        // The values are given by `b_masked = b[3] & 0x7F` and `c_masked = c[3] & 0x7F`.
        builder.send_byte(
            ByteOpcode::AND.as_field::<AB::F>(),
            local.b_masked,
            local.b[3],
            AB::F::from_canonical_u8(0x7f),
            is_real.clone(),
        );
        builder.send_byte(
            ByteOpcode::AND.as_field::<AB::F>(),
            local.c_masked,
            local.c[3],
            AB::F::from_canonical_u8(0x7f),
            is_real.clone(),
        );

        // Set the values of `b_bit` and `c_bit`.
        builder.assert_eq(local.bit_b, local.msb_b * local.is_slt);
        builder.assert_eq(local.bit_c, local.msb_c * local.is_slt);

        // Assert the correctness of `local.msb_b` and `local.msb_c` using the mask.
        let inv_128 = AB::F::from_canonical_u32(128).inverse();
        builder.assert_eq(local.msb_b, (local.b[3] - local.b_masked) * inv_128);
        builder.assert_eq(local.msb_c, (local.c[3] - local.c_masked) * inv_128);

        // Constrain that when is_sign_eq = (bit_b == bit_c).

        // assert the flag is a boolean.
        builder.assert_bool(local.is_sign_eq);

        // assert the correction of the comparison.
        builder.when(local.is_sign_eq).assert_eq(local.bit_b, local.bit_c);
        builder
            .when(is_real.clone())
            .when_not(local.is_sign_eq)
            .assert_one(local.bit_b + local.bit_c);

        // Assert the final result `a` is correct.

        // Check that `a[0]` is set correctly.
        // This check is done only when `op_a_not_0 == 1`.
        builder.when(local.op_a_not_0).assert_eq(
            local.a,
            local.bit_b * (AB::Expr::one() - local.bit_c) + local.is_sign_eq * local.sltu,
        );

        // Verify that the byte equality flags are set correctly, i.e. all are boolean and only
        // at most a single byte flag is set.
        let sum_flags =
            local.byte_flags[0] + local.byte_flags[1] + local.byte_flags[2] + local.byte_flags[3];
        builder.assert_bool(local.byte_flags[0]);
        builder.assert_bool(local.byte_flags[1]);
        builder.assert_bool(local.byte_flags[2]);
        builder.assert_bool(local.byte_flags[3]);
        builder.assert_bool(sum_flags.clone());
        builder.when(is_real.clone()).assert_eq(AB::Expr::one() - local.is_comp_eq, sum_flags);

        // Constrain `local.sltu == STLU(b_comp, c_comp)`.
        //
        // We define bytes `b_comp_byte` and `c_comp_byte` as follows: If `b_comp == c_comp`, then
        // `b_comp_byte = c_comp_byte = 0`. Otherwise, we set `b_comp_byte` and `c_comp_byte` to
        // the first differing byte (in most significant order). We will use the `local.is_comp_eq`
        // flag to indicate whether the bytes are equal.

        // Check the equality flag is boolean.
        builder.assert_bool(local.is_comp_eq);

        // Find the differing byte if `b_comp != c_comp` and assert equality in case the flag
        // `local.is_comp_eq` is set to `1`.

        // A flag to indicate whether an equality check is necessary (this is for all bytes from
        // most significant until the first inequality.
        let mut is_inequality_visited = AB::Expr::zero();

        // Expressions for computing the comparison bytes.
        let mut b_comparison_byte = AB::Expr::zero();
        let mut c_comparison_byte = AB::Expr::zero();
        // Iterate over the bytes in reverse order and select the differing bytes using the byte
        // flag columns values.
        for (b_byte, c_byte, &flag) in
            izip!(b_comp.0.iter().rev(), c_comp.0.iter().rev(), local.byte_flags.iter().rev())
        {
            // Once the byte flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited = is_inequality_visited.clone() + flag.into();

            b_comparison_byte = b_comparison_byte.clone() + b_byte.clone() * flag;
            c_comparison_byte = c_comparison_byte.clone() + c_byte.clone() * flag;

            // If inequality is not visited, assert that the bytes are equal.
            builder
                .when_not(is_inequality_visited.clone())
                .assert_eq(b_byte.clone(), c_byte.clone());
            // If the numbers are assumed equal, inequality should not be visited.
            builder.when(local.is_comp_eq).assert_zero(is_inequality_visited.clone());
        }
        // We need to verify that the comparison bytes are set correctly. This is only relevant in
        // the case where the bytes are not equal.

        // Constrain the row comparison byte values to be equal to the calciulated ones.
        let (b_comp_byte, c_comp_byte) = (local.comparison_bytes[0], local.comparison_bytes[1]);
        builder.assert_eq(b_comp_byte, b_comparison_byte);
        builder.assert_eq(c_comp_byte, c_comparison_byte);

        // Using the values above, we can constrain the `local.is_comp_eq` flag. We already asserted
        // in the loop that when `local.is_comp_eq == 1` then all bytes are euqal. It is left to
        // verify that when `local.is_comp_eq == 0` the comparison bytes are indeed not equal.
        // This is done using the inverse hint `not_eq_inv`.
        builder
            .when_not(local.is_comp_eq)
            .assert_eq(local.not_eq_inv * (b_comp_byte - c_comp_byte), is_real.clone());

        // Now the value of `local.sltu` is equal to the same value for the comparison bytes.
        //
        // Set `local.sltu = STLU(b_comp_byte, c_comp_byte)` via a lookup.
        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            local.sltu,
            b_comp_byte,
            c_comp_byte,
            is_real.clone(),
        );

        // Constrain the operation flags.

        // SAFETY: All selectors `is_slt`, `is_sltu` are checked to be boolean.
        // Each "real" row has exactly one selector turned on, as `is_real = is_slt + is_sltu` is boolean.
        // Therefore, the `opcode` matches the corresponding opcode.

        // Check that the operation flags are boolean.
        builder.assert_bool(local.is_slt);
        builder.assert_bool(local.is_sltu);
        // Check that at most one of the operation flags is set.
        builder.assert_bool(local.is_slt + local.is_sltu);

        // Receive the arguments.
        // SAFETY: This checks the following.
        // - `next_pc = pc + 4`
        // - `num_extra_cycles = 0`
        // - `op_a_val` is constrained by the chip when `op_a_not_0 == 1`
        // - `op_a_not_0` is correct, due to the sent `op_a_0` being equal to `1 - op_a_not_0`
        // - `op_a_immutable = 0`
        // - `is_memory = 0`
        // - `is_syscall = 0`
        // - `is_halt = 0`
        builder.receive_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.pc,
            local.pc + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
            AB::Expr::zero(),
            local.is_slt * AB::F::from_canonical_u32(Opcode::SLT as u32)
                + local.is_sltu * AB::F::from_canonical_u32(Opcode::SLTU as u32),
            Word::extend_var::<AB>(local.a),
            local.b,
            local.c,
            AB::Expr::one() - local.op_a_not_0,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use std::borrow::BorrowMut;

    use crate::{
        alu::LtCols,
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{run_malicious_test, uni_stark_prove as prove, uni_stark_verify as verify},
    };
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};
    use sp1_core_executor::{
        events::{AluEvent, MemoryRecordEnum},
        ExecutionRecord, Instruction, Opcode, Program,
    };
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, chip_name, CpuProver,
        MachineProver, StarkGenericConfig, Val,
    };

    use super::LtChip;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.lt_events = vec![AluEvent::new(0, Opcode::SLT, 0, 3, 2, false)];
        let chip = LtChip::default();
        let generate_trace = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let trace: RowMajorMatrix<BabyBear> = generate_trace;
        println!("{:?}", trace.values)
    }

    fn prove_babybear_template(shard: &mut ExecutionRecord) {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let chip = LtChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn prove_babybear_slt() {
        let mut shard = ExecutionRecord::default();

        const NEG_3: u32 = 0b11111111111111111111111111111101;
        const NEG_4: u32 = 0b11111111111111111111111111111100;
        shard.lt_events = vec![
            // 0 == 3 < 2
            AluEvent::new(0, Opcode::SLT, 0, 3, 2, false),
            // 1 == 2 < 3
            AluEvent::new(0, Opcode::SLT, 1, 2, 3, false),
            // 0 == 5 < -3
            AluEvent::new(0, Opcode::SLT, 0, 5, NEG_3, false),
            // 1 == -3 < 5
            AluEvent::new(0, Opcode::SLT, 1, NEG_3, 5, false),
            // 0 == -3 < -4
            AluEvent::new(0, Opcode::SLT, 0, NEG_3, NEG_4, false),
            // 1 == -4 < -3
            AluEvent::new(0, Opcode::SLT, 1, NEG_4, NEG_3, false),
            // 0 == 3 < 3
            AluEvent::new(0, Opcode::SLT, 0, 3, 3, false),
            // 0 == -3 < -3
            AluEvent::new(0, Opcode::SLT, 0, NEG_3, NEG_3, false),
        ];

        prove_babybear_template(&mut shard);
    }

    #[test]
    fn prove_babybear_sltu() {
        let mut shard = ExecutionRecord::default();

        const LARGE: u32 = 0b11111111111111111111111111111101;
        shard.lt_events = vec![
            // 0 == 3 < 2
            AluEvent::new(0, Opcode::SLTU, 0, 3, 2, false),
            // 1 == 2 < 3
            AluEvent::new(0, Opcode::SLTU, 1, 2, 3, false),
            // 0 == LARGE < 5
            AluEvent::new(0, Opcode::SLTU, 0, LARGE, 5, false),
            // 1 == 5 < LARGE
            AluEvent::new(0, Opcode::SLTU, 1, 5, LARGE, false),
            // 0 == 0 < 0
            AluEvent::new(0, Opcode::SLTU, 0, 0, 0, false),
            // 0 == LARGE < LARGE
            AluEvent::new(0, Opcode::SLTU, 0, LARGE, LARGE, false),
        ];

        prove_babybear_template(&mut shard);
    }

    #[test]
    fn test_malicious_lt() {
        const NUM_TESTS: usize = 5;

        for opcode in [Opcode::SLTU, Opcode::SLT] {
            for _ in 0..NUM_TESTS {
                let op_b = thread_rng().gen_range(0..u32::MAX);
                let op_c = thread_rng().gen_range(0..u32::MAX);

                let correct_op_a = if opcode == Opcode::SLTU {
                    op_b < op_c
                } else {
                    (op_b as i32) < (op_c as i32)
                };

                let op_a = !correct_op_a;

                let instructions = vec![
                    Instruction::new(opcode, 5, op_b, op_c, true, true),
                    Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
                ];

                let program = Program::new(instructions, 0, 0);
                let stdin = SP1Stdin::new();

                type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

                let malicious_trace_pv_generator = move |prover: &P,
                                                         record: &mut ExecutionRecord|
                      -> Vec<(
                    String,
                    RowMajorMatrix<Val<BabyBearPoseidon2>>,
                )> {
                    let mut malicious_record = record.clone();
                    malicious_record.cpu_events[0].a = op_a as u32;
                    if let Some(MemoryRecordEnum::Write(mut write_record)) =
                        malicious_record.cpu_events[0].a_record
                    {
                        write_record.value = op_a as u32;
                    }
                    let mut traces = prover.generate_traces(&malicious_record);

                    let lt_chip_name = chip_name!(LtChip, BabyBear);
                    for (chip_name, trace) in traces.iter_mut() {
                        if *chip_name == lt_chip_name {
                            let first_row = trace.row_mut(0);
                            let first_row: &mut LtCols<BabyBear> = first_row.borrow_mut();
                            first_row.a = BabyBear::from_bool(op_a);
                        }
                    }

                    traces
                };

                let result =
                    run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
                let lt_chip_name = chip_name!(LtChip, BabyBear);
                assert!(
                    result.is_err() && result.unwrap_err().is_constraints_failing(&lt_chip_name)
                );
            }
        }
    }
}
