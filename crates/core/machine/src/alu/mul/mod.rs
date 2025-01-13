//! Implementation to check that b * c = product.
//!
//! We first extend the operands to 64 bits. We sign-extend them if the op code is signed. Then we
//! calculate the un-carried product and propagate the carry. Finally, we check that the appropriate
//! bits of the product match the result.
//!
//! b_64 = sign_extend(b) if signed operation else b
//! c_64 = sign_extend(c) if signed operation else c
//!
//! m = []
//! # 64-bit integers have 8 limbs.
//! # Calculate un-carried product.
//! for i in 0..8:
//!     for j in 0..8:
//!         if i + j < 8:
//!             m\[i + j\] += b_64\[i\] * c_64\[j\]
//!
//! # Propagate carry
//! for i in 0..8:
//!     x = m\[i\]
//!     if i > 0:
//!         x += carry\[i - 1\]
//!     carry\[i\] = x / 256
//!     m\[i\] = x % 256
//!
//! if upper_half:
//!     assert_eq(a, m\[4..8\])
//! if lower_half:
//!     assert_eq(a, m\[0..4\])

mod utils;

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program, DEFAULT_PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::{BYTE_SIZE, LONG_WORD_SIZE, WORD_SIZE};
use sp1_stark::{air::MachineAir, Word};

use crate::{
    air::SP1CoreAirBuilder,
    alu::mul::utils::get_msb,
    utils::{next_power_of_two, zeroed_f_vec},
};

/// The number of main trace columns for `MulChip`.
pub const NUM_MUL_COLS: usize = size_of::<MulCols<u8>>();

/// The mask for a byte.
const BYTE_MASK: u8 = 0xff;

/// A chip that implements multiplication for the multiplication opcodes.
#[derive(Default)]
pub struct MulChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulCols<T> {
    /// The program counter.
    pub pc: T,

    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Flag indicating whether `a` is not register 0.
    pub op_a_not_0: T,

    /// Trace.
    pub carry: [T; LONG_WORD_SIZE],

    /// An array storing the product of `b * c` after the carry propagation.
    pub product: [T; LONG_WORD_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The most significant bit of `c`.
    pub c_msb: T,

    /// The sign extension of `b`.
    pub b_sign_extend: T,

    /// The sign extension of `c`.
    pub c_sign_extend: T,

    /// Flag indicating whether the opcode is `MUL` (`u32 x u32`).
    pub is_mul: T,

    /// Flag indicating whether the opcode is `MULH` (`i32 x i32`, upper half).
    pub is_mulh: T,

    /// Flag indicating whether the opcode is `MULHU` (`u32 x u32`, upper half).
    pub is_mulhu: T,

    /// Flag indicating whether the opcode is `MULHSU` (`i32 x u32`, upper half).
    pub is_mulhsu: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for MulChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Mul".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let nb_rows = input.mul_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MUL_COLS);
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        values.chunks_mut(chunk_size * NUM_MUL_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_MUL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut MulCols<F> = row.borrow_mut();

                    if idx < nb_rows {
                        let mut byte_lookup_events = Vec::new();
                        let event = &input.mul_events[idx];
                        self.event_to_row(event, cols, &mut byte_lookup_events);
                    }
                });
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MUL_COLS)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.mul_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .mul_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_MUL_COLS];
                    let cols: &mut MulCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect::<Vec<_>>());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.mul_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl MulChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut MulCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.pc = F::from_canonical_u32(event.pc);

        let a_word = event.a.to_le_bytes();
        let b_word = event.b.to_le_bytes();
        let c_word = event.c.to_le_bytes();

        let mut b = b_word.to_vec();
        let mut c = c_word.to_vec();
        cols.op_a_not_0 = F::from_bool(!event.op_a_0);

        // Handle b and c's signs.
        {
            let b_msb = get_msb(b_word);
            cols.b_msb = F::from_canonical_u8(b_msb);
            let c_msb = get_msb(c_word);
            cols.c_msb = F::from_canonical_u8(c_msb);

            // If b is signed and it is negative, sign extend b.
            if (event.opcode == Opcode::MULH || event.opcode == Opcode::MULHSU) && b_msb == 1 {
                cols.b_sign_extend = F::one();
                b.resize(LONG_WORD_SIZE, BYTE_MASK);
            }

            // If c is signed and it is negative, sign extend c.
            if event.opcode == Opcode::MULH && c_msb == 1 {
                cols.c_sign_extend = F::one();
                c.resize(LONG_WORD_SIZE, BYTE_MASK);
            }

            // Insert the MSB lookup events.
            {
                let words = [b_word, c_word];
                let mut blu_events: Vec<ByteLookupEvent> = vec![];
                for word in words.iter() {
                    let most_significant_byte = word[WORD_SIZE - 1];
                    blu_events.push(ByteLookupEvent {
                        opcode: ByteOpcode::MSB,
                        a1: get_msb(*word) as u16,
                        a2: 0,
                        b: most_significant_byte,
                        c: 0,
                    });
                }
                blu.add_byte_lookup_events(blu_events);
            }
        }

        let mut product = [0u32; LONG_WORD_SIZE];
        for i in 0..b.len() {
            for j in 0..c.len() {
                if i + j < LONG_WORD_SIZE {
                    product[i + j] += (b[i] as u32) * (c[j] as u32);
                }
            }
        }

        // Calculate the correct product using the `product` array. We store the
        // correct carry value for verification.
        let base = (1 << BYTE_SIZE) as u32;
        let mut carry = [0u32; LONG_WORD_SIZE];
        for i in 0..LONG_WORD_SIZE {
            carry[i] = product[i] / base;
            product[i] %= base;
            if i + 1 < LONG_WORD_SIZE {
                product[i + 1] += carry[i];
            }
            cols.carry[i] = F::from_canonical_u32(carry[i]);
        }

        cols.product = product.map(F::from_canonical_u32);
        cols.a = Word(a_word.map(F::from_canonical_u8));
        cols.b = Word(b_word.map(F::from_canonical_u8));
        cols.c = Word(c_word.map(F::from_canonical_u8));
        cols.is_real = F::one();
        cols.is_mul = F::from_bool(event.opcode == Opcode::MUL);
        cols.is_mulh = F::from_bool(event.opcode == Opcode::MULH);
        cols.is_mulhu = F::from_bool(event.opcode == Opcode::MULHU);
        cols.is_mulhsu = F::from_bool(event.opcode == Opcode::MULHSU);

        // Range check.
        {
            blu.add_u16_range_checks(&carry.map(|x| x as u16));
            blu.add_u8_range_checks(&product.map(|x| x as u8));
        }
    }
}

impl<F> BaseAir<F> for MulChip {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<AB> Air<AB> for MulChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MulCols<AB::Var> = (*local).borrow();
        let base = AB::F::from_canonical_u32(1 << 8);

        let zero: AB::Expr = AB::F::zero().into();
        let one: AB::Expr = AB::F::one().into();
        let byte_mask = AB::F::from_canonical_u8(BYTE_MASK);

        // Calculate the MSBs.
        let (b_msb, c_msb) = {
            let msb_pairs =
                [(local.b_msb, local.b[WORD_SIZE - 1]), (local.c_msb, local.c[WORD_SIZE - 1])];
            let opcode = AB::F::from_canonical_u32(ByteOpcode::MSB as u32);
            for msb_pair in msb_pairs.iter() {
                let msb = msb_pair.0;
                let byte = msb_pair.1;
                builder.send_byte(opcode, msb, byte, zero.clone(), local.is_real);
            }
            (local.b_msb, local.c_msb)
        };

        // Calculate whether to extend b and c's sign.
        let (b_sign_extend, c_sign_extend) = {
            // MULH or MULHSU
            let is_b_i32 = local.is_mulh + local.is_mulhsu - local.is_mulh * local.is_mulhsu;

            let is_c_i32 = local.is_mulh;

            builder.assert_eq(local.b_sign_extend, is_b_i32 * b_msb);
            builder.assert_eq(local.c_sign_extend, is_c_i32 * c_msb);
            (local.b_sign_extend, local.c_sign_extend)
        };

        // Sign extend local.b and local.c whenever appropriate.
        let (b, c) = {
            let mut b: Vec<AB::Expr> = vec![AB::F::zero().into(); LONG_WORD_SIZE];
            let mut c: Vec<AB::Expr> = vec![AB::F::zero().into(); LONG_WORD_SIZE];
            for i in 0..LONG_WORD_SIZE {
                if i < WORD_SIZE {
                    b[i] = local.b[i].into();
                    c[i] = local.c[i].into();
                } else {
                    b[i] = b_sign_extend * byte_mask;
                    c[i] = c_sign_extend * byte_mask;
                }
            }
            (b, c)
        };

        // Compute the uncarried product b(x) * c(x) = m(x).
        let mut m: Vec<AB::Expr> = vec![AB::F::zero().into(); LONG_WORD_SIZE];
        for i in 0..LONG_WORD_SIZE {
            for j in 0..LONG_WORD_SIZE {
                if i + j < LONG_WORD_SIZE {
                    m[i + j] = m[i + j].clone() + b[i].clone() * c[j].clone();
                }
            }
        }

        // Propagate carry.
        let product = {
            for i in 0..LONG_WORD_SIZE {
                if i == 0 {
                    builder.assert_eq(local.product[i], m[i].clone() - local.carry[i] * base);
                } else {
                    builder.assert_eq(
                        local.product[i],
                        m[i].clone() + local.carry[i - 1] - local.carry[i] * base,
                    );
                }
            }
            local.product
        };

        // Compare the product's appropriate bytes with that of the result.
        // This constraint is only done when `op_a_not_0 == 1`.
        {
            let is_lower = local.is_mul;
            let is_upper = local.is_mulh + local.is_mulhu + local.is_mulhsu;
            for i in 0..WORD_SIZE {
                builder.when(local.op_a_not_0).when(is_lower).assert_eq(product[i], local.a[i]);
                builder
                    .when(local.op_a_not_0)
                    .when(is_upper.clone())
                    .assert_eq(product[i + WORD_SIZE], local.a[i]);
            }
        }

        // Check that the boolean values are indeed boolean values.
        {
            let booleans = [
                local.b_msb,
                local.c_msb,
                local.b_sign_extend,
                local.c_sign_extend,
                local.is_mul,
                local.is_mulh,
                local.is_mulhu,
                local.is_mulhsu,
                local.is_real,
            ];
            for boolean in booleans.iter() {
                builder.assert_bool(*boolean);
            }
        }

        // If signed extended, the MSB better be 1.
        builder.when(local.b_sign_extend).assert_eq(local.b_msb, one.clone());
        builder.when(local.c_sign_extend).assert_eq(local.c_msb, one.clone());

        // SAFETY: All selectors `is_mul`, `is_mulh`, `is_mulhu`, `is_mulhsu` are checked to be boolean.
        // Also, the multiplicity `is_real` is checked to be boolean, and `is_real = 0` leads to no interactions.
        // Each "real" row has exactly one selector turned on, as constrained below.
        // Therefore, in "real" rows, the `opcode` matches the corresponding opcode.

        // Calculate the opcode.
        let opcode = {
            // Exactly one of the opcodes must be on.
            builder
                .when(local.is_real)
                .assert_one(local.is_mul + local.is_mulh + local.is_mulhu + local.is_mulhsu);

            let mul: AB::Expr = AB::F::from_canonical_u32(Opcode::MUL as u32).into();
            let mulh: AB::Expr = AB::F::from_canonical_u32(Opcode::MULH as u32).into();
            let mulhu: AB::Expr = AB::F::from_canonical_u32(Opcode::MULHU as u32).into();
            let mulhsu: AB::Expr = AB::F::from_canonical_u32(Opcode::MULHSU as u32).into();
            local.is_mul * mul
                + local.is_mulh * mulh
                + local.is_mulhu * mulhu
                + local.is_mulhsu * mulhsu
        };

        // Range check.
        {
            // Ensure that the carry is at most 2^16. This ensures that
            // product_before_carry_propagation - carry * base + last_carry never overflows or
            // underflows enough to "wrap" around to create a second solution.
            builder.slice_range_check_u16(&local.carry, local.is_real);

            builder.slice_range_check_u8(&local.product, local.is_real);
        }

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
            opcode,
            local.a,
            local.b,
            local.c,
            AB::Expr::one() - local.op_a_not_0,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_real,
        );

        builder.when(local.op_a_not_0).assert_one(local.is_real);
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{run_malicious_test, uni_stark_prove as prove, uni_stark_verify as verify},
    };
    use p3_baby_bear::BabyBear;
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

    use super::MulChip;

    #[test]
    fn generate_trace_mul() {
        let mut shard = ExecutionRecord::default();

        // Fill mul_events with 10^7 MULHSU events.
        let mut mul_events: Vec<AluEvent> = Vec::new();
        for _ in 0..10i32.pow(7) {
            mul_events.push(AluEvent::new(
                0,
                Opcode::MULHSU,
                0x80004000,
                0x80000000,
                0xffff8000,
                false,
            ));
        }
        shard.mul_events = mul_events;
        let chip = MulChip::default();
        let _trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        let mut mul_events: Vec<AluEvent> = Vec::new();

        let mul_instructions: Vec<(Opcode, u32, u32, u32)> = vec![
            (Opcode::MUL, 0x00001200, 0x00007e00, 0xb6db6db7),
            (Opcode::MUL, 0x00001240, 0x00007fc0, 0xb6db6db7),
            (Opcode::MUL, 0x00000000, 0x00000000, 0x00000000),
            (Opcode::MUL, 0x00000001, 0x00000001, 0x00000001),
            (Opcode::MUL, 0x00000015, 0x00000003, 0x00000007),
            (Opcode::MUL, 0x00000000, 0x00000000, 0xffff8000),
            (Opcode::MUL, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MUL, 0x00000000, 0x80000000, 0xffff8000),
            (Opcode::MUL, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d),
            (Opcode::MUL, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab),
            (Opcode::MUL, 0x00000000, 0xff000000, 0xff000000),
            (Opcode::MUL, 0x00000001, 0xffffffff, 0xffffffff),
            (Opcode::MUL, 0xffffffff, 0xffffffff, 0x00000001),
            (Opcode::MUL, 0xffffffff, 0x00000001, 0xffffffff),
            (Opcode::MULHU, 0x00000000, 0x00000000, 0x00000000),
            (Opcode::MULHU, 0x00000000, 0x00000001, 0x00000001),
            (Opcode::MULHU, 0x00000000, 0x00000003, 0x00000007),
            (Opcode::MULHU, 0x00000000, 0x00000000, 0xffff8000),
            (Opcode::MULHU, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MULHU, 0x7fffc000, 0x80000000, 0xffff8000),
            (Opcode::MULHU, 0x0001fefe, 0xaaaaaaab, 0x0002fe7d),
            (Opcode::MULHU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
            (Opcode::MULHU, 0xfe010000, 0xff000000, 0xff000000),
            (Opcode::MULHU, 0xfffffffe, 0xffffffff, 0xffffffff),
            (Opcode::MULHU, 0x00000000, 0xffffffff, 0x00000001),
            (Opcode::MULHU, 0x00000000, 0x00000001, 0xffffffff),
            (Opcode::MULHSU, 0x00000000, 0x00000000, 0x00000000),
            (Opcode::MULHSU, 0x00000000, 0x00000001, 0x00000001),
            (Opcode::MULHSU, 0x00000000, 0x00000003, 0x00000007),
            (Opcode::MULHSU, 0x00000000, 0x00000000, 0xffff8000),
            (Opcode::MULHSU, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MULHSU, 0x80004000, 0x80000000, 0xffff8000),
            (Opcode::MULHSU, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
            (Opcode::MULHSU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
            (Opcode::MULHSU, 0xff010000, 0xff000000, 0xff000000),
            (Opcode::MULHSU, 0xffffffff, 0xffffffff, 0xffffffff),
            (Opcode::MULHSU, 0xffffffff, 0xffffffff, 0x00000001),
            (Opcode::MULHSU, 0x00000000, 0x00000001, 0xffffffff),
            (Opcode::MULH, 0x00000000, 0x00000000, 0x00000000),
            (Opcode::MULH, 0x00000000, 0x00000001, 0x00000001),
            (Opcode::MULH, 0x00000000, 0x00000003, 0x00000007),
            (Opcode::MULH, 0x00000000, 0x00000000, 0xffff8000),
            (Opcode::MULH, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MULH, 0x00000000, 0x80000000, 0x00000000),
            (Opcode::MULH, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
            (Opcode::MULH, 0xffff0081, 0x0002fe7d, 0xaaaaaaab),
            (Opcode::MULH, 0x00010000, 0xff000000, 0xff000000),
            (Opcode::MULH, 0x00000000, 0xffffffff, 0xffffffff),
            (Opcode::MULH, 0xffffffff, 0xffffffff, 0x00000001),
            (Opcode::MULH, 0xffffffff, 0x00000001, 0xffffffff),
        ];
        for t in mul_instructions.iter() {
            mul_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3, false));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - mul_instructions.len()) {
            mul_events.push(AluEvent::new(0, Opcode::MUL, 1, 1, 1, false));
        }

        shard.mul_events = mul_events;
        let chip = MulChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn test_malicious_mul() {
        const NUM_TESTS: usize = 5;

        for opcode in [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU] {
            for _ in 0..NUM_TESTS {
                let (correct_op_a, op_b, op_c) = if opcode == Opcode::MUL {
                    let op_b = thread_rng().gen_range(0..i32::MAX);
                    let op_c = thread_rng().gen_range(0..i32::MAX);
                    ((op_b.overflowing_mul(op_c).0) as u32, op_b as u32, op_c as u32)
                } else if opcode == Opcode::MULH {
                    let op_b = thread_rng().gen_range(0..i32::MAX);
                    let op_c = thread_rng().gen_range(0..i32::MAX);
                    let result = (op_b as i64) * (op_c as i64);
                    (((result >> 32) as i32) as u32, op_b as u32, op_c as u32)
                } else if opcode == Opcode::MULHU {
                    let op_b = thread_rng().gen_range(0..u32::MAX);
                    let op_c = thread_rng().gen_range(0..u32::MAX);
                    let result: u64 = (op_b as u64) * (op_c as u64);
                    ((result >> 32) as u32, op_b as u32, op_c as u32)
                } else if opcode == Opcode::MULHSU {
                    let op_b = thread_rng().gen_range(0..i32::MAX);
                    let op_c = thread_rng().gen_range(0..u32::MAX);
                    let result: i64 = (op_b as i64) * (op_c as i64);
                    ((result >> 32) as u32, op_b as u32, op_c as u32)
                } else {
                    unreachable!()
                };

                let op_a = thread_rng().gen_range(0..u32::MAX);
                assert!(op_a != correct_op_a);

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
                    malicious_record.mul_events[0].a = op_a;
                    prover.generate_traces(&malicious_record)
                };

                let result =
                    run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
                let mul_chip_name = chip_name!(MulChip, BabyBear);
                assert!(
                    result.is_err() && result.unwrap_err().is_constraints_failing(&mul_chip_name)
                );
            }
        }
    }
}
