use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use itertools::izip;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField;
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use sp1_derive::AlignedBorrow;
use tracing::instrument;

use crate::air::{BaseAirBuilder, MachineAir};
use crate::air::{SP1AirBuilder, Word};
use crate::runtime::{ExecutionRecord, Opcode, Program};
use crate::utils::pad_to_power_of_two;

/// The number of main trace columns for `LtChip`.
pub const NUM_LT_COLS: usize = size_of::<LtCols<u8>>();

/// A chip that implements bitwise operations for the opcodes SLT and SLTU.
#[derive(Default)]
pub struct LtChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct LtCols<T> {
    /// The shard number, used for byte lookup table.
    pub shard: T,

    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Boolean flag to indicate which byte pair differs if the operands are not equal.
    pub byte_flags: [T; 4],

    /// The masking b[3] & 0x7F.
    pub b_masked: T,
    /// The masking c[3] & 0x7F.
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

    /// The result of the intermediate SLTU operation.
    pub stlu: T,
    /// A bollean flag for an intermediate comparison.
    pub is_comp_eq: T,
    /// A boolean flag for comparing the sign bits.
    pub is_sign_eq: T,
    /// The comparison bytes to be looked up.
    pub comparison_bytes: [T; 2],

    /// Boolean flag to indicate whether to do an equality check between the bytes.
    ///
    /// This should be true for all bytes smaller than the first byte pair that differs. With LE
    /// bytes, this is all bytes after the differing byte pair.
    pub byte_equality_check: [T; 4],

    /// If the opcode is SLT.
    pub is_slt: T,

    /// If the opcode is SLTU.
    pub is_sltu: T,
}

impl LtCols<u32> {
    pub fn from_trace_row<F: PrimeField32>(row: &[F]) -> Self {
        let sized: [u32; NUM_LT_COLS] = row
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        *sized.as_slice().borrow()
    }
}

impl<F: PrimeField> MachineAir<F> for LtChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Lt".to_string()
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {}

    #[instrument(name = "generate lt trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = input
            .lt_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_LT_COLS];
                let cols: &mut LtCols<F> = row.as_mut_slice().borrow_mut();
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                cols.shard = F::from_canonical_u32(event.shard);
                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));

                // If this is SLT, mask the MSB of b & c before computing cols.bits.
                let masked_b = b[3] & 0x7f;
                let masked_c = c[3] & 0x7f;
                cols.b_masked = F::from_canonical_u8(masked_b);
                cols.c_masked = F::from_canonical_u8(masked_c);

                let mut b_comp = b;
                let mut c_comp = c;
                if event.opcode == Opcode::SLT {
                    b_comp[3] = masked_b;
                    c_comp[3] = masked_c;
                }
                cols.stlu = F::from_bool(b_comp < c_comp);
                cols.is_comp_eq = F::from_bool(b_comp == c_comp);

                // Set the byte equality flags.
                for (b_byte, c_byte, flag) in izip!(
                    b_comp.iter().rev(),
                    c_comp.iter().rev(),
                    cols.byte_flags.iter_mut().rev()
                ) {
                    if c_byte != b_byte {
                        *flag = F::one();
                        cols.stlu = F::from_bool(b_byte < c_byte);
                        cols.not_eq_inv = F::from_canonical_u8(b_byte - c_byte).inverse();
                        cols.comparison_bytes = [*b_byte, *c_byte].map(F::from_canonical_u8);
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

                assert_eq!(
                    cols.a[0],
                    cols.bit_b * (F::one() - cols.bit_c) + cols.is_sign_eq * cols.stlu
                );

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_LT_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_LT_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.lt_events.is_empty()
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

        // Dummy degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        );

        // We can compute the signed set-less-than as follows:
        // SLT (signed) = b_s * (1 - c_s) + (b_s == c_s) * SLTU(b_<s, c_<s)
        // Source: Jolt 5.3: Set Less Than (https://people.cs.georgetown.edu/jthaler/Jolt-paper.pdf)

        // We will compute SLTU(b_comp, c_comp) where `b_comp` and `c_comp` where:
        // * if the operation is `STLU`, `b_comp = b` and `c_comp = c`
        // * if the operation is `STL`, `b_comp = b & 0x7FFFFFFF` and `c_comp = c & 0x7FFFFFFF``
        //
        // We will set booleans `b_bit` and `c_bit` so that:
        // * If the operation is `STLU`, then `b_bit = 0` and `c_bit = 0`.
        // * If the operation is `STL`, then `b_bit`, `c_bit` are the most significant bits of `b`
        //   and `c` respectively.
        //
        // Then, we will compute the answer as:
        // SLT = b_bit * (1 - c_bit) + (b_bit == c_bit) * SLTU(b_comp, c_comp)

        // First, we set up the values of `b_comp` and `c_comp`.
        let mut b_comp: Word<AB::Expr> = local.b.map(|x| x.into());
        let mut c_comp: Word<AB::Expr> = local.c.map(|x| x.into());

        b_comp[3] = local.b[3] * local.is_sltu + local.b_masked * local.is_slt;
        c_comp[3] = local.c[3] * local.is_sltu + local.c_masked * local.is_slt;

        // Constrain `local.stlu == STLU(b_comp, c_comp)`.
        builder.assert_bool(local.stlu);

        // Set the values of `b_bit` and `c_bit`.
        builder.assert_eq(local.bit_b, local.msb_b * local.is_slt);
        builder.assert_eq(local.bit_c, local.msb_c * local.is_slt);

        // Constrain that when is_sign_eq = (bit_b == bit_c).
        builder
            .when(local.is_sign_eq)
            .assert_eq(local.bit_b, local.bit_c);
        builder
            .when(is_real.clone())
            .when_not(local.is_sign_eq)
            .assert_one(local.bit_b + local.bit_c);

        // Assert the result `a` is correct. First, check that `a` is set correctly:
        builder.assert_eq(
            local.a[0],
            local.bit_b * (AB::Expr::one() - local.bit_c) + local.is_sign_eq * local.stlu,
        );
        // Check the 3 most significant bytes of 'a' are zero.
        builder.assert_zero(local.a[1]);
        builder.assert_zero(local.a[2]);
        builder.assert_zero(local.a[3]);

        // Verify that the byte equality flags are set correctly, i.e. all are boolean and only
        // a single byte pair is set.
        let sum_flags =
            local.byte_flags[0] + local.byte_flags[1] + local.byte_flags[2] + local.byte_flags[3];
        builder.assert_bool(local.byte_flags[0]);
        builder.assert_bool(local.byte_flags[1]);
        builder.assert_bool(local.byte_flags[2]);
        builder.assert_bool(local.byte_flags[3]);
        builder.assert_bool(sum_flags.clone());
        builder
            .when(is_real.clone())
            .assert_eq(AB::Expr::one() - local.is_comp_eq, sum_flags);

        // Now we constrain the correct value of `stlu`.

        // A flag to indicate whether an equality check is necessary (this is for all bytes from
        // most significant until the first inequality.
        let mut is_inequality_visited = AB::Expr::zero();

        let mut b_comparison_byte = AB::Expr::zero();
        let mut c_comparison_byte = AB::Expr::zero();

        for (b_byte, c_byte, &flag) in izip!(
            b_comp.0.iter().rev(),
            c_comp.0.iter().rev(),
            local.byte_flags.iter().rev()
        ) {
            // Once the byte flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited += flag.into();

            b_comparison_byte += b_byte.clone() * flag;
            c_comparison_byte += c_byte.clone() * flag;

            builder
                .when_not(is_inequality_visited.clone())
                .assert_eq(b_byte.clone(), c_byte.clone());
        }

        // Constrain the values of the most significant bits.
        builder.assert_bool(local.msb_b);
        builder.assert_bool(local.msb_c);

        // Check that the operation flags are boolean.
        builder.assert_bool(local.is_slt);
        builder.assert_bool(local.is_sltu);
        // Check that at most one of the operation flags is set.
        // *remark*: this is not strictly necessary since it's also covered by the bus multiplicity
        // but this is included here to make sure the condition is met.
        builder.assert_bool(local.is_slt + local.is_sltu);

        // Receive the arguments.
        builder.receive_alu(
            local.is_slt * AB::F::from_canonical_u32(Opcode::SLT as u32)
                + local.is_sltu * AB::F::from_canonical_u32(Opcode::SLTU as u32),
            local.a,
            local.b,
            local.c,
            local.shard,
            is_real,
        );
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        air::MachineAir,
        stark::StarkGenericConfig,
        utils::{uni_stark_prove as prove, uni_stark_verify as verify},
    };
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        alu::AluEvent,
        runtime::{ExecutionRecord, Opcode},
        utils::BabyBearPoseidon2,
    };

    use super::LtChip;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.lt_events = vec![AluEvent::new(0, 0, Opcode::SLT, 0, 3, 2)];
        let chip = LtChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
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
            AluEvent::new(0, 0, Opcode::SLT, 0, 3, 2),
            // 1 == 2 < 3
            AluEvent::new(0, 1, Opcode::SLT, 1, 2, 3),
            // 0 == 5 < -3
            AluEvent::new(0, 3, Opcode::SLT, 0, 5, NEG_3),
            // 1 == -3 < 5
            AluEvent::new(0, 2, Opcode::SLT, 1, NEG_3, 5),
            // 0 == -3 < -4
            AluEvent::new(0, 4, Opcode::SLT, 0, NEG_3, NEG_4),
            // 1 == -4 < -3
            AluEvent::new(0, 4, Opcode::SLT, 1, NEG_4, NEG_3),
            // 0 == 3 < 3
            AluEvent::new(0, 5, Opcode::SLT, 0, 3, 3),
            // 0 == -3 < -3
            AluEvent::new(0, 5, Opcode::SLT, 0, NEG_3, NEG_3),
        ];

        prove_babybear_template(&mut shard);
    }

    #[test]
    fn prove_babybear_sltu() {
        let mut shard = ExecutionRecord::default();

        const LARGE: u32 = 0b11111111111111111111111111111101;
        shard.lt_events = vec![
            // 0 == 3 < 2
            AluEvent::new(0, 0, Opcode::SLTU, 0, 3, 2),
            // 1 == 2 < 3
            AluEvent::new(0, 1, Opcode::SLTU, 1, 2, 3),
            // 0 == LARGE < 5
            AluEvent::new(0, 2, Opcode::SLTU, 0, LARGE, 5),
            // 1 == 5 < LARGE
            AluEvent::new(0, 3, Opcode::SLTU, 1, 5, LARGE),
            // 0 == 0 < 0
            AluEvent::new(0, 5, Opcode::SLTU, 0, 0, 0),
            // 0 == LARGE < LARGE
            AluEvent::new(0, 5, Opcode::SLTU, 0, LARGE, LARGE),
        ];

        prove_babybear_template(&mut shard);
    }
}
