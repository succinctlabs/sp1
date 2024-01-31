use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField;
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use p3_maybe_rayon::prelude::*;
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};

use crate::runtime::{Opcode, Segment};
use crate::utils::{pad_to_power_of_two, Chip};

/// The number of main trace columns for `LtChip`.
pub const NUM_LT_COLS: usize = size_of::<LtCols<u8>>();

/// A chip that implements bitwise operations for the opcodes SLT and SLTU.
#[derive(Default)]
pub struct LtChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct LtCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Boolean flag to indicate which byte pair differs
    pub byte_flag: [T; 4],

    /// Sign bits of MSB
    pub sign: [T; 2],

    // Boolean flag to indicate whether the sign bits of b and c are equal.
    pub sign_xor: T,

    /// Boolean flag to indicate whether to do an equality check between the bytes.
    ///
    /// This should be true for all bytes smaller than the first byte pair that differs. With LE
    /// bytes, this is all bytes after the differing byte pair.
    pub byte_equality_check: [T; 4],

    /// Bit decomposition of 256 + b[i] - c[i], where i is the index of the largest byte pair that
    /// differs. This value is at most 2^9 - 1, so it can be represented as 10 bits.
    pub bits: [T; 10],

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

impl<F: PrimeField> Chip<F> for LtChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = segment
            .lt_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_LT_COLS];
                let cols: &mut LtCols<F> = row.as_mut_slice().borrow_mut();
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));

                // If this is SLT, mask the MSB of b & c before computing cols.bits.
                let mut masked_b = b;
                let mut masked_c = c;
                masked_b[3] &= 0x7f;
                masked_c[3] &= 0x7f;

                // If this is SLT, set the sign bits of b and c.
                if event.opcode == Opcode::SLT {
                    cols.sign[0] = F::from_canonical_u8(b[3] >> 7);
                    cols.sign[1] = F::from_canonical_u8(c[3] >> 7);
                }

                cols.sign_xor = cols.sign[0] * (F::from_canonical_u16(1) - cols.sign[1])
                    + cols.sign[1] * (F::from_canonical_u16(1) - cols.sign[0]);

                // Starting from the largest byte, find the first byte pair, index i that differs.
                let equal_bytes = b == c;
                // Defaults to the first byte in BE if the bytes are equal.
                let mut idx_to_check = 3;
                // Find the first byte pair that differs in BE.
                for i in (0..4).rev() {
                    if b[i] != c[i] {
                        idx_to_check = i;
                        break;
                    }
                }

                // If this is SLT, masked_b and masked_c are used for cols.bits instead of b
                // and c.
                if event.opcode == Opcode::SLT {
                    let z = 256u16 + masked_b[idx_to_check] as u16 - masked_c[idx_to_check] as u16;
                    for j in 0..10 {
                        cols.bits[j] = F::from_canonical_u16(z >> j & 1);
                    }
                } else {
                    let z = 256u16 + b[idx_to_check] as u16 - c[idx_to_check] as u16;
                    for j in 0..10 {
                        cols.bits[j] = F::from_canonical_u16(z >> j & 1);
                    }
                }
                // byte_flag marks the byte which cols.bits is computed from.
                cols.byte_flag[idx_to_check] = F::one();

                // byte_equality_check marks the bytes that should be checked for equality (i.e.
                // all bytes after the first byte pair that differs in BE).
                // Note: If b and c are equal, set byte_equality_check to true for all bytes.
                for i in 0..4 {
                    if i > idx_to_check || equal_bytes {
                        cols.byte_equality_check[i] = F::one();
                    }
                }

                cols.is_slt = F::from_bool(event.opcode == Opcode::SLT);
                cols.is_sltu = F::from_bool(event.opcode == Opcode::SLTU);

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

    fn name(&self) -> String {
        "Lt".to_string()
    }
}

impl<F> BaseAir<F> for LtChip {
    fn width(&self) -> usize {
        NUM_LT_COLS
    }
}

impl<AB> Air<AB> for LtChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &LtCols<AB::Var> = main.row_slice(0).borrow();

        let one = AB::Expr::one();

        // Dummy degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        );

        let base_2 = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512].map(AB::F::from_canonical_u32);
        let bit_comp: AB::Expr = local
            .bits
            .into_iter()
            .zip(base_2)
            .map(|(bit, base)| bit * base)
            .sum();

        for i in 0..4 {
            let check_eq = (one.clone() - local.byte_flag[i]) * local.byte_equality_check[i];
            builder.when(check_eq).assert_eq(local.b[i], local.c[i]);

            // In the largest byte, the top bit will be masked if this is an SLT operation.
            if i == 3 {
                // If SLTU, verify bits = 256 + b[i] - c[i].
                let byte_flag_and_sltu = local.byte_flag[3] * local.is_sltu;
                builder.when(byte_flag_and_sltu).assert_eq(
                    AB::Expr::from_canonical_u32(256) + local.b[3] - local.c[3],
                    bit_comp.clone(),
                );

                // If SLT, use b_masked and c_masked instead of b and c.
                // bits = 256 + b_masked[i] - c_masked[i]
                // local.b[i] - (128 * local.sign[0]) is equivalent to masking the MSB of b[i].
                let b_masked = local.b[3] - (AB::Expr::from_canonical_u32(128) * local.sign[0]);
                let c_masked = local.c[3] - (AB::Expr::from_canonical_u32(128) * local.sign[1]);

                let byte_flag_and_slt = local.byte_flag[3] * local.is_slt;
                builder.when(byte_flag_and_slt).assert_eq(
                    AB::Expr::from_canonical_u32(256) + b_masked - c_masked,
                    bit_comp.clone(),
                );
            } else {
                builder.when(local.byte_flag[i]).assert_eq(
                    AB::Expr::from_canonical_u32(256) + local.b[i] - local.c[i],
                    bit_comp.clone(),
                );
            }

            builder.assert_bool(local.byte_flag[i]);
            builder.assert_bool(local.byte_equality_check[i])
        }
        // Verify at most one byte flag is set.
        let flag_sum =
            local.byte_flag[0] + local.byte_flag[1] + local.byte_flag[2] + local.byte_flag[3];
        builder.assert_bool(flag_sum.clone());

        // Compute if b < c. local.bits includes the masking of the MSB of b and c if the operation
        // is SLT. If this is SLTU, there is no masking, so is_b_less_than_c is the final result.
        // local.bits = 256 + b - c, so if bits[8] is 0, then b < c.
        let is_b_less_than_c = AB::Expr::one() - local.bits[8];
        builder
            .when(local.is_sltu)
            .assert_eq(local.a[0], is_b_less_than_c.clone());

        // SLT (signed) = b_s * (1 - c_s) + EQ(b_s, c_s) * SLTU(b_<s, c_<s)
        // SLTU(b_<s, c_<s) is the result of the operation above on masked inputs, is_b_less_than_c.
        // Source: Jolt 5.3: Set Less Than (https://people.cs.georgetown.edu/jthaler/Jolt-paper.pdf)

        // local.sign[0] (b_s) and local.sign[1] (c_s) are the sign bits of b and c respectively.
        builder.assert_bool(local.sign[0]);
        builder.assert_bool(local.sign[1]);
        let only_b_neg = local.sign[0] * (one.clone() - local.sign[1]);

        // Assert local.sign_xor is the XOR of the sign bits.
        builder.assert_eq(
            local.sign_xor,
            local.sign[0] * (one.clone() - local.sign[1])
                + local.sign[1] * (one.clone() - local.sign[0]),
        );
        // Note: EQ(b_s, c_s) = 1 - sign_xor
        let signed_is_b_less_than_c =
            only_b_neg.clone() + ((one.clone() - local.sign_xor) * is_b_less_than_c.clone());

        // Assert signed_is_b_less_than_c matches the output.
        builder
            .when(local.is_slt)
            .assert_eq(local.a[0], signed_is_b_less_than_c.clone());

        // Check output bits and bit decomposition are valid.
        builder.assert_bool(local.a[0]);
        for i in 1..4 {
            builder.assert_zero(local.a[i]);
        }
        for bit in local.bits.into_iter() {
            builder.assert_bool(bit);
        }

        // Receive the arguments.
        builder.receive_alu(
            local.is_slt * AB::F::from_canonical_u32(Opcode::SLT as u32)
                + local.is_sltu * AB::F::from_canonical_u32(Opcode::SLTU as u32),
            local.a,
            local.b,
            local.c,
            local.is_slt + local.is_sltu,
        );
    }
}

#[cfg(test)]
mod tests {

    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::thread_rng;

    use crate::{
        alu::AluEvent,
        runtime::{Opcode, Segment},
        utils::{BabyBearPoseidon2, Chip, StarkUtils},
    };

    use super::LtChip;

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.lt_events = vec![AluEvent::new(0, Opcode::SLT, 0, 3, 2)];
        let chip = LtChip::default();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values)
    }

    fn prove_babybear_template(segment: &mut Segment) {
        let config = BabyBearPoseidon2::new(&mut thread_rng());
        let mut challenger = config.challenger();

        let chip = LtChip::default();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(segment);
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn prove_babybear_slt() {
        let mut segment = Segment::default();

        const NEG_3: u32 = 0b11111111111111111111111111111101;
        const NEG_4: u32 = 0b11111111111111111111111111111100;
        segment.lt_events = vec![
            // 0 == 3 < 2
            AluEvent::new(0, Opcode::SLT, 0, 3, 2),
            // 1 == 2 < 3
            AluEvent::new(1, Opcode::SLT, 1, 2, 3),
            // 0 == 5 < -3
            AluEvent::new(3, Opcode::SLT, 0, 5, NEG_3),
            // 1 == -3 < 5
            AluEvent::new(2, Opcode::SLT, 1, NEG_3, 5),
            // 0 == -3 < -4
            AluEvent::new(4, Opcode::SLT, 0, NEG_3, NEG_4),
            // 1 == -4 < -3
            AluEvent::new(4, Opcode::SLT, 1, NEG_4, NEG_3),
            // 0 == 3 < 3
            AluEvent::new(5, Opcode::SLT, 0, 3, 3),
            // 0 == -3 < -3
            AluEvent::new(5, Opcode::SLT, 0, NEG_3, NEG_3),
        ];

        prove_babybear_template(&mut segment);
    }

    #[test]
    fn prove_babybear_sltu() {
        let mut segment = Segment::default();

        const LARGE: u32 = 0b11111111111111111111111111111101;
        segment.lt_events = vec![
            // 0 == 3 < 2
            AluEvent::new(0, Opcode::SLTU, 0, 3, 2),
            // 1 == 2 < 3
            AluEvent::new(1, Opcode::SLTU, 1, 2, 3),
            // 0 == LARGE < 5
            AluEvent::new(2, Opcode::SLTU, 0, LARGE, 5),
            // 1 == 5 < LARGE
            AluEvent::new(3, Opcode::SLTU, 1, 5, LARGE),
            // 0 == 0 < 0
            AluEvent::new(5, Opcode::SLTU, 0, 0, 0),
            // 0 == LARGE < LARGE
            AluEvent::new(5, Opcode::SLTU, 0, LARGE, LARGE),
        ];

        prove_babybear_template(&mut segment);
    }
}
