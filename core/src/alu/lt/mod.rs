use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField;
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};

use crate::runtime::{Opcode, Runtime};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_LT_COLS: usize = size_of::<LtCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
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

    /// Boolean flag to indicate whether to do an equality check between the bytes. This should be
    /// true for all bytes smaller than the first byte pair that differs. With LE bytes, this is all
    /// bytes after the differing byte pair.
    pub byte_equality_check: [T; 4],

    // Bit decomposition of 256 + b[i] - c[i], where i is the index of the largest byte pair that
    // differs. This value is at most 2^9 - 1, so it can be represented as 10 bits.
    pub bits: [T; 10],

    /// Selector flags for the operation to perform.
    pub is_slt: T,
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
        unsafe { transmute::<[u32; NUM_LT_COLS], LtCols<u32>>(sized) }
    }
}

/// A chip that implements bitwise operations for the opcodes SLT and SLTU.
pub struct LtChip;

impl LtChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for LtChip {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = runtime
            .lt_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_LT_COLS];
                let cols: &mut LtCols<F> = unsafe { transmute(&mut row) };
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));

                // If this is SLT, we'll need to mask the MSB of b & c when computing cols.bits
                let mut masked_b = b.clone();
                let mut masked_c = c.clone();
                masked_b[3] &= 0x7f;
                masked_c[3] &= 0x7f;

                if event.opcode == Opcode::SLT {
                    cols.sign[0] = F::from_canonical_u8(b[3] >> 7);
                    cols.sign[1] = F::from_canonical_u8(c[3] >> 7);
                }

                cols.sign_xor = cols.sign[0] * (F::from_canonical_u16(1) - cols.sign[1])
                    + cols.sign[1] * (F::from_canonical_u16(1) - cols.sign[0]);

                // Find the first byte pair, index i, that differs, and set the byte flag as well as
                // the bits for 256 + b[i] - c[i].

                for i in (0..4).rev() {
                    if b[i] != c[i] {
                        if event.opcode == Opcode::SLT {
                            let z = 256u16 + masked_b[i] as u16 - masked_c[i] as u16;
                            for j in 0..10 {
                                cols.bits[j] = F::from_canonical_u16(z >> j & 1);
                            }
                        } else {
                            let z = 256u16 + b[i] as u16 - c[i] as u16;
                            for j in 0..10 {
                                cols.bits[j] = F::from_canonical_u16(z >> j & 1);
                            }
                        }
                        cols.byte_flag[i] = F::one();

                        for j in (i + 1)..4 {
                            cols.byte_equality_check[j] = F::one();
                        }
                        break;
                    }
                }
                if b == c {
                    let z = 256u16 + b[3] as u16 - c[3] as u16;
                    for i in 0..10 {
                        cols.bits[i] = F::from_canonical_u16(z >> i & 1);
                    }
                    cols.byte_flag[3] = F::one();

                    for i in 0..3 {
                        cols.byte_equality_check[i] = F::one();
                    }
                }


                cols.is_slt = F::from_bool(event.opcode == Opcode::SLT);
                cols.is_sltu = F::from_bool(event.opcode == Opcode::SLTU);

                println!(
                    "a: {:?}, b: {:?}, c: {:?}, byte_flag: {:?}, sign: {:?}, sign_xor: {:?}, byte_equality_check: {:?}, bits: {:?}, is_slt: {:?}, is_sltu: {:?}",
                    cols.a, cols.b, cols.c, cols.byte_flag, cols.sign, cols.sign_xor, cols.byte_equality_check, cols.bits, cols.is_slt, cols.is_sltu
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

            if i == 3 {
                // // If SLT, compare b_masked and c_masked instead of b and c.
                let b_masked = local.b[i] - (AB::Expr::from_canonical_u32(128) * local.sign[0]);
                let c_masked = local.c[i] - (AB::Expr::from_canonical_u32(128) * local.sign[1]);

                let byte_flag_and_slt = local.byte_flag[i] * local.is_slt;
                builder.when(byte_flag_and_slt).assert_eq(
                    AB::Expr::from_canonical_u32(256) + b_masked - c_masked,
                    bit_comp.clone(),
                );

                let byte_flag_and_not_slt = local.byte_flag[i] * (one.clone() - local.is_slt);
                builder.when(byte_flag_and_not_slt).assert_eq(
                    AB::Expr::from_canonical_u32(256) + local.b[i] - local.c[i],
                    bit_comp.clone(),
                );
            } else {
                builder.when(local.byte_flag[i]).assert_eq(
                    AB::Expr::from_canonical_u32(256) + local.b[i] - local.c[i],
                    bit_comp.clone(),
                );
            }

            // builder.assert_bool(local.byte_flag[i]);
        }
        // Verify at most one byte flag is set.
        let flag_sum =
            local.byte_flag[0] + local.byte_flag[1] + local.byte_flag[2] + local.byte_flag[3];
        builder.assert_bool(flag_sum.clone());

        // SLTU (unsigned)
        // SLTU = 1 - bits[8]
        // local.bits = 256 + b - c, so if bits[8] is 0, then b < c.
        let computed_is_sltu = AB::Expr::one() - local.bits[8];
        builder
            .when(local.is_sltu)
            .assert_eq(local.a[0], computed_is_sltu.clone());

        // SLT (signed)
        // b_s and c_s are the sign bits.
        // b_<s, c_<s are b, c after masking the MSB.
        // SLT = b_s * (1 - c_s) + EQ(b_s, c_s) * SLTU(b_<s, c_<s)
        // Source: Jolt 5.3: Set Less Than (https://people.cs.georgetown.edu/jthaler/Jolt-paper.pdf)
        builder.assert_bool(local.sign[0]);
        builder.assert_bool(local.sign[1]);
        let only_b_neg = local.sign[0] * (one.clone() - local.sign[1]);

        // Assert local.is_neq_sign was computed correctly.
        builder.assert_eq(
            local.sign_xor,
            local.sign[0] * (one.clone() - local.sign[1])
                + local.sign[1] * (one.clone() - local.sign[0]),
        );
        // SLT = b_s * (1 - c_s) + EQ(b_s, c_s) * SLTU(b_<s, c_<s)
        // Note: EQ(b_s, c_s) = 1 - is_neq_sign
        let computed_is_slt =
            only_b_neg.clone() + ((one.clone() - local.sign_xor) * computed_is_sltu.clone());
        // Assert computed_is_slt matches the output.
        builder
            .when(local.is_slt)
            .assert_eq(local.a[0], computed_is_slt.clone());

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
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_matrix::{dense::RowMajorMatrix, MatrixRowSlices};
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use p3_uni_stark::{prove, verify, StarkConfigImpl};
    use rand::thread_rng;

    use crate::{
        alu::{AluEvent, LtCols},
        runtime::{Opcode, Program, Runtime},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::LtChip;

    #[test]
    fn generate_trace() {
        let instructions = vec![];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);
        runtime.lt_events = vec![AluEvent::new(0, Opcode::SLT, 0, 3, 2)];
        let chip = LtChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);

        let num_rows = trace.values.len() / trace.width;
        for i in 0..num_rows {
            let cols = LtCols::<u32>::from_trace_row(trace.row_slice(i));
            let only_b_neg = cols.sign[0] * (1 - cols.sign[1]);
            let equal_sign = cols.sign[0] * cols.sign[1] + (1 - cols.sign[0]) * (1 - cols.sign[1]);
            let computed_is_lt = only_b_neg + (equal_sign * (1 - cols.bits[8]));
            assert_eq!(cols.a[0], computed_is_lt);
        }
    }

    fn prove_babybear_template(runtime: &mut Runtime) {
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

        let chip = LtChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn prove_babybear_slt() {
        let instructions = vec![];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);

        const NEG_3: u32 = 0b11111111111111111111111111111101;
        const NEG_4: u32 = 0b11111111111111111111111111111100;
        runtime.lt_events = vec![
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

        prove_babybear_template(&mut runtime);
    }

    #[test]
    fn prove_babybear_sltu() {
        let instructions = vec![];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);

        const LARGE: u32 = 0b11111111111111111111111111111101;
        runtime.lt_events = vec![
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

        prove_babybear_template(&mut runtime);
    }
}
