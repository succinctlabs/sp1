use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field, PrimeField32};
use p3_field::{PackedField, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::{MatrixRowSlices, MatrixRows};
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

    /// Sign bits of MSG
    pub sign: [T; 2],

    /// Boolean flag to indicate whether to do an equality check between the bytes (after the byte that differs, this should be false)
    pub byte_equality_check: [T; 4],

    // Bit decomposition of 256 + input_1 - input_2
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

/// A chip that implements bitwise operations for the opcodes SLT, SLTI, SLTU, and SLTIU.
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
                let mut b = event.b.to_le_bytes();
                let mut c = event.c.to_le_bytes();

                // If the operands are signed, get and then mask the MSB of b & c.
                if event.opcode == Opcode::SLT || event.opcode == Opcode::SLTI {
                    cols.sign[0] = F::from_canonical_u8(b[3] >> 7);
                    cols.sign[1] = F::from_canonical_u8(c[3] >> 7);
                    b[3] = b[3] & (0b0111_1111);
                    c[3] = c[3] & (0b0111_1111);
                }

                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));

                b.reverse();
                c.reverse();

                // TODO: Add a byte_check flag to skip equality check for bytes after the byte flag.
                if let Some(n) = b
                    .into_iter()
                    .zip(c.into_iter())
                    .enumerate()
                    .find_map(|(n, (x, y))| if x != y { Some(n) } else { None })
                {
                    let z = 256u16 + b[n] as u16 - c[n] as u16;
                    for i in 0..10 {
                        cols.bits[i] = F::from_canonical_u16(z >> i & 1);
                    }
                    cols.byte_flag[n] = F::one();

                    for i in 0..n {
                        cols.byte_equality_check[i] = F::one();
                    }
                }

                // Reverse cols.byte_flag from BE to match the LE byte order of a, b and c.
                cols.byte_flag.reverse();
                cols.byte_equality_check.reverse();

                println!("A: {:?}, B: {:?}, C: {:?}", cols.a, cols.b, cols.c);
                // println!("Sign: {:?} {:?}", cols.sign[0], cols.sign[1]);
                // println!("Bits: {:?}", cols.bits);
                // println!("Byte flag: {:?}", cols.byte_flag);
                // println!("Byte equality check: {:?}", cols.byte_equality_check);

                cols.is_slt = F::from_bool(event.opcode == Opcode::SLT);
                cols.is_sltu = F::from_bool(event.opcode == Opcode::SLTU);
                // println!("IS_SLT: {:?}", cols.is_slt);
                // println!("IS_SLTU: {:?}", cols.is_sltu);

                // Compute the expected result.
                let computed_is_ltu = F::from_canonical_u16(1) - cols.bits[8];
                println!("Computed IS_SLTU: {:?}", computed_is_ltu);

                let only_b_neg = cols.sign[0] * (F::from_canonical_u16(1) - cols.sign[1]);
                let equal_sign = cols.sign[0] * cols.sign[1]
                    + (F::from_canonical_u16(1) - cols.sign[0])
                        * (F::from_canonical_u16(1) - cols.sign[1]);
                let computed_is_lt: F = only_b_neg + (equal_sign * computed_is_ltu.clone());
                println!("Computed IS_SLT: {:?}", computed_is_lt);

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

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
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

            builder.when(local.byte_flag[i]).assert_eq(
                AB::Expr::from_canonical_u32(256) + local.b[i] - local.c[i],
                bit_comp.clone(),
            );

            builder.assert_bool(local.byte_flag[i]);
        }
        // Verify at most one byte flag is set.
        let flag_sum =
            local.byte_flag[0] + local.byte_flag[1] + local.byte_flag[2] + local.byte_flag[3];
        builder.assert_bool(flag_sum.clone());

        let computed_is_ltu = AB::Expr::one() - local.bits[8];
        builder.assert_bool(computed_is_ltu.clone());
        // Output constraints
        // SLTU
        builder
            .when(local.is_sltu)
            .assert_eq(local.a[0], computed_is_ltu.clone());

        // SLT
        // b_s and c_s are sign bits.
        // b_<s and c_<s are b and c after the MSB is masked.
        // LTS = b_s * (1 - c_s) + EQ(b_s, c_s) * SLTU(b_<s, c_<s)
        builder.assert_bool(local.sign[0]);
        builder.assert_bool(local.sign[1]);
        let only_b_neg = local.sign[0] * (one.clone() - local.sign[1]);
        // builder.when(only_b_neg).assert_one(local.a[0]);

        let equal_sign = local.sign[0] * local.sign[1]
            + (one.clone() - local.sign[0]) * (one.clone() - local.sign[1]);
        let computed_is_lt = only_b_neg + (equal_sign.clone() * computed_is_ltu.clone());
        builder.assert_zero(local.is_slt * local.a[0] - local.is_slt * computed_is_lt.clone());
        // builder.assert_eq(local.is_slt * local.a[0], local.is_slt * computed_is_lt);

        // Check bit decomposition is valid.
        builder.assert_bool(local.a[0]);
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
    use std::borrow::Borrow;

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
        alu::{lt::LtCols, AluEvent},
        runtime::{Opcode, Runtime},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::LtChip;

    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program, 0);
        runtime.lt_events = vec![AluEvent::new(0, Opcode::SLT, 0, 3, 2)];
        let chip = LtChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);

        // let only_b_neg = local.sign[0] * (one.clone() - local.sign[1]);
        // // builder.when(only_b_neg).assert_one(local.a[0]);

        // let equal_sign = local.sign[0] * local.sign[1]
        //     + (one.clone() - local.sign[0]) * (one.clone() - local.sign[1]);
        // let computed_is_lt: AB::Expr = only_b_neg + (equal_sign.clone() * computed_is_ltu.clone());
        // builder
        //     .when(local.is_slt)
        //     .assert_eq(local.a[0], computed_is_lt);

        // builder.assert_eq(local.is_slt * local.a[0], local.is_slt * computed_is_lt);

        let num_rows = trace.values.len() / trace.width;
        for i in 0..num_rows {
            let cols = LtCols::<u32>::from_trace_row(trace.row_slice(i));
            let only_b_neg = cols.sign[0] * (1 - cols.sign[1]);
            println!("{}", only_b_neg);
            let equal_sign = cols.sign[0] * cols.sign[1] + (1 - cols.sign[0]) * (1 - cols.sign[1]);
            let computed_is_lt = only_b_neg + (equal_sign * (1 - cols.bits[8]));
            println!("{} {} {}", cols.is_slt, cols.a[0], computed_is_lt);
            println!(
                "{} {}",
                cols.is_slt * cols.a[0],
                cols.is_slt * computed_is_lt
            );
        }
    }

    #[test]
    fn prove_babybear_lt() {
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

        let program = vec![];
        let mut runtime = Runtime::new(program, 0);
        // runtime.lt_events = vec![AluEvent::new(0, Opcode::SLT, 0, 3, 2)].repeat(1000);
        runtime.lt_events = vec![
            AluEvent::new(0, Opcode::SLTU, 0, 3, 2),
            // AluEvent::new(1, Opcode::SLT, 1, 2, 3),
            // AluEvent::new(
            //     2,
            //     Opcode::SLT,
            //     0,
            //     // -3
            //     0b11111111111111111111111111111101,
            //     // -4
            //     0b11111111111111111111111111111100,
            // ),
            // AluEvent::new(3, Opcode::SLT, 0, 65536, 255),
            // AluEvent::new(4, Opcode::SLT, 1, 255, 65536),
            //  1 == -3 < 5
            // AluEvent::new(0, Opcode::SLT, 1, 0b11111111111111111111111111111101, 5),
        ];
        // .repeat(10);
        let chip = LtChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
