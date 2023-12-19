//! Implementation to check that b * c = product. (no `mod N`, no truncation)
//!
//! Decompose b, c, product into u8's. Perform the appropriate range checks.
//!
//! 1. Use m[i] to denote the convolution (i.e., b[i]c[0] + b[i - 1]c[1] +
//!    ... + b[1]c[i - 1] + b[0]c[i]).
//! 2. carry[i]: "overflow" from calculating the i-th term. More
//!    specifically, carry[i] = floor((m[i] + carry[i - 1]) / 256).
//
//! local.product[i] = m[i] + carry[i - 1] (mod 256)
//! <=> local.product[i] = m[i] + carry[i - 1] - 256K for some integer K
//! <=> local.product[i]
//!    = m[i] + carry[i - 1] - 256 * floor((m[i] + carry[i - 1]) / 256)
//
//! Conveniently, this value of K is equivalent to carry[i].
//!
//! Finally, we verify that the result `a` matches the appropriate bits.
//! (e.g., For MUL, `a` matches the low word of `local.product`)

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};
use crate::disassembler::WORD_SIZE;
use crate::runtime::{Opcode, Runtime};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_MUL_COLS: usize = size_of::<MulCols<u8>>();

// The number of digits in the product is at most the sum of the number of
// digits in the multiplicands.
const PRODUCT_SIZE: usize = 2 * WORD_SIZE;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
pub struct MulCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace.
    pub carry: [T; PRODUCT_SIZE],

    /// `product` stores the actual product of b * c without truncating.
    pub product: [T; PRODUCT_SIZE],

    /// Selector to know whether this row is enabled.
    pub is_real: T,

    // Whether the output is the upper half or the lower half of b * c.
    pub is_upper: T,
}

/// A chip that implements addition for the opcodes MUL.
pub struct MulChip;

impl MulChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for MulChip {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = runtime
            .mul_events
            .par_iter()
            .map(|event| {
                assert!(event.opcode == Opcode::MUL || event.opcode == Opcode::MULHU);
                let mut row = [F::zero(); NUM_MUL_COLS];
                let cols: &mut MulCols<F> = unsafe { transmute(&mut row) };
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                let mut product = [0u32; PRODUCT_SIZE];

                for i in 0..WORD_SIZE {
                    for j in 0..WORD_SIZE {
                        product[i + j] += (b[i] as u32) * (c[j] as u32);
                    }
                }
                for i in 0..PRODUCT_SIZE {
                    cols.product[i] = F::from_canonical_u32(product[i] & 0xff);
                    cols.carry[i] = F::from_canonical_u32(product[i] >> 8);
                    if i + 1 < PRODUCT_SIZE {
                        product[i + 1] += product[i] >> 8;
                    }
                }
                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));
                cols.is_real = F::one();

                // - MUL: unsigned x unsigned and take the lower half.
                // - MULHU: unsigned x unsigned and take the upper half.
                cols.is_upper = F::from_bool(event.opcode == Opcode::MULHU);
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_MUL_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MUL_COLS, F>(&mut trace.values);

        trace
    }
}

impl<F> BaseAir<F> for MulChip {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<AB> Air<AB> for MulChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MulCols<AB::Var> = main.row_slice(0).borrow();
        let base = AB::F::from_canonical_u32(1 << 8);
        let one: AB::Expr = AB::F::one().into();

        // Compute the uncarried product b(x) * c(x) = m(x).
        const UNCARRIED_PRODUCT_SIZE: usize = 2 * WORD_SIZE - 1;
        let mut m: Vec<AB::Expr> = vec![AB::F::zero().into(); UNCARRIED_PRODUCT_SIZE];
        for i in 0..WORD_SIZE {
            for j in 0..WORD_SIZE {
                m[i + j] += local.b[i] * local.c[j];
            }
        }

        // Compute the carried product by decomposing each coefficient of m(x)
        // into some carry and product. Note that we must assume that the carry
        // is range checked to avoid underflow.
        for i in 0..PRODUCT_SIZE {
            if i == 0 {
                // When i = 0, there is no carry from the previous term as
                // there is no previous term.
                builder.assert_eq(local.product[i], m[i].clone() - local.carry[i] * base);
            } else if i < PRODUCT_SIZE - 1 {
                // When 0 < i < PRODUCT_SIZE - 1, there is a carry from the
                // previous term, and there's a carry from this term.
                builder.assert_eq(
                    local.product[i],
                    m[i].clone() + local.carry[i - 1] - local.carry[i] * base,
                );
            } else {
                // The highest term can only be the carry from the previous
                // term since there is not b[k]c[l] such that k + l == i.
                builder.assert_eq(local.product[i], local.carry[i - 1]);
            }
        }

        // Assert that the upper or lower half word of the product matches the result.
        for i in 0..WORD_SIZE {
            builder.assert_eq(
                local.is_upper * local.product[i + WORD_SIZE]
                    + (one.clone() - local.is_upper) * local.product[i],
                local.a[i],
            );
        }

        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_upper);

        // Receive the arguments.
        builder.receive_alu(
            AB::F::from_canonical_u32(Opcode::MUL as u32),
            local.a,
            local.b,
            local.c,
            local.is_real,
        );

        // TODO: Range check the carry column.

        // A dummy constraint to keep the degree at least 3.
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
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
    use p3_matrix::dense::RowMajorMatrix;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use p3_uni_stark::{prove, verify, StarkConfigImpl};
    use rand::thread_rng;

    use crate::{
        alu::AluEvent,
        runtime::{Opcode, Runtime},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::MulChip;

    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program, 0);
        runtime.add_events = vec![AluEvent::new(0, Opcode::MUL, 100000, 500, 200)];
        let chip = MulChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
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
        let mut mul_events: Vec<AluEvent> = Vec::new();

        const MUL_TEST_LENGTH: usize = 26;
        let mul_instructions: [(Opcode, u32, u32, u32); MUL_TEST_LENGTH] = [
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
        ];
        for t in mul_instructions.iter() {
            mul_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - MUL_TEST_LENGTH) {
            mul_events.push(AluEvent::new(0, Opcode::MUL, 1, 1, 1));
        }

        runtime.mul_events = mul_events;
        let chip = MulChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
