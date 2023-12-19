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
use crate::runtime::{Opcode, Runtime};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_MUL_COLS: usize = size_of::<MulCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
pub struct MulCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace. u32::max ** 2 = (2^32 - 1)^ 2 = 63 bits, so we need 8 bytes.
    /// `product` stores the actual product of b * c without truncating.
    pub carry: [T; 8],
    pub product: [T; 8],

    /// Selector to know whether this row is enabled.
    pub is_real: T,
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
                assert!(event.opcode == Opcode::MUL);
                let mut row = [F::zero(); NUM_MUL_COLS];
                let cols: &mut MulCols<F> = unsafe { transmute(&mut row) };
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                let mut product = [0u32; 9];

                for i in 0..4 {
                    for j in 0..4 {
                        product[i + j] += (b[i] as u32) * (c[j] as u32);
                    }
                }
                for i in 0..8 {
                    cols.product[i] = F::from_canonical_u32(product[i] & 0xff);
                    cols.carry[i] = F::from_canonical_u32(product[i] >> 8);
                    product[i + 1] += product[i] >> 8;
                }
                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));
                cols.is_real = F::one();
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

        // A dummy constraint to keep the degree at least 3.
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        );
        // We'll check that b * c = product. Note that, here, we check that
        // this product is _actually_ the product of b * c without any truncation.
        // We first decompose b, c, product into an array of u8's.
        //
        // We check b * c = product by actually calculating what the value of the
        // i-th term of product (i.e., product[i]) should be.
        //
        // We will do so by comparing these pieces of information:
        //
        // 1. local.product[i]: What we think `product[i]` ought to be.
        // 2. BC[i] := b[i]c[0] + b[i - 1]c[1] + ... + b[1]c[i - 1] + b[0]c[i]
        // 3. carry[i]: "overflow" from calculating the i-th term. More
        //    specifically, floor((BC[i] + carry[i - 1]) / 256).
        //
        // local.product[i] is indeed the correct value of product[i] iff
        // local.product[i] = BC[i] + carry[i - 1] (mod 256).
        //
        // local.product[i] = BC[i] + carry[i - 1] (mod 256)
        // <=> local.product[i] = BC[i] + carry[i - 1] + 256K for some integer K
        // <=> local.product[i]
        //    = BC[i] + carry[i - 1] + 256 * floor((BC[i] + carry[i - 1]) / 256)
        //
        // Conveniently, this value of K is equivalent to carry[i]. Therefore,
        // we obtain the necessary and sufficient condition
        // local.product[i] = BC[i] + carry[i - 1] + 256 * carry[i].
        //
        // Notice that carry[i] was the only value for K that would satisfy the
        // equation. Therefore, this constraint also verifies that carry[i] was
        // correct.
        //
        // It is clear that this argument can be easily turned into induction.

        let zero: AB::Expr = AB::F::zero().into();
        for n in 0..8 {
            let mut b_times_c = zero.clone();

            // Calculate BC[i] here. We have to be careful with indices as both
            // b and c only have 4 elements.
            for i in 0..4 {
                let j = (n as i32) - (i as i32);

                if 0 <= j && j < 4 {
                    b_times_c += local.b[i] * local.c[n - i];
                }
            }

            if n > 0 {
                // carry[n-1] = the overflow from calculating product[n-1].
                b_times_c += local.carry[n - 1].into();
            }

            // We set K = local.carry[n].
            let overflow = local.carry[n] * base;

            // This is BC[i] - 256 * K.
            let b_times_c_minus_overflow = b_times_c - overflow;

            builder.assert_eq(b_times_c_minus_overflow, local.product[n]);
        }

        // Ensure that the lowest 4 bytes are calculated correctly (MUL)
        for i in 0..4 {
            builder.assert_eq(local.product[i], local.a[i]);
        }

        // Receive the arguments.
        builder.receive_alu(
            AB::F::from_canonical_u32(Opcode::MUL as u32),
            local.a,
            local.b,
            local.c,
            local.is_real,
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
        runtime.mul_events =
            vec![AluEvent::new(0, Opcode::MUL, 3160867512, 2222324, 3335238)].repeat(1000);
        let chip = MulChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
