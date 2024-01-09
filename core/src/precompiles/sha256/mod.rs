use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_field::PrimeField32;
use p3_field::TwoAdicField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::mem::size_of;
use std::mem::transmute;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::runtime::Segment;
use crate::utils::pad_to_power_of_two;
use crate::utils::Chip;

pub const NUM_SHA_EXTEND_COLS: usize = size_of::<ShaExtendCols<u8>>();

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct ShaExtendCols<T> {
    pub i: T,
    pub cycle_16: T,
    pub cycle_16_minus_one: T,
    pub cycle_16_minus_one_inv: T,
    pub cycle_16_minus_one_is_zero: T,
    pub cycle_3: [T; 3],
    // pub w_i_minus_15: Word<T>,
    // pub w_i_minus_15_rr_7: Word<T>,
    // pub w_i_minus_15_rr_18: Word<T>,
    // pub w_i_minus_15_rs_3: Word<T>,
    // pub w_i_minus_15_rr_7_xor_w_i_minus_15_rr_18: Word<T>,
    // pub s0: Word<T>,

    // pub w_i_minus_2: Word<T>,
    // pub w_i_minus_2_rr_17: Word<T>,
    // pub w_i_minus_2_rr_19: Word<T>,
    // pub w_i_minus_2_rs_10: Word<T>,
    // pub w_i_minus_2_rr_17_xor_w_i_minus_2_rr_19: Word<T>,
    // pub s1: Word<T>,

    // pub w_i_minus_16: Word<T>,
    // pub w_i_minus_16_plus_s0: Word<T>,

    // pub w_i_minus_7: Word<T>,
    // pub w_i_minus_7_plus_s1: Word<T>,

    // pub w_i: Word<T>,
}

pub struct ShaExtendChip;

impl ShaExtendChip {
    pub fn new() -> Self {
        Self {}
    }

    fn populate_flags<F: PrimeField>(&self, i: usize, cols: &mut ShaExtendCols<F>) {
        let g = F::from_canonical_u32(BabyBear::two_adic_generator(4).as_canonical_u32());
        cols.cycle_16 = g.exp_u64((i + 1) as u64);
        cols.cycle_16_minus_one = cols.cycle_16 - F::one();
        cols.cycle_16_minus_one_inv = if cols.cycle_16_minus_one == F::zero() {
            F::one()
        } else {
            cols.cycle_16_minus_one.inverse()
        };
        cols.cycle_16_minus_one_is_zero = F::from_bool(cols.cycle_16_minus_one == F::zero());

        let j = i % 48;
        cols.i = F::from_canonical_usize(j);
        cols.cycle_3[0] = F::from_bool(j < 16);
        cols.cycle_3[1] = F::from_bool(16 <= j && j < 32);
        cols.cycle_3[2] = F::from_bool(32 <= j && j < 48);
    }
}

impl<F: PrimeField> Chip<F> for ShaExtendChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows = Vec::new();

        for i in 0..96 {
            let mut row = [F::zero(); NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = unsafe { transmute(&mut row) };
            self.populate_flags(i, cols);
            rows.push(row);
            println!("{:?}", cols);
        }

        let nb_rows = rows.len();
        for i in nb_rows..nb_rows.next_power_of_two() {
            let mut row = [F::zero(); NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = unsafe { transmute(&mut row) };
            self.populate_flags(i, cols);
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_EXTEND_COLS,
        );

        trace
    }
}

impl<F> BaseAir<F> for ShaExtendChip {
    fn width(&self) -> usize {
        NUM_SHA_EXTEND_COLS
    }
}

impl<AB> Air<AB> for ShaExtendChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // TODO: `local.is_real needs to be properly copied down.

        let main = builder.main();
        let local: &ShaExtendCols<AB::Var> = main.row_slice(0).borrow();
        let next: &ShaExtendCols<AB::Var> = main.row_slice(1).borrow();

        let one = AB::Expr::from(AB::F::one());
        let cycle_16_generator =
            AB::F::from_canonical_u32(BabyBear::two_adic_generator(4).as_canonical_u32());

        // Initialize counter variables on the first row.
        builder
            .when_first_row()
            .assert_eq(local.cycle_16, cycle_16_generator);

        // Multiply the current cycle by the generator of group with order 16.
        builder
            .when_transition()
            .assert_eq(local.cycle_16 * cycle_16_generator, next.cycle_16);

        // Calculate whether 16 cycles have passed.
        builder.assert_eq(local.cycle_16 - one.clone(), local.cycle_16_minus_one);
        builder.assert_eq(
            one.clone() - local.cycle_16_minus_one * local.cycle_16_minus_one_inv,
            local.cycle_16_minus_one_is_zero,
        );
        builder.assert_zero(local.cycle_16_minus_one * local.cycle_16_minus_one_is_zero);

        // Increment the step flags when 16 cycles have passed. Otherwise, keep them the same.
        for i in 0..3 {
            builder
                .when_transition()
                .when(local.cycle_16_minus_one_is_zero)
                .assert_eq(local.cycle_3[i], next.cycle_3[(i + 1) % 3]);
            builder
                .when_transition()
                .when(one.clone() - local.cycle_16_minus_one_is_zero)
                .assert_eq(local.cycle_3[i], next.cycle_3[i]);
        }

        // Increment `i` by one. Once it reaches the end of the cycle, reset it to zero.
        builder
            .when_transition()
            .when(local.cycle_16_minus_one_is_zero * local.cycle_3[2])
            .assert_eq(next.i, AB::F::zero());
        builder
            .when_transition()
            .when(one.clone() - local.cycle_16_minus_one_is_zero)
            .assert_eq(local.i + one.clone(), next.i);

        builder.assert_eq(
            local.cycle_16 * local.cycle_16_minus_one * local.cycle_16_minus_one_inv,
            local.cycle_16 * local.cycle_16_minus_one * local.cycle_16_minus_one_inv,
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
        runtime::{Opcode, Segment},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::ShaExtendChip;

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.add_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6)];
        let chip = ShaExtendChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
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

        let mut segment = Segment::default();
        let chip = ShaExtendChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
