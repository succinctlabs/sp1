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
use crate::precompiles::sha256_extend::flags::populate_flags;
use crate::runtime::Segment;
use crate::utils::pad_to_power_of_two;
use crate::utils::Chip;

use self::flags::eval_flags;

mod flags;

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
}

impl<F: PrimeField> Chip<F> for ShaExtendChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows = Vec::new();

        for i in 0..96 {
            let mut row = [F::zero(); NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = unsafe { transmute(&mut row) };
            populate_flags(i, cols);
            rows.push(row);
            println!("{:?}", cols);
        }

        let nb_rows = rows.len();
        for i in nb_rows..nb_rows.next_power_of_two() {
            let mut row = [F::zero(); NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = unsafe { transmute(&mut row) };
            populate_flags(i, cols);
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
        eval_flags(builder);
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
