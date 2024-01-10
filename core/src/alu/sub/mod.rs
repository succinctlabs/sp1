use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use std::mem::transmute;
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};

use crate::runtime::{Opcode, Segment};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_SUB_COLS: usize = size_of::<SubCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
pub struct SubCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace.
    pub carry: [T; 4],

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

/// A chip that implements subtraction for the opcode SUB.
pub struct SubChip;

impl SubChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for SubChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = segment
            .sub_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_SUB_COLS];
                let cols: &mut SubCols<F> = unsafe { transmute(&mut row) };
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                let mut carry = [0u8, 0u8, 0u8, 0u8];
                if b[0] < c[0] {
                    carry[0] = 1;
                    cols.carry[0] = F::one();
                }

                if b[1] < c[1] + carry[0] {
                    carry[1] = 1;
                    cols.carry[1] = F::one();
                }

                if b[2] < c[2] + carry[1] {
                    carry[2] = 1;
                    cols.carry[2] = F::one();
                }

                if b[3] < c[3] + carry[2] {
                    carry[3] = 1;
                    cols.carry[3] = F::one();
                }

                println!("a: {:?}, b: {:?}, c: {:?}, carry: {:?}", a, b, c, carry);

                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));
                cols.is_real = F::one();

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SUB_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_SUB_COLS, F>(&mut trace.values);

        trace
    }
}

impl<F> BaseAir<F> for SubChip {
    fn width(&self) -> usize {
        NUM_SUB_COLS
    }
}

impl<AB> Air<AB> for SubChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &SubCols<AB::Var> = main.row_slice(0).borrow();
        let base = AB::Expr::from_canonical_u32(1 << 8);

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base.

        let overflow_a_0 = base.clone() - local.a[0];
        let overflow_a_1 = base.clone() - local.a[1];
        let overflow_a_2 = base.clone() - local.a[2];
        let overflow_a_3 = base.clone() - local.a[3];

        let expected_a_0 = local.a[0] + local.carry[0] * (-overflow_a_0 - local.a[0]);
        let expected_a_1 = local.a[1] + local.carry[1] * (-overflow_a_1 - local.a[1]);
        let expected_a_2 = local.a[2] + local.carry[2] * (-overflow_a_2 - local.a[2]);
        let expected_a_3 = local.a[3] + local.carry[3] * (-overflow_a_3 - local.a[3]);

        builder.assert_zero(local.b[0] - local.c[0] - expected_a_0);
        builder.assert_zero(local.b[1] - local.c[1] - local.carry[0] - expected_a_1);
        builder.assert_zero(local.b[2] - local.c[2] - local.carry[1] - expected_a_2);
        builder.assert_zero(local.b[3] - local.c[3] - local.carry[2] - expected_a_3);

        // Assert that the carry is either zero or one.
        builder.assert_bool(local.carry[0]);
        builder.assert_bool(local.carry[1]);
        builder.assert_bool(local.carry[2]);

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        );

        // Receive the arguments.
        builder.receive_alu(
            AB::F::from_canonical_u32(Opcode::SUB as u32),
            local.a,
            local.b,
            local.c,
            local.is_real,
        )
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
    use rand::{thread_rng, Rng};

    use crate::{
        alu::AluEvent,
        runtime::{Opcode, Segment},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::SubChip;

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.sub_events = vec![AluEvent::new(
            0,
            Opcode::SUB,
            327680u32.wrapping_sub(16975360u32),
            327680,
            16975360,
        )];
        let chip = SubChip {};
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values)
    }

    #[test]
    fn generate_trace_overflow() {
        let mut segment = Segment::default();
        segment.sub_events = vec![AluEvent::new(0, Opcode::SUB, 0u32.wrapping_sub(1u32), 0, 1)];
        let chip = SubChip {};
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

        for i in 0..1 {
            let operand_1 = thread_rng().gen_range(0..u8::MAX);
            let operand_2 = thread_rng().gen_range(0..u8::MAX);
            let result = operand_1.wrapping_sub(operand_2);
            segment.sub_events.push(AluEvent::new(
                0,
                Opcode::SUB,
                result as u32,
                operand_1 as u32,
                operand_2 as u32,
            ));
        }
        let chip = SubChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
