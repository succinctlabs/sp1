use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, AirBuilder, BaseAir, VirtualPairCol};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use valida_derive::AlignedBorrow;

use crate::air::Word;
use crate::lookup::{Interaction, InteractionKind};
use crate::runtime::{Opcode, Runtime};
use crate::utils::{indices_arr, pad_to_power_of_two, Chip};

pub const NUM_SHIFT_COLS: usize = size_of::<ShiftCols<u8>>();
const SHIFT_COL_MAP: ShiftCols<usize> = make_col_map();

const fn make_col_map() -> ShiftCols<usize> {
    let indices_arr = indices_arr::<NUM_SHIFT_COLS>();
    unsafe { transmute::<[usize; NUM_SHIFT_COLS], ShiftCols<usize>>(indices_arr) }
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
pub struct ShiftCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Selector flags for the operation to perform.
    pub is_sll: T,
    pub is_srl: T,
    pub is_sra: T,
}

/// A chip that implements bitwise operations for the opcodes SLL, SLLI, SRL, SRLI, SRA, and SRAI.
pub struct ShiftChip;

impl ShiftChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for ShiftChip {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = runtime
            .shift_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_SHIFT_COLS];
                let cols: &mut ShiftCols<F> = unsafe { transmute(&mut row) };
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();
                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHIFT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_SHIFT_COLS, F>(&mut trace.values);

        trace
    }

    fn receives(&self) -> Vec<Interaction<F>> {
        vec![Interaction::new(
            vec![
                VirtualPairCol::new_main(
                    vec![
                        (
                            SHIFT_COL_MAP.is_sll,
                            F::from_canonical_u32(Opcode::SLL as u32),
                        ),
                        (
                            SHIFT_COL_MAP.is_srl,
                            F::from_canonical_u32(Opcode::SRL as u32),
                        ),
                        (
                            SHIFT_COL_MAP.is_sra,
                            F::from_canonical_u32(Opcode::SRA as u32),
                        ),
                    ],
                    F::zero(),
                ),
                VirtualPairCol::single_main(SHIFT_COL_MAP.a[0]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.a[1]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.a[2]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.a[3]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.b[0]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.b[1]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.b[2]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.b[3]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.c[0]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.c[1]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.c[2]),
                VirtualPairCol::single_main(SHIFT_COL_MAP.c[3]),
            ],
            VirtualPairCol::constant(F::one()),
            InteractionKind::Alu,
        )]
    }
}

impl<F> BaseAir<F> for ShiftChip {
    fn width(&self) -> usize {
        NUM_SHIFT_COLS
    }
}

impl<AB> Air<AB> for ShiftChip
where
    AB: AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShiftCols<AB::Var> = main.row_slice(0).borrow();

        let two = AB::F::from_canonical_u32(2);

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

    use super::ShiftChip;

    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program);
        runtime.shift_events = vec![AluEvent::new(0, Opcode::SLL, 14, 8, 6)];
        let chip = ShiftChip::new();
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
        let mut runtime = Runtime::new(program);
        runtime.shift_events = vec![AluEvent::new(0, Opcode::SLL, 14, 8, 6)].repeat(1000);
        let chip = ShiftChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
