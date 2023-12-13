use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use valida_derive::AlignedBorrow;

use crate::air::Word;
use crate::lookup::Interaction;

use super::{pad_to_power_of_two, u32_to_u8_limbs, AluEvent, Chip};

pub const NUM_SHIFT_COLS: usize = size_of::<ShiftCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
pub struct ShiftCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace.
    pub c_bits_0: [T; 8],

    /// Selector flags for the operation to perform.
    pub is_sll: T,
    pub is_srl: T,
    pub is_sra: T,
}

/// A chip that implements bitwise operations for the opcodes XOR, XORI, OR, ORI, AND, and ANDI.
pub struct ShiftChip {
    events: Vec<AluEvent>,
}

impl<F: PrimeField> Chip<F> for ShiftChip {
    fn generate_trace(&self, _: &mut crate::Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = self
            .events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_SHIFT_COLS];
                let cols: &mut ShiftCols<F> = unsafe { transmute(&mut row) };
                let a = u32_to_u8_limbs(event.a);
                let b = u32_to_u8_limbs(event.b);
                let c = u32_to_u8_limbs(event.c);

                todo!();

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

    fn sends(&self) -> Vec<Interaction<F>> {
        vec![]
    }

    fn receives(&self) -> Vec<Interaction<F>> {
        vec![]
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

        todo!();
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
        alu::{AluEvent, Chip},
        runtime::Opcode,
        Runtime,
    };
    use p3_commit::ExtensionMmcs;

    use super::ShiftChip;

    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program);
        let events = vec![AluEvent {
            clk: 0,
            opcode: Opcode::ADD,
            a: 14,
            b: 8,
            c: 6,
        }];
        let chip = ShiftChip { events };
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
        let events = vec![
            AluEvent {
                clk: 0,
                opcode: Opcode::XOR,
                a: 25,
                b: 10,
                c: 19,
            },
            AluEvent {
                clk: 0,
                opcode: Opcode::OR,
                a: 27,
                b: 10,
                c: 19,
            },
            AluEvent {
                clk: 0,
                opcode: Opcode::AND,
                a: 2,
                b: 10,
                c: 19,
            },
        ]
        .repeat(1000);
        let chip = ShiftChip { events };
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
