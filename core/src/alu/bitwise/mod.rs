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
use crate::runtime::Opcode;
use crate::utils::{pad_to_power_of_two, Chip};

use super::AluEvent;

pub const NUM_BITWISE_COLS: usize = size_of::<BitwiseCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
pub struct BitwiseCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace.
    pub b_bits: [[T; 8]; 4],
    pub c_bits: [[T; 8]; 4],

    /// Selector flags for the operation to perform.
    pub is_xor: T,
    pub is_or: T,
    pub is_and: T,
}

/// A chip that implements bitwise operations for the opcodes XOR, XORI, OR, ORI, AND, and ANDI.
pub struct BitwiseChip {
    events: Vec<AluEvent>,
}

impl<F: PrimeField> Chip<F> for BitwiseChip {
    fn generate_trace(&self, _: &mut crate::Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = self
            .events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_BITWISE_COLS];
                let cols: &mut BitwiseCols<F> = unsafe { transmute(&mut row) };
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                for i in 0..4 {
                    for j in 0..8 {
                        cols.b_bits[i][j] = F::from_bool((b[i] >> j) & 1 == 1);
                        cols.c_bits[i][j] = F::from_bool((c[i] >> j) & 1 == 1);
                    }
                }

                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));

                cols.is_xor =
                    F::from_bool(event.opcode == Opcode::XOR || event.opcode == Opcode::XORI);
                cols.is_or =
                    F::from_bool(event.opcode == Opcode::OR || event.opcode == Opcode::ORI);
                cols.is_and =
                    F::from_bool(event.opcode == Opcode::AND || event.opcode == Opcode::ANDI);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BITWISE_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_BITWISE_COLS, F>(&mut trace.values);

        trace
    }

    fn sends(&self) -> Vec<Interaction<F>> {
        vec![]
    }

    fn receives(&self) -> Vec<Interaction<F>> {
        vec![]
    }
}

impl<F> BaseAir<F> for BitwiseChip {
    fn width(&self) -> usize {
        NUM_BITWISE_COLS
    }
}

impl<AB> Air<AB> for BitwiseChip
where
    AB: AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &BitwiseCols<AB::Var> = main.row_slice(0).borrow();

        let two = AB::F::from_canonical_u32(2);

        // Check that the bits of the operands are correct.
        for i in 0..4 {
            let mut b_sum = AB::Expr::zero();
            let mut c_sum = AB::Expr::zero();
            let mut power = AB::F::one();
            for j in 0..8 {
                builder.assert_bool(local.b_bits[i][j]);
                builder.assert_bool(local.c_bits[i][j]);
                b_sum += local.b_bits[i][j] * power;
                c_sum += local.c_bits[i][j] * power;
                power *= two;
            }
            builder.assert_zero(b_sum - local.b[i]);
            builder.assert_zero(c_sum - local.c[i]);
        }

        // Constrain is_xor, is_or, and is_and to be bits and that only at most one is enabled.
        builder.assert_bool(local.is_xor);
        builder.assert_bool(local.is_or);
        builder.assert_bool(local.is_and);
        builder.assert_bool(local.is_xor + local.is_or + local.is_and);

        // Constrain the bitwise operation.
        for i in 0..4 {
            let mut xor = AB::Expr::zero();
            let mut or = AB::Expr::zero();
            let mut and = AB::Expr::zero();
            let mut power = AB::F::one();
            for j in 0..8 {
                xor += (local.b_bits[i][j] + local.c_bits[i][j]
                    - local.b_bits[i][j] * local.c_bits[i][j] * two)
                    * power;
                or += (local.b_bits[i][j] + local.c_bits[i][j]
                    - local.b_bits[i][j] * local.c_bits[i][j])
                    * power;
                and += local.b_bits[i][j] * local.c_bits[i][j] * power;
                power *= two;
            }
            builder.when(local.is_xor).assert_zero(xor - local.a[i]);
            builder.when(local.is_or).assert_zero(or - local.a[i]);
            builder.when(local.is_and).assert_zero(and - local.a[i]);
        }

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
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

    use crate::{alu::AluEvent, runtime::Opcode, utils::Chip, Runtime};
    use p3_commit::ExtensionMmcs;

    use super::BitwiseChip;

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
        let chip = BitwiseChip { events };
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
        let chip = BitwiseChip { events };
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
