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

pub const NUM_DIVREM_COLS: usize = size_of::<DivRemCols<u8>>();

const BYTE_SIZE: usize = 8;
const BYTE_MASK: u8 = 0xff;
const SIGN_BIT_MASK: u8 = 0x80;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
#[repr(C)]
pub struct DivRemCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// b = quotient * c + remainder.
    pub quotient: [T; WORD_SIZE],
    pub remainder: [T; WORD_SIZE],

    /// `mul_carry` stores the carry when multiplying quotient by c. Since
    /// the product is strictly smaller than b, we only need WORD_SIZE bytes.
    pub mul_carry: [T; WORD_SIZE],

    /// `add_carry` stores the carry when adding remainder to quotient * c.
    pub add_carry: [T; WORD_SIZE],

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

/// A chip that implements addition for the opcodes DIV/REM.
pub struct DivRemChip;

impl DivRemChip {
    pub fn new() -> Self {
        Self {}
    }
}

fn is_sign_bit_on(a: [u8; WORD_SIZE]) -> bool {
    (a[WORD_SIZE - 1] & SIGN_BIT_MASK) != 0
}

impl<F: PrimeField> Chip<F> for DivRemChip {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = runtime
            .mul_events
            .par_iter()
            .map(|event| {
                assert!(
                    event.opcode == Opcode::DIVREM
                        || event.opcode == Opcode::DIVREMHU
                        || event.opcode == Opcode::DIVREMH
                        || event.opcode == Opcode::DIVREMHSU
                );
                let mut row = [F::zero(); NUM_DIVREM_COLS];
                let cols: &mut DivRemCols<F> = unsafe { transmute(&mut row) };
                let a_word = event.a.to_le_bytes();
                let b_word = event.b.to_le_bytes();
                let c_word = event.c.to_le_bytes();

                let mut b = b_word.to_vec();
                let mut c = c_word.to_vec();

                // Sign extend b and c whenever appropriate.
                if event.opcode == Opcode::DIVREMH || event.opcode == Opcode::MULHSU {
                    if is_sign_bit_on(b_word) {
                        // b is signed and it is negative. Sign extend b.
                        cols.is_b_negative = F::one();
                        b.resize(PRODUCT_SIZE, BYTE_MASK);
                    }
                }

                if event.opcode == Opcode::DIVREMH {
                    if is_sign_bit_on(c_word) {
                        // c is signed and it is negative. Sign extend c.
                        cols.is_c_negative = F::one();
                        c.resize(PRODUCT_SIZE, BYTE_MASK);
                    }
                }

                let mut product = [0u32; PRODUCT_SIZE];

                for i in 0..b.len() {
                    for j in 0..c.len() {
                        if i + j < PRODUCT_SIZE {
                            product[i + j] += (b[i] as u32) * (c[j] as u32);
                        }
                    }
                }

                // Calculate the correct product using the `product` array. We
                // store the correct carry value for verification.
                let base = 1 << BYTE_SIZE;
                for i in 0..PRODUCT_SIZE {
                    let carry = product[i] / base;
                    product[i] %= base;
                    if i + 1 < PRODUCT_SIZE {
                        product[i + 1] += carry;
                    }
                    cols.carry[i] = F::from_canonical_u32(carry);
                }

                cols.product = product.map(F::from_canonical_u32);
                cols.a = Word(a_word.map(F::from_canonical_u8));
                cols.b = Word(b_word.map(F::from_canonical_u8));
                cols.c = Word(c_word.map(F::from_canonical_u8));
                cols.is_real = F::one();

                if event.opcode != Opcode::DIVREM {
                    // DIVREM is the only op code that checks the lower half.
                    cols.is_upper = F::one();
                }

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_DIVREM_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_DIVREM_COLS, F>(&mut trace.values);

        trace
    }
}

impl<F> BaseAir<F> for DivRemChip {
    fn width(&self) -> usize {
        NUM_DIVREM_COLS
    }
}

impl<AB> Air<AB> for DivRemChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &DivRemCols<AB::Var> = main.row_slice(0).borrow();
        let base = AB::F::from_canonical_u32(1 << 8);
        let one: AB::Expr = AB::F::one().into();

        // 0xff
        let byte_mask = AB::F::from_canonical_u8(BYTE_MASK);

        // Sign extend local.b and local.c whenever appropriate.
        let mut b: Vec<AB::Expr> = vec![AB::F::zero().into(); PRODUCT_SIZE];
        let mut c: Vec<AB::Expr> = vec![AB::F::zero().into(); PRODUCT_SIZE];
        for i in 0..PRODUCT_SIZE {
            if i < WORD_SIZE {
                b[i] = local.b[i].into();
                c[i] = local.c[i].into();
            } else {
                b[i] = local.is_b_negative.clone() * byte_mask;
                c[i] = local.is_c_negative.clone() * byte_mask;
            }
        }

        // Compute the uncarried product b(x) * c(x) = m(x).
        let mut m: Vec<AB::Expr> = vec![AB::F::zero().into(); PRODUCT_SIZE];

        for i in 0..PRODUCT_SIZE {
            for j in 0..PRODUCT_SIZE {
                if i + j < PRODUCT_SIZE {
                    m[i + j] += b[i].clone() * c[j].clone();
                }
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
            } else {
                // When 0 < i < PRODUCT_SIZE, there is a carry from the
                // previous term, and there's a carry from this term. This is
                // true even for the highest term due to the possible sign bits.
                builder.assert_eq(
                    local.product[i],
                    m[i].clone() + local.carry[i - 1] - local.carry[i] * base,
                );
            }
        }

        // Assert that the upper or lower half word of the product matches the result.
        for i in 0..WORD_SIZE {
            let appropriate_half = local.is_upper * local.product[i + WORD_SIZE]
                + (one.clone() - local.is_upper) * local.product[i];
            builder.assert_eq(appropriate_half, local.a[i]);
        }

        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_upper);
        builder.assert_bool(local.is_b_negative);
        builder.assert_bool(local.is_c_negative);

        // Receive the arguments.
        builder.receive_alu(
            AB::F::from_canonical_u32(Opcode::DIVREM as u32),
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

    use super::DivRemChip;

    #[test]
    fn generate_trace() {
        let program = vec![];
        let mut runtime = Runtime::new(program, 0);
        runtime.mul_events = vec![AluEvent::new(
            0,
            Opcode::DIVREMHSU,
            0x80004000,
            0x80000000,
            0xffff8000,
        )];
        let chip = DivRemChip::new();
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

        let mul_instructions: Vec<(Opcode, u32, u32, u32)> = vec![
            //(Opcode::DIVREM, 0x00001200, 0x00007e00, 0xb6db6db7),
            //(Opcode::DIVREM, 0x00001240, 0x00007fc0, 0xb6db6db7),
            //(Opcode::DIVREM, 0x00000000, 0x00000000, 0x00000000),
            //(Opcode::DIVREM, 0x00000001, 0x00000001, 0x00000001),
            //(Opcode::DIVREM, 0x00000015, 0x00000003, 0x00000007),
            //(Opcode::DIVREM, 0x00000000, 0x00000000, 0xffff8000),
            //(Opcode::DIVREM, 0x00000000, 0x80000000, 0x00000000),
            //(Opcode::DIVREM, 0x00000000, 0x80000000, 0xffff8000),
            //(Opcode::DIVREM, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d),
            //(Opcode::DIVREM, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab),
            //(Opcode::DIVREM, 0x00000000, 0xff000000, 0xff000000),
            //(Opcode::DIVREM, 0x00000001, 0xffffffff, 0xffffffff),
            //(Opcode::DIVREM, 0xffffffff, 0xffffffff, 0x00000001),
            //(Opcode::DIVREM, 0xffffffff, 0x00000001, 0xffffffff),
            //(Opcode::DIVREMHU, 0x00000000, 0x00000000, 0x00000000),
            //(Opcode::DIVREMHU, 0x00000000, 0x00000001, 0x00000001),
            //(Opcode::DIVREMHU, 0x00000000, 0x00000003, 0x00000007),
            //(Opcode::DIVREMHU, 0x00000000, 0x00000000, 0xffff8000),
            //(Opcode::DIVREMHU, 0x00000000, 0x80000000, 0x00000000),
            //(Opcode::DIVREMHU, 0x7fffc000, 0x80000000, 0xffff8000),
            //(Opcode::DIVREMHU, 0x0001fefe, 0xaaaaaaab, 0x0002fe7d),
            //(Opcode::DIVREMHU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
            //(Opcode::DIVREMHU, 0xfe010000, 0xff000000, 0xff000000),
            //(Opcode::DIVREMHU, 0xfffffffe, 0xffffffff, 0xffffffff),
            //(Opcode::DIVREMHU, 0x00000000, 0xffffffff, 0x00000001),
            //(Opcode::DIVREMHU, 0x00000000, 0x00000001, 0xffffffff),
            //(Opcode::DIVREMHSU, 0x00000000, 0x00000000, 0x00000000),
            //(Opcode::DIVREMHSU, 0x00000000, 0x00000001, 0x00000001),
            //(Opcode::DIVREMHSU, 0x00000000, 0x00000003, 0x00000007),
            //(Opcode::DIVREMHSU, 0x00000000, 0x00000000, 0xffff8000),
            //(Opcode::DIVREMHSU, 0x00000000, 0x80000000, 0x00000000),
            //(Opcode::DIVREMHSU, 0x80004000, 0x80000000, 0xffff8000),
            //(Opcode::DIVREMHSU, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
            //(Opcode::DIVREMHSU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab),
            //(Opcode::DIVREMHSU, 0xff010000, 0xff000000, 0xff000000),
            //(Opcode::DIVREMHSU, 0xffffffff, 0xffffffff, 0xffffffff),
            //(Opcode::DIVREMHSU, 0xffffffff, 0xffffffff, 0x00000001),
            //(Opcode::DIVREMHSU, 0x00000000, 0x00000001, 0xffffffff),
            //(Opcode::DIVREMH, 0x00000000, 0x00000000, 0x00000000),
            //(Opcode::DIVREMH, 0x00000000, 0x00000001, 0x00000001),
            //(Opcode::DIVREMH, 0x00000000, 0x00000003, 0x00000007),
            //(Opcode::DIVREMH, 0x00000000, 0x00000000, 0xffff8000),
            //(Opcode::DIVREMH, 0x00000000, 0x80000000, 0x00000000),
            //(Opcode::DIVREMH, 0x00000000, 0x80000000, 0x00000000),
            //(Opcode::DIVREMH, 0xffff0081, 0xaaaaaaab, 0x0002fe7d),
            //(Opcode::DIVREMH, 0xffff0081, 0x0002fe7d, 0xaaaaaaab),
            //(Opcode::DIVREMH, 0x00010000, 0xff000000, 0xff000000),
            //(Opcode::DIVREMH, 0x00000000, 0xffffffff, 0xffffffff),
            //(Opcode::DIVREMH, 0xffffffff, 0xffffffff, 0x00000001),
            //(Opcode::DIVREMH, 0xffffffff, 0x00000001, 0xffffffff),
        ];
        for t in mul_instructions.iter() {
            mul_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - mul_instructions.len()) {
            mul_events.push(AluEvent::new(0, Opcode::DIVREM, 1, 1, 1));
        }

        runtime.mul_events = mul_events;
        let chip = DivRemChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
