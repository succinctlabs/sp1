//! Perform the division and remainder verification.
//!
//! The trace contains quotient, remainder, and carry columns where
//! b = c * quotient + remainder.
//!
//! Given (a, b, c, quotient, remainder, carry) in the trace,
//! (quotient, remainder, carry) are correct if and only if
//!
//! b = c * quotient + remainder with 0 <= remainder < c.

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

    /// `carry` stores the carry when "carry-propagating" quotient * c + remainder.
    pub carry: [T; WORD_SIZE],

    pub is_divu: T,
    pub is_remu: T,

    pub division_by_0: T,

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

impl<F: PrimeField> Chip<F> for DivRemChip {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = runtime
            .divrem_events
            .par_iter()
            .map(|event| {
                assert!(event.opcode == Opcode::DIVU || event.opcode == Opcode::REMU);
                let mut row = [F::zero(); NUM_DIVREM_COLS];
                let cols: &mut DivRemCols<F> = unsafe { transmute(&mut row) };
                let a_word = event.a.to_le_bytes();
                let b_word = event.b.to_le_bytes();
                let c_word = event.c.to_le_bytes();

                if event.c == 0 {
                    cols.division_by_0 = F::one();
                } else {
                    let quotient = (event.b / event.c).to_le_bytes();
                    let remainder = (event.b % event.c).to_le_bytes();

                    let mut result = [0u32; WORD_SIZE];

                    // Multiply the quotient by c.
                    for i in 0..quotient.len() {
                        for j in 0..c_word.len() {
                            if i + j < result.len() {
                                result[i + j] += (quotient[i] as u32) * (c_word[j] as u32);
                            }
                        }
                    }

                    // Add remainder to product.
                    for i in 0..WORD_SIZE {
                        result[i] += remainder[i] as u32;
                    }

                    let base = 1 << BYTE_SIZE;

                    // "carry-propagate" as some terms are bigger than u8 now.
                    for i in 0..WORD_SIZE {
                        let carry = result[i] / base;
                        result[i] %= base;
                        if i + 1 < result.len() {
                            result[i + 1] += carry;
                        }
                        cols.carry[i] = F::from_canonical_u32(carry);
                    }

                    // result is c * quotient + remainder, which must equal b.
                    result.iter().zip(b_word.iter()).for_each(|(r, b)| {
                        assert_eq!(*r, *b as u32);
                    });
                    cols.quotient = quotient.map(F::from_canonical_u8);
                    cols.remainder = remainder.map(F::from_canonical_u8);
                }

                cols.a = Word(a_word.map(F::from_canonical_u8));
                cols.b = Word(b_word.map(F::from_canonical_u8));
                cols.c = Word(c_word.map(F::from_canonical_u8));
                cols.is_real = F::one();
                cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
                cols.is_remu = F::from_bool(event.opcode == Opcode::REMU);

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

        let mut result: Vec<AB::Expr> = vec![AB::F::zero().into(); WORD_SIZE];

        // Multiply the quotient by c. After this for loop, we have
        // \sigma_{i=0}^{WORD_SIZE - 1} result[i] * base^i = quotient * c.
        //
        // For simplicity, we will write F(result) =
        // \sigma_{i=0}^{WORD_SIZE - 1} result[i] * base^i = quotient * c.
        for i in 0..WORD_SIZE {
            for j in 0..WORD_SIZE {
                if i + j < WORD_SIZE {
                    result[i + j] += local.quotient[i].clone() * local.c[j].clone();
                }
            }
        }

        // Add remainder to product. After this for loop, we have
        // F(result) = quotient * c + remainder.
        for i in 0..WORD_SIZE {
            result[i] += local.remainder[i].into();
        }

        // We will "carry-propagate" the `result` array without changing
        // F(result).
        for i in 0..WORD_SIZE {
            let carry = local.carry[i].clone();

            // We subtract carry * base from result[i], which reduces
            // F(result) by carry * base^{i + 1}.
            result[i] -= carry.clone() * base.clone();

            if i + 1 < WORD_SIZE {
                // Adding carry to result[i + 1] increases
                // F(result) by carry * base^{i + 1}.
                result[i + 1] += carry.into();
            }

            // We added and subtracted carry * base^{i + 1} to F(result), so
            // F(result) remains the same.
        }

        // Now, result is c * quotient + remainder, which must equal b, unless c
        // was 0. Here, we confirm that the `quotient`, `remainder`, and `carry`
        // are correct.
        for i in 0..WORD_SIZE {
            let res_eq_b = result[i].clone() - local.b[i].clone();
            builder.assert_zero((one.clone() - local.division_by_0) * res_eq_b);
        }

        // We've confirmed the correctness of `quotient` and `remainder`. Now,
        // we need to check the output `a` indeed matches what we have.
        for i in 0..WORD_SIZE {
            let exp = local.is_divu * local.quotient[i] + local.is_remu * local.remainder[i];
            builder.assert_zero((one.clone() - local.division_by_0) * (exp - local.a[i]));
        }

        // Finally, deal with division by 0,
        builder.assert_bool(local.division_by_0);

        let byte_mask = AB::F::from_canonical_u32(0xFF);
        for i in 0..WORD_SIZE {
            // If the division_by_0 flag is set, then c better be 0.
            builder.assert_zero(local.division_by_0.clone() * local.c[i]);

            // division by 0 => DIVU returns 2^32 - 1 and REMU returns b.
            builder.assert_zero(
                local.division_by_0.clone() * local.is_divu * (local.a[i] - byte_mask),
            );
            builder.assert_zero(
                local.division_by_0.clone() * local.is_remu * (local.a[i] - local.b[i]),
            );
        }

        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_remu);
        builder.assert_bool(local.is_divu);

        // If it's a real column, exactly one of is_remu and is_divu must be 1.
        builder.assert_zero(local.is_real * local.is_remu * local.is_divu);

        // If it's a real column, exactly one of is_remu and is_divu must be 1.
        builder.assert_zero(local.is_real * (one.clone() - local.is_divu - local.is_remu));

        let divu: AB::Expr = AB::F::from_canonical_u32(Opcode::DIVU as u32).into();
        let remu: AB::Expr = AB::F::from_canonical_u32(Opcode::REMU as u32).into();
        let opcode = local.is_divu * divu + local.is_remu * remu;

        // Receive the arguments.
        builder.receive_alu(opcode, local.a, local.b, local.c, local.is_real);

        // TODO: Range check the carry column.
        // TODO: Range check remainder. (i.e., 0 <= remainder < c)

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
        runtime::{Opcode, Program, Runtime},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::DivRemChip;

    #[test]
    fn generate_trace() {
        let instructions = vec![];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);

        runtime.divrem_events = vec![AluEvent::new(0, Opcode::DIVU, 2, 17, 3)];
        let chip = DivRemChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }

    fn neg(a: u32) -> u32 {
        u32::MAX - a + 1
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

        let instructions = vec![];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);
        let mut divrem_events: Vec<AluEvent> = Vec::new();

        let divrems: Vec<(Opcode, u32, u32, u32)> = vec![
            (Opcode::DIVU, 3, 20, 6),
            (Opcode::DIVU, 715827879, neg(20), 6),
            (Opcode::DIVU, 0, 20, neg(6)),
            (Opcode::DIVU, 0, neg(20), neg(6)),
            (Opcode::DIVU, 1 << 31, 1 << 31, 1),
            (Opcode::DIVU, 0, 1 << 31, neg(1)),
            (Opcode::DIVU, u32::MAX, 1 << 31, 0),
            (Opcode::DIVU, u32::MAX, 1, 0),
            (Opcode::DIVU, u32::MAX, 0, 0),
            (Opcode::REMU, 4, 18, 7),
            (Opcode::REMU, 6, neg(20), 11),
            (Opcode::REMU, 23, 23, neg(6)),
            (Opcode::REMU, neg(21), neg(21), neg(11)),
            (Opcode::REMU, 5, 5, 0),
            (Opcode::REMU, neg(1), neg(1), 0),
            (Opcode::REMU, 0, 0, 0),
        ];
        for t in divrems.iter() {
            divrem_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - divrems.len()) {
            //mul_events.push(AluEvent::new(0, Opcode::DIVREM, 1, 1, 1));
        }

        runtime.divrem_events = divrem_events;
        let chip = DivRemChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
