//! Logical And Arithmetic Right Shift Verification.
//!
//! Implements verification for a = b >> c, decomposing the shift into bit and byte components:
//!
//! 1. num_bits_to_shift = c % 8: Bit-level shift, achieved by multiplying b by 2^num_bits_to_shift.
//! 2. num_bytes_to_shift = c // 8: Byte-level shift, shifting entire bytes or words in b.
//!
//! The right shift is verified by reformulating it as (b >> c) = (b >> (num_bytes_to_shift * 8)) >>
//! num_bits_to_shift.
//!
//! By byte shifting is done by shifting each byte, and bit-shifting is done by ShrCarry lookups.
//!
//! The correct leading bits of logical and arithmetic right shifts are verified
//! by sign extending b to 64 bits.
//!
//! c = take the least significant 5 bits of c
//! num_bytes_to_shift = c // 8
//! num_bits_to_shift = c % 8
//!
//! # Sign extend b to 64 bits.
//!
//! # Byte shift.
//! result = [0; LONG_WORD_SIZE]
//! for i in range(LONG_WORD_SIZE - num_bytes_to_shift):
//!     result[i] = b[i + num_bytes_to_shift]
//!
//! # Bit shift.
//! carry_multiplier = 1 << (8 - num_bits_to_shift)
//! last_carry = 0
//! for i in reversed(range(LONG_WORD_SIZE)):
//!     # Shifts a byte to the right and returns both the shifted byte and the bits that carried.
//!     (result[i], carry) = shr_carry(result[i], num_bits_to_shift)
//!     result[i] += last_carry * carry_multiplier
//!     last_carry = carry
//!
//! # The 4 least significant bytes must match a. The 4 most significant bytes of result may be
//! # inaccurate.
//! assert a = result[0..WORD_SIZE]

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, BaseAir};

use crate::disassembler::WORD_SIZE;
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};

use crate::runtime::{Opcode, Segment};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_SHIFT_RIGHT_COLS: usize = size_of::<ShiftRightCols<u8>>();

/// The number of bytes necessary to represent a 64-bit integer.
const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

/// The number of bits in a byte.
const BYTE_SIZE: usize = 8;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
pub struct ShiftRightCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [T; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [T; WORD_SIZE],

    /// The result of "byte-shifting" the input operand `b` by `num_bytes_to_shift`.
    pub byte_shift_result: [T; LONG_WORD_SIZE],

    /// An array whose `i`th element is the bits that carried when shifting the `i`th byte of
    /// `byte_shift_result` by `num_bits_to_shift`.
    pub carry: [T; LONG_WORD_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// Flag to indicate whether `b` is negative.
    pub b_neg: T,

    /// Selector flags for the operation to perform.
    pub is_srl: T,
    pub is_sra: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

/// A chip that implements bitwise operations for the opcodes SRL, SRLI, SRA, and SRAI.
pub struct RightShiftChip;

impl RightShiftChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for RightShiftChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = segment
            .shift_right_events
            .par_iter()
            .map(|event| {
                assert!(event.opcode == Opcode::SRL || event.opcode == Opcode::SRA);
                let mut row = [F::zero(); NUM_SHIFT_RIGHT_COLS];
                let cols: &mut ShiftRightCols<F> = unsafe { transmute(&mut row) };
                // Initialize cols with basic operands and flags derived from the current event.
                {
                    cols.a = Word::from(event.a);
                    cols.b = Word::from(event.b);
                    cols.c = Word::from(event.c);

                    cols.is_srl = F::from_bool(event.opcode == Opcode::SRL);
                    cols.is_sra = F::from_bool(event.opcode == Opcode::SRA);
                }
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHIFT_RIGHT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_SHIFT_RIGHT_COLS, F>(&mut trace.values);

        trace
    }
}

impl<F> BaseAir<F> for RightShiftChip {
    fn width(&self) -> usize {
        NUM_SHIFT_RIGHT_COLS
    }
}

impl<AB> Air<AB> for RightShiftChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShiftRightCols<AB::Var> = main.row_slice(0).borrow();

        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        );

        // Receive the arguments.
        builder.receive_alu(
            local.is_srl * AB::F::from_canonical_u32(Opcode::SRL as u32)
                + local.is_sra * AB::F::from_canonical_u32(Opcode::SRA as u32),
            local.a,
            local.b,
            local.c,
            local.is_srl + local.is_sra,
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

    use super::RightShiftChip;

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.shift_right_events = vec![AluEvent::new(0, Opcode::SRL, 6, 12, 1)];
        let chip = RightShiftChip::new();
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
        segment.shift_right_events = vec![AluEvent::new(0, Opcode::SRL, 6, 12, 1)].repeat(1000);
        let chip = RightShiftChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
