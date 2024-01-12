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
//! # Sign extend b to 64 bits if SRA.
//!
//! # Byte shift. Leave the num_bytes_to_shift most significant bytes of b 0 for simplicity as it
//! # doesn't affect the correctness of the result.
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
use p3_air::{Air, AirBuilder, BaseAir};

use crate::bytes::utils::shr_carry;
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
#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
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

    /// The result of "bit-shifting" the byte-shifted input by `num_bits_to_shift`.
    pub bit_shift_result: [T; LONG_WORD_SIZE],

    /// An array whose `i`th element is the bits that carried when shifting the `i`th byte of
    /// `byte_shift_result` by `num_bits_to_shift`.
    pub carry: [T; LONG_WORD_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// Selector flags for the operation to perform.
    pub is_srl: T,
    pub is_sra: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

/// Calculate the number of bytes and bits to shift by. Note that we take the least significant 5
/// bits per the RISC-V spec.
fn decompose_shift_into_byte_and_bit_shifting(shift_amount: u32) -> (usize, usize) {
    let n = (shift_amount % 32) as usize;
    let num_bytes_to_shift = n / BYTE_SIZE;
    let num_bits_to_shift = n % BYTE_SIZE;
    (num_bytes_to_shift, num_bits_to_shift)
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

                    cols.b_msb = F::from_canonical_u32((event.b >> 31) & 1);

                    cols.is_srl = F::from_bool(event.opcode == Opcode::SRL);
                    cols.is_sra = F::from_bool(event.opcode == Opcode::SRA);
                }

                let (num_bytes_to_shift, num_bits_to_shift) =
                    decompose_shift_into_byte_and_bit_shifting(event.c);

                let mut byte_shift_result = [0u8; LONG_WORD_SIZE];

                // Byte shift.
                {
                    for i in 0..WORD_SIZE {
                        cols.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
                    }
                    let sign_extended_b = {
                        if event.opcode == Opcode::SRA {
                            // Sign extension is necessary only for arithmetic right shift.
                            ((event.b as i32) as i64).to_le_bytes()
                        } else {
                            (event.b as u64).to_le_bytes()
                        }
                    };

                    for i in 0..LONG_WORD_SIZE {
                        if i + num_bytes_to_shift < LONG_WORD_SIZE {
                            byte_shift_result[i] = sign_extended_b[i + num_bytes_to_shift];
                        }
                    }
                    cols.byte_shift_result = byte_shift_result.map(F::from_canonical_u8);
                }

                // bit shifting
                {
                    for i in 0..BYTE_SIZE {
                        cols.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
                    }
                    let carry_multiplier = 1 << (8 - num_bits_to_shift);
                    let mut last_carry = 0u32;
                    for i in (0..LONG_WORD_SIZE).rev() {
                        let (shifted_byte, carry) =
                            shr_carry(byte_shift_result[i], num_bits_to_shift as u8);
                        cols.carry[i] = F::from_canonical_u8(carry);
                        cols.bit_shift_result[i] = F::from_canonical_u32(
                            shifted_byte as u32 + last_carry * carry_multiplier,
                        );
                        last_carry = carry as u32;
                        if i < WORD_SIZE {
                            // TODO do "anti-tests", like make sure to pass wrong inputs and make them fail.
                            // debug_assert_eq!(cols.a[i], cols.bit_shift_result[i].clone());
                        }
                    }
                }

                println!("cols: {:#?}", cols);

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

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::zero(); NUM_SHIFT_RIGHT_COLS];
            let cols: &mut ShiftRightCols<F> = unsafe { transmute(&mut row) };
            cols.shift_by_n_bits[0] = F::one();
            cols.shift_by_n_bytes[0] = F::one();
            row
        };
        debug_assert!(padded_row_template.len() == NUM_SHIFT_RIGHT_COLS);
        for i in segment.shift_right_events.len() * NUM_SHIFT_RIGHT_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_SHIFT_RIGHT_COLS];
        }

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

        // TODO: Calculate the MSB of b using byte lookup.
        // TODO: Check shift_by_n_bytes and shift_by_n_bits match c by looking at the SLL example.
        // Byte shift the sign-extended b.
        {
            // The leading bytes of b should be 0xff if b's MSB is 1 & opcode = SRA, 0 otherwise.
            // TODO: Likely this will cause a polynomial degree error.
            let leading_byte =
                local.is_sra.clone() * local.b_msb.clone() * AB::Expr::from_canonical_u8(0xff);
            let mut sign_extended_b: Vec<AB::Expr> = vec![];
            for i in 0..WORD_SIZE {
                sign_extended_b.push(local.b[i].into());
            }
            for _ in 0..WORD_SIZE {
                sign_extended_b.push(leading_byte.clone());
            }

            for num_bytes_to_shift in 0..WORD_SIZE {
                for i in 0..(LONG_WORD_SIZE - num_bytes_to_shift) {
                    builder
                        .when(local.shift_by_n_bytes[num_bytes_to_shift].clone())
                        .assert_eq(
                            local.byte_shift_result[i].clone(),
                            sign_extended_b[i + num_bytes_to_shift].clone(),
                        );
                }
            }
        }

        // Bit shift the byte_shift_result using ShrCarry, and compare the result to a.
        {
            // The carry multiplier is 2^(8 - num_bits_to_shift).
            let mut carry_multiplier = AB::Expr::from_canonical_u8(0);
            for i in 0..BYTE_SIZE {
                carry_multiplier += AB::Expr::from_canonical_u32(1u32 << (8 - i))
                    * local.shift_by_n_bits[i].clone();
            }
            for i in (0..LONG_WORD_SIZE).rev() {
                // TODO: ShrCarry (bit_shift_result[i], num_bits_to_shift, carry[i])

                let mut v: AB::Expr = local.byte_shift_result[i].into();
                if i + 1 < LONG_WORD_SIZE {
                    v += local.carry[i + 1].clone() * carry_multiplier.clone();
                }
                builder.assert_eq(v, local.bit_shift_result[i].clone());
            }
        }

        // The 4 least significant bytes must match a. The 4 most significant bytes of result may be
        // inaccurate.
        {
            for i in 0..WORD_SIZE {
                println!("i: {}", i);
                builder.assert_eq(local.a[i].clone(), local.bit_shift_result[i].clone());
            }
        }

        // Check that the flags are indeed boolean.
        {
            let flags = [local.is_srl, local.is_sra, local.is_real, local.b_msb];
            for flag in flags.iter() {
                builder.assert_bool(*flag);
            }
            for shift_by_n_byte in local.shift_by_n_bytes.iter() {
                builder.assert_bool(*shift_by_n_byte);
            }
            for shift_by_n_bit in local.shift_by_n_bits.iter() {
                builder.assert_bool(*shift_by_n_bit);
            }
        }

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

        let shifts = vec![
            (Opcode::SRL, 0xffff8000, 0xffff8000, 0),
            // (Opcode::SRL, 0x7fffc000, 0xffff8000, 1),
            // (Opcode::SRL, 0x01ffff00, 0xffff8000, 7),
            // (Opcode::SRL, 0x0003fffe, 0xffff8000, 14),
            // (Opcode::SRL, 0x0001ffff, 0xffff8001, 15),
            // (Opcode::SRL, 0xffffffff, 0xffffffff, 0),
            // (Opcode::SRL, 0x7fffffff, 0xffffffff, 1),
            // (Opcode::SRL, 0x01ffffff, 0xffffffff, 7),
            // (Opcode::SRL, 0x0003ffff, 0xffffffff, 14),
            // (Opcode::SRL, 0x00000001, 0xffffffff, 31),
            // (Opcode::SRL, 0x21212121, 0x21212121, 0),
            // (Opcode::SRL, 0x10909090, 0x21212121, 1),
            // (Opcode::SRL, 0x00424242, 0x21212121, 7),
            // (Opcode::SRL, 0x00008484, 0x21212121, 14),
            // (Opcode::SRL, 0x00000000, 0x21212121, 31),
            // (Opcode::SRL, 0x21212121, 0x21212121, 0xffffffe0),
            // (Opcode::SRL, 0x10909090, 0x21212121, 0xffffffe1),
            // (Opcode::SRL, 0x00424242, 0x21212121, 0xffffffe7),
            // (Opcode::SRL, 0x00008484, 0x21212121, 0xffffffee),
            // (Opcode::SRL, 0x00000000, 0x21212121, 0xffffffff),
            // (Opcode::SRA, 0x00000000, 0x00000000, 0),
            // (Opcode::SRA, 0xc0000000, 0x80000000, 1),
            // (Opcode::SRA, 0xff000000, 0x80000000, 7),
            // (Opcode::SRA, 0xfffe0000, 0x80000000, 14),
            // (Opcode::SRA, 0xffffffff, 0x80000001, 31),
            // (Opcode::SRA, 0x7fffffff, 0x7fffffff, 0),
            // (Opcode::SRA, 0x3fffffff, 0x7fffffff, 1),
            // (Opcode::SRA, 0x00ffffff, 0x7fffffff, 7),
            // (Opcode::SRA, 0x0001ffff, 0x7fffffff, 14),
            // (Opcode::SRA, 0x00000000, 0x7fffffff, 31),
            // (Opcode::SRA, 0x81818181, 0x81818181, 0),
            // (Opcode::SRA, 0xc0c0c0c1, 0x81818181, 1),
            // (Opcode::SRA, 0xff030303, 0x81818181, 7),
            // (Opcode::SRA, 0xfffe0606, 0x81818181, 14),
            // (Opcode::SRA, 0xffffffff, 0x81818181, 31),
        ];
        let mut shift_events: Vec<AluEvent> = Vec::new();
        for t in shifts.iter() {
            shift_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3));
        }
        let mut segment = Segment::default();
        segment.shift_right_events = shift_events;
        let chip = RightShiftChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
