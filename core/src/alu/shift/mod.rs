//! Verifies left shift.
//!
//! b << c = b << (8 * num_bytes_to_shift + num_bits_to_shift) = (b << num_bits_to_shift) <<
//! num_bits_to_shift = (b * pow(2, num_bits_to_shift)) << num_bytes_to_shift where
//! num_bits_to_shift = c % 8 and num_bytes_to_shift = c // 8. We will call shifting by
//! num_bits_to_shift "bit shifting" and shifting by 8 * num_bytes_to_shift "byte shifting".
//!
//! c = take the least significant 5 bits of c
//! num_bytes_to_shift = c // 8
//! num_bits_to_shift = c % 8
//!
//! # "Bit shift"
//! bit_shift_multiplier = pow(2, num_bits_to_shift)
//! bit_shift_result = bit_shift_multiplier * b
//!
//! # "Byte shift"
//! for i in range(WORD_SIZE):
//!     if i < num_bytes_to_shift:
//!         assert(a[i] == 0)
//!     else:
//!         assert(a[i] == bit_shift_result[i - num_bytes_to_shift])
//!
//! Notes:
//! - Ideally, we would simply calculate b * pow(2, c), but pow(2, c) could
//!   overflow in F. pow(2, num_bits_to_shift) won't.
//! - Shifting by a multiple of 8 bits is easy (=num_bytes_to_shift) since we
//!   just shift words.

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

use crate::air::{CurtaAirBuilder, Word};

use crate::disassembler::WORD_SIZE;
use crate::runtime::{Opcode, Segment};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_SHIFT_COLS: usize = size_of::<ShiftCols<u8>>();

pub const BYTE_SIZE: usize = 8;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct ShiftCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// The least significant byte of `c`. Used to verify `shift_by_n_bits`` and `shift_by_n_bytes`.
    pub c_least_sig_byte: [T; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [T; BYTE_SIZE],

    /// The number to multiply to shift `b` by `num_bits_to_shift`. (i.e., `2^num_bits_to_shift`)
    pub bit_shift_multiplier: T,

    /// The result of multiplying `b` by `bit_shift_multiplier`.
    pub bit_shift_result: [T; WORD_SIZE],

    /// The carry propagated when multiplying `b` by `bit_shift_multiplier`.
    pub bit_shift_result_carry: [T; WORD_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [T; WORD_SIZE],

    /// Selector flags for the operation to perform.
    pub is_sll: T,
    pub is_srl: T,
    pub is_sra: T,

    pub is_real: T,
}

/// A chip that implements bitwise operations for the opcodes SLL, SLLI, SRL, SRLI, SRA, and SRAI.
pub struct ShiftChip;

impl ShiftChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for ShiftChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = segment
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
                cols.is_sll = F::from_bool(event.opcode == Opcode::SLL);
                cols.is_srl = F::from_bool(event.opcode == Opcode::SRL);
                cols.is_sra = F::from_bool(event.opcode == Opcode::SRA);
                cols.is_real = F::one();
                for i in 0..BYTE_SIZE {
                    cols.c_least_sig_byte[i] = F::from_canonical_u32((event.c >> i) & 1);
                }

                // Variables for bit shifting.
                let num_bits_to_shift = event.c as usize % BYTE_SIZE;
                for i in 0..BYTE_SIZE {
                    cols.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
                }

                let bit_shift_multiplier = 1u32 << num_bits_to_shift;
                cols.bit_shift_multiplier = F::from_canonical_u32(bit_shift_multiplier);

                let mut carry = 0u32;
                let base = 1u32 << BYTE_SIZE;
                for i in 0..WORD_SIZE {
                    let v = b[i] as u32 * bit_shift_multiplier + carry;
                    cols.bit_shift_result[i] = F::from_canonical_u32(v % base);
                    carry = v / base;
                    cols.bit_shift_result_carry[i] = F::from_canonical_u32(carry);
                }

                // Variables for byte shifting.
                let num_bytes_to_shift = (event.c & 0b11111) as usize / BYTE_SIZE;
                for i in 0..WORD_SIZE {
                    cols.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
                }

                // Sanity check.
                for i in num_bytes_to_shift..WORD_SIZE {
                    debug_assert_eq!(
                        cols.bit_shift_result[i - num_bytes_to_shift],
                        F::from_canonical_u8(a[i])
                    );
                }

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

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::zero(); NUM_SHIFT_COLS];
            let cols: &mut ShiftCols<F> = unsafe { transmute(&mut row) };
            cols.is_sll = F::one();
            cols.shift_by_n_bits[0] = F::one();
            cols.shift_by_n_bytes[0] = F::one();
            cols.bit_shift_multiplier = F::one();
            row
        };
        debug_assert!(padded_row_template.len() == NUM_SHIFT_COLS);
        for i in segment.shift_events.len() * NUM_SHIFT_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_SHIFT_COLS];
        }

        trace
    }
}

impl<F> BaseAir<F> for ShiftChip {
    fn width(&self) -> usize {
        NUM_SHIFT_COLS
    }
}

impl<AB> Air<AB> for ShiftChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShiftCols<AB::Var> = main.row_slice(0).borrow();

        let zero: AB::Expr = AB::F::zero().into();
        let one: AB::Expr = AB::F::one().into();
        let base: AB::Expr = AB::F::from_canonical_u32(1 << BYTE_SIZE).into();

        // We first "bit shift" and next we "byte shift". Then we compare the results with a.
        // Finally, we perform some misc checks.

        // Step 1: Verify all the variables for "bit shifting". Ensure that c_least_sig_byte is
        // correct by using c.
        let mut c_byte_sum = zero.clone();
        for i in 0..BYTE_SIZE {
            let val: AB::Expr = AB::F::from_canonical_u32(1 << i).into();
            c_byte_sum += val * local.c_least_sig_byte[i].clone();
        }
        builder.assert_eq(c_byte_sum, local.c[0]);

        // Ensure that shift_by_n_bits are correct using c_least_sig_byte.
        let mut num_bits_to_shift = zero.clone();
        for i in 0..3 {
            num_bits_to_shift += local.c_least_sig_byte[i] * AB::F::from_canonical_u32(1 << i);
        }
        for i in 0..BYTE_SIZE {
            builder
                .when(local.shift_by_n_bits[i].clone())
                .assert_eq(num_bits_to_shift.clone(), AB::F::from_canonical_usize(i));
        }

        // Ensure that bit_shift_multiplier is correct using shift_by_n_bits.
        for i in 0..BYTE_SIZE {
            builder.when(local.shift_by_n_bits[i]).assert_eq(
                local.bit_shift_multiplier.clone(),
                AB::F::from_canonical_usize(1 << i),
            );
        }

        // Ensure that bit_shift_result and bit_shift_result_carry is correct using
        // bit_shift_multiplier.
        for i in 0..WORD_SIZE {
            let mut v = local.b[i] * local.bit_shift_multiplier
                - local.bit_shift_result_carry[i].clone() * base.clone();
            if i > 0 {
                v += local.bit_shift_result_carry[i - 1].into();
            }
            builder.assert_eq(local.bit_shift_result[i], v);
        }

        // Step 2: Verify all the variables for "byte shift".

        // Verify that num_bytes_to_shift is correct using c_least_sig_byte.
        let num_bytes_to_shift =
            local.c_least_sig_byte[3] + local.c_least_sig_byte[4] * AB::F::from_canonical_u32(2);

        // Verify that shift_by_n_bytes is correct using num_bytes_to_shift.
        for i in 0..WORD_SIZE {
            builder
                .when(local.shift_by_n_bytes[i])
                .assert_eq(num_bytes_to_shift.clone(), AB::F::from_canonical_usize(i));
        }
        // Step 3: Verify that the result matches a.

        // Verify that local.a is indeed correct using shift_by_n_bytes and bit_shift_result.
        for num_bytes_to_shift in 0..WORD_SIZE {
            let mut shifting = builder.when(local.shift_by_n_bytes[num_bytes_to_shift]);
            for i in 0..WORD_SIZE {
                if i < num_bytes_to_shift {
                    // The first num_bytes_to_shift bytes must be zero.
                    shifting.assert_eq(local.a[i], zero.clone());
                } else {
                    shifting.assert_eq(
                        local.a[i],
                        local.bit_shift_result[i - num_bytes_to_shift].clone(),
                    );
                }
            }
        }

        // Step 4: Perform misc checks such as range checks & bool checks. Finally, perform all the
        // range checks.
        for bit in local.c_least_sig_byte.iter() {
            builder.assert_bool(*bit);
        }

        for shift in local.shift_by_n_bits.iter() {
            builder.assert_bool(*shift);
        }
        builder.assert_eq(
            local
                .shift_by_n_bits
                .iter()
                .fold(zero.clone(), |acc, &x| acc + x),
            one.clone(),
        );

        for _x in local.bit_shift_result.iter() {
            // TODO: _x in [0, 255]
        }

        for _x in local.bit_shift_result_carry.iter() {
            // TODO: _x in [0, 255]
        }

        for shift in local.shift_by_n_bytes.iter() {
            builder.assert_bool(*shift);
        }

        builder.assert_eq(
            local
                .shift_by_n_bytes
                .iter()
                .fold(zero.clone(), |acc, &x| acc + x),
            one.clone(),
        );

        builder.assert_bool(local.is_sll);
        builder.assert_bool(local.is_srl);
        builder.assert_bool(local.is_sra);

        // Exactly one of them must be true.
        builder.assert_eq(local.is_sll + local.is_srl + local.is_sra, one.clone());

        builder.assert_bool(local.is_real);

        // Receive the arguments.
        builder.receive_alu(
            local.is_sll * AB::F::from_canonical_u32(Opcode::SLL as u32)
                + local.is_srl * AB::F::from_canonical_u32(Opcode::SRL as u32)
                + local.is_sra * AB::F::from_canonical_u32(Opcode::SRA as u32),
            local.a,
            local.b,
            local.c,
            local.is_sll + local.is_srl + local.is_sra,
        );

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
        runtime::{Opcode, Segment},
        utils::Chip,
    };
    use p3_commit::ExtensionMmcs;

    use super::ShiftChip;

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.shift_events = vec![AluEvent::new(0, Opcode::SLL, 16, 8, 1)];
        let chip = ShiftChip::new();
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

        let mut shift_events: Vec<AluEvent> = Vec::new();
        let shift_instructions: Vec<(Opcode, u32, u32, u32)> = vec![
            (Opcode::SLL, 0x00000002, 0x00000001, 1),
            (Opcode::SLL, 0x00000080, 0x00000001, 7),
            (Opcode::SLL, 0x00004000, 0x00000001, 14),
            (Opcode::SLL, 0x80000000, 0x00000001, 31),
            (Opcode::SLL, 0xffffffff, 0xffffffff, 0),
            (Opcode::SLL, 0xfffffffe, 0xffffffff, 1),
            (Opcode::SLL, 0xffffff80, 0xffffffff, 7),
            (Opcode::SLL, 0xffffc000, 0xffffffff, 14),
            (Opcode::SLL, 0x80000000, 0xffffffff, 31),
            (Opcode::SLL, 0x21212121, 0x21212121, 0),
            (Opcode::SLL, 0x42424242, 0x21212121, 1),
            (Opcode::SLL, 0x90909080, 0x21212121, 7),
            (Opcode::SLL, 0x48484000, 0x21212121, 14),
            (Opcode::SLL, 0x80000000, 0x21212121, 31),
            (Opcode::SLL, 0x21212121, 0x21212121, 0xffffffe0),
            (Opcode::SLL, 0x42424242, 0x21212121, 0xffffffe1),
            (Opcode::SLL, 0x90909080, 0x21212121, 0xffffffe7),
            (Opcode::SLL, 0x48484000, 0x21212121, 0xffffffee),
            (Opcode::SLL, 0x00000000, 0x21212120, 0xffffffff),
        ];
        for t in shift_instructions.iter() {
            shift_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - shift_instructions.len()) {
            //shift_events.push(AluEvent::new(0, Opcode::SLL, 14, 8, 6));
        }

        let mut segment = Segment::default();
        segment.shift_events = shift_events;
        let chip = ShiftChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
