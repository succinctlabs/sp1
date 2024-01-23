use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField;
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};

use crate::bytes::utils::lt;
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::runtime::{Opcode, Segment};
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_LT_COLS: usize = size_of::<LtCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
#[repr(C)]
pub struct LtCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// b[i] < c[i].
    pub unsigned_b_lt_c: [T; 4],

    /// Boolean flag to indicate which byte pair differs
    pub byte_flag: [T; 4],

    // Boolean flag to indicate whether the sign bits of b and c are equal.
    pub sign_xor: T,

    /// Boolean flag to indicate whether to do an equality check between the bytes. This should be
    /// true for all bytes with a lower index than the first byte pair that differs in BE.
    pub byte_equality_check: [T; 4],

    /// Selector flags for the operation to perform.
    pub is_slt: T,
    pub is_sltu: T,
}

impl LtCols<u32> {
    pub fn from_trace_row<F: PrimeField32>(row: &[F]) -> Self {
        let sized: [u32; NUM_LT_COLS] = row
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        unsafe { transmute::<[u32; NUM_LT_COLS], LtCols<u32>>(sized) }
    }
}

/// A chip that implements bitwise operations for the opcodes SLT and SLTU.
pub struct LtChip;

impl LtChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for LtChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = segment
            .lt_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_LT_COLS];
                let cols: &mut LtCols<F> = unsafe { transmute(&mut row) };
                let a = event.a.to_be_bytes();
                let b = event.b.to_be_bytes();
                let c = event.c.to_be_bytes();

                cols.a = Word(a.map(F::from_canonical_u8));
                cols.b = Word(b.map(F::from_canonical_u8));
                cols.c = Word(c.map(F::from_canonical_u8));

                for i in 0..4 {
                    let is_b_lt_c = lt(b[i], c[i]);

                    let byte_event = ByteLookupEvent {
                        opcode: ByteOpcode::LTU,
                        a1: is_b_lt_c,
                        a2: 0,
                        b: b[i],
                        c: c[i],
                    };

                    // unsigned_b_lt_c[i] stores the value of the unsigned lt comparison of b and c.
                    cols.unsigned_b_lt_c[i] = F::from_canonical_u8(is_b_lt_c);

                    segment
                        .byte_lookups
                        .entry(byte_event)
                        .and_modify(|j| *j += 1)
                        .or_insert(1);
                }

                let mut sign_xor = 0;
                if event.opcode == Opcode::SLT {
                    sign_xor = (b[3] >> 7) ^ (c[3] >> 7);
                }

                cols.sign_xor = F::from_canonical_u8(sign_xor);

                // Starting from the largest byte, find the first byte pair, index i that differs.
                let equal_bytes = b == c;
                // Defaults to the first byte in BE if the bytes are equal.
                let mut idx_to_check = 0;
                // Find the first byte pair that differs in BE.
                for i in 0..4 {
                    if b[i] != c[i] {
                        idx_to_check = i;
                        cols.byte_flag[i] = F::one();
                        break;
                    }
                }

                // byte_equality_check marks the bytes that should be checked for equality (i.e.
                // all bytes after the first byte pair that differs in BE).
                // Note: If b and c are equal, set byte_equality_check to true for all bytes.
                for i in 0..4 {
                    if i < idx_to_check || equal_bytes {
                        cols.byte_equality_check[i] = F::one();
                    }
                }

                cols.is_slt = F::from_bool(event.opcode == Opcode::SLT);
                cols.is_sltu = F::from_bool(event.opcode == Opcode::SLTU);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_LT_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_LT_COLS, F>(&mut trace.values);

        trace
    }

    fn name(&self) -> String {
        "Lt".to_string()
    }
}

impl<F> BaseAir<F> for LtChip {
    fn width(&self) -> usize {
        NUM_LT_COLS
    }
}

impl<AB> Air<AB> for LtChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &LtCols<AB::Var> = main.row_slice(0).borrow();

        let one = AB::Expr::one();

        // Dummy degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        );

        let mult = local.is_slt + local.is_sltu;

        for ((a, b), c) in local.a.into_iter().zip(local.b).zip(local.c) {
            builder.send_byte(ByteOpcode::LTU.to_field::<AB::F>(), a, b, c, mult.clone());
        }

        for i in 0..4 {
            // If the bytes are marked equal, verify they are equal.
            builder
                .when(local.byte_equality_check[i])
                .assert_eq(local.b[i], local.c[i]);

            if i == 0 {
                // If the sign bits of b, c are different, the output should be 1 - unsigned_b_lt_c.
                // Ex. 0b10000000 < 0b01111111 = 0 in unsigned, but is 1 in signed.
                // Ex. 0b01111111 < 0b10000000 = 1 in unsigned, but is 0 in signed.
                // Therefore, we can just flip the result of local.unsigned_b_lt_c[0] to get
                // the output if the sign bits are different.
                builder
                    .when(local.sign_xor)
                    .assert_eq(local.a[3], one.clone() - local.unsigned_b_lt_c[0]);

                // If the first bytes are different, but the sign bits are the same.
                let diff_first_byte_same_sign = (one.clone() - local.sign_xor) * local.byte_flag[i];
                builder
                    .when(diff_first_byte_same_sign)
                    .assert_eq(local.a[3], local.unsigned_b_lt_c[0]);
            } else {
                // If the byte is marked as differing, verify the output matches unsigned_b_lt_c.
                // This also works for signed comparisons.
                // Ex. 0b11111111 (-1) < 0b11111110 (-2) = 0 in signed & unsigned.
                builder
                    .when(local.byte_flag[i])
                    .assert_eq(local.unsigned_b_lt_c[i], local.a[3]);
            }

            builder.assert_bool(local.byte_flag[i]);
            builder.assert_bool(local.byte_equality_check[i]);
            builder.assert_bool(local.unsigned_b_lt_c[i]);
        }

        // Verify at most one byte flag is set.
        let flag_sum =
            local.byte_flag[0] + local.byte_flag[1] + local.byte_flag[2] + local.byte_flag[3];
        builder.assert_bool(flag_sum.clone());

        // Check output bits are valid.
        for i in 0..3 {
            builder.assert_zero(local.a[i]);
        }
        builder.assert_bool(local.a[3]);

        // Sign XOR
        builder.assert_bool(local.sign_xor);

        // Receive the arguments.
        builder.receive_alu(
            local.is_slt * AB::F::from_canonical_u32(Opcode::SLT as u32)
                + local.is_sltu * AB::F::from_canonical_u32(Opcode::SLTU as u32),
            local.a,
            local.b,
            local.c,
            local.is_slt + local.is_sltu,
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

    use super::LtChip;

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.lt_events = vec![AluEvent::new(0, Opcode::SLT, 0, 3, 2)];
        let chip = LtChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values)
    }

    fn prove_babybear_template(segment: &mut Segment) {
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
        let fri_config = MyFriConfig::new(1, 40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);
        let mut challenger = Challenger::new(perm.clone());

        let chip = LtChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(segment);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }

    #[test]
    fn prove_babybear_slt() {
        let mut segment = Segment::default();

        const NEG_3: u32 = 0b11111111111111111111111111111101;
        const NEG_4: u32 = 0b11111111111111111111111111111100;
        segment.lt_events = vec![
            // 0 == 3 < 2
            AluEvent::new(0, Opcode::SLT, 0, 3, 2),
            // 1 == 2 < 3
            AluEvent::new(1, Opcode::SLT, 1, 2, 3),
            // 0 == 5 < -3
            AluEvent::new(3, Opcode::SLT, 0, 5, NEG_3),
            // 1 == -3 < 5
            AluEvent::new(2, Opcode::SLT, 1, NEG_3, 5),
            // 0 == -3 < -4
            AluEvent::new(4, Opcode::SLT, 0, NEG_3, NEG_4),
            // 1 == -4 < -3
            AluEvent::new(4, Opcode::SLT, 1, NEG_4, NEG_3),
            // 0 == 3 < 3
            AluEvent::new(5, Opcode::SLT, 0, 3, 3),
            // 0 == -3 < -3
            AluEvent::new(5, Opcode::SLT, 0, NEG_3, NEG_3),
        ];

        prove_babybear_template(&mut segment);
    }

    #[test]
    fn prove_babybear_sltu() {
        let mut segment = Segment::default();

        const LARGE: u32 = 0b11111111111111111111111111111101;
        segment.lt_events = vec![
            // 0 == 3 < 2
            AluEvent::new(0, Opcode::SLTU, 0, 3, 2),
            // 1 == 2 < 3
            AluEvent::new(1, Opcode::SLTU, 1, 2, 3),
            // 0 == LARGE < 5
            AluEvent::new(2, Opcode::SLTU, 0, LARGE, 5),
            // 1 == 5 < LARGE
            AluEvent::new(3, Opcode::SLTU, 1, 5, LARGE),
            // 0 == 0 < 0
            AluEvent::new(5, Opcode::SLTU, 0, 0, 0),
            // 0 == LARGE < LARGE
            AluEvent::new(5, Opcode::SLTU, 0, LARGE, LARGE),
        ];

        prove_babybear_template(&mut segment);
    }
}
