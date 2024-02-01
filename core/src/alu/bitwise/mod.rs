use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word};
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::runtime::{Opcode, Segment};
use crate::utils::{pad_to_power_of_two, Chip};

/// The number of main trace columns for `BitwiseChip`.
pub const NUM_BITWISE_COLS: usize = size_of::<BitwiseCols<u8>>();

/// A chip that implements bitwise operations for the opcodes XOR, OR, and AND.
#[derive(Default)]
pub struct BitwiseChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
pub struct BitwiseCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// If the opcode is XOR.
    pub is_xor: T,

    // If the opcode is OR.
    pub is_or: T,

    /// If the opcode is AND.
    pub is_and: T,
}

impl<F: PrimeField> Chip<F> for BitwiseChip {
    fn name(&self) -> String {
        "Bitwise".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = segment
            .bitwise_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_BITWISE_COLS];
                let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
                let a = event.a.to_le_bytes();
                let b = event.b.to_le_bytes();
                let c = event.c.to_le_bytes();

                cols.a = Word::from(event.a);
                cols.b = Word::from(event.b);
                cols.c = Word::from(event.c);

                cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
                cols.is_or = F::from_bool(event.opcode == Opcode::OR);
                cols.is_and = F::from_bool(event.opcode == Opcode::AND);

                for ((b_a, b_b), b_c) in a.into_iter().zip(b).zip(c) {
                    let byte_event = ByteLookupEvent {
                        opcode: ByteOpcode::from(event.opcode),
                        a1: b_a as u32,
                        a2: 0,
                        b: b_b as u32,
                        c: b_c as u32,
                    };
                    segment
                        .byte_lookups
                        .entry(byte_event)
                        .and_modify(|i| *i += 1)
                        .or_insert(1);
                }

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
}

impl<F> BaseAir<F> for BitwiseChip {
    fn width(&self) -> usize {
        NUM_BITWISE_COLS
    }
}

impl<AB> Air<AB> for BitwiseChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &BitwiseCols<AB::Var> = main.row_slice(0).borrow();

        // Get the opcode for the operation.
        let opcode = local.is_xor * ByteOpcode::XOR.as_field::<AB::F>()
            + local.is_or * ByteOpcode::OR.as_field::<AB::F>()
            + local.is_and * ByteOpcode::AND.as_field::<AB::F>();

        // Get a multiplicity of `1` only for a true row.
        let mult = local.is_xor + local.is_or + local.is_and;
        for ((a, b), c) in local.a.into_iter().zip(local.b).zip(local.c) {
            builder.send_byte(opcode.clone(), a, b, c, mult.clone());
        }

        // Receive the arguments.
        builder.receive_alu(
            local.is_xor * Opcode::XOR.as_field::<AB::F>()
                + local.is_or * Opcode::OR.as_field::<AB::F>()
                + local.is_and * Opcode::AND.as_field::<AB::F>(),
            local.a,
            local.b,
            local.c,
            local.is_xor + local.is_or + local.is_and,
        );

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(
            local.a[0] * local.b[0] * local.c[0] - local.a[0] * local.b[0] * local.c[0],
        );
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;

    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use rand::thread_rng;

    use super::BitwiseChip;
    use crate::alu::AluEvent;
    use crate::runtime::{Opcode, Segment};
    use crate::utils::{BabyBearPoseidon2, Chip, StarkUtils};

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.bitwise_events = vec![AluEvent::new(0, Opcode::XOR, 25, 10, 19)];
        let chip = BitwiseChip::default();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new(&mut thread_rng());
        let mut challenger = config.challenger();

        let mut segment = Segment::default();
        segment.bitwise_events = [
            AluEvent::new(0, Opcode::XOR, 25, 10, 19),
            AluEvent::new(0, Opcode::OR, 27, 10, 19),
            AluEvent::new(0, Opcode::AND, 2, 10, 19),
        ]
        .repeat(1000);
        let chip = BitwiseChip::default();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
