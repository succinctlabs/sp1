use crate::air::WordAirBuilder;
use p3_air::AirBuilder;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use sp1_core_executor::events::{ByteLookupEvent, ByteRecord};
use sp1_core_executor::ByteOpcode;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::SepticExtensionAirBuilder;
use sp1_stark::{
    air::SP1AirBuilder,
    septic_curve::{
        SepticCurve, A_EC_LOGUP, B_EC_LOGUP, CURVE_WITNESS_DUMMY_POINT_X,
        CURVE_WITNESS_DUMMY_POINT_Y,
    },
    septic_extension::{SepticBlock, SepticExtension},
    InteractionKind, Word,
};

/// A set of columns needed to compute the global interaction elliptic curve digest.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct GlobalInteractionOperation<T> {
    pub offset: T,
    pub x_coordinate: SepticBlock<T>,
    pub y_coordinate: SepticBlock<T>,
    pub y6_byte_decomp: Word<T>,
}

impl<F: PrimeField32> GlobalInteractionOperation<F> {
    pub fn populate(
        &mut self,
        values: SepticBlock<u32>,
        is_receive: bool,
        is_real: bool,
        kind: InteractionKind,
        blu: &mut impl ByteRecord,
    ) {
        if is_real {
            let x_start =
                SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(values.0[i]))
                    + SepticExtension::from_base(F::from_canonical_u32((kind as u32) << 24));
            let (point, offset) = SepticCurve::<F>::lift_x(x_start);
            let x_coordinate = point.x;
            let mut y_coordinate = point.y;
            self.offset = F::from_canonical_u8(offset);
            self.x_coordinate = SepticBlock::<F>::from(x_coordinate.0);
            if !is_receive {
                y_coordinate = -y_coordinate;
            }
            self.y_coordinate = SepticBlock::<F>::from(y_coordinate.0);
            let range_check_value = if is_receive {
                y_coordinate.0[6].as_canonical_u32() - 1
            } else {
                y_coordinate.0[6].as_canonical_u32() - (F::ORDER_U32 + 1) / 2
            };
            self.y6_byte_decomp = Word::from(range_check_value);
            blu.add_byte_lookup_event(ByteLookupEvent {
                shard: values[0],
                opcode: ByteOpcode::U8Range,
                a1: 0,
                a2: 0,
                b: offset,
                c: 0,
            });
            blu.add_byte_lookup_event(ByteLookupEvent {
                shard: values[0],
                opcode: ByteOpcode::LTU,
                a1: 1,
                a2: 0,
                b: (range_check_value >> 24) as u8,
                c: 60,
            });
            blu.add_u8_range_checks(values[0], &range_check_value.to_le_bytes());
        } else {
            self.populate_dummy();
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn populate_memory(
        &mut self,
        shard: u32,
        clk: u32,
        addr: u32,
        value: u32,
        is_receive: bool,
        is_real: bool,
        blu: &mut impl ByteRecord,
    ) {
        self.populate(
            SepticBlock([
                shard,
                clk,
                addr,
                value & 255,
                (value >> 8) & 255,
                (value >> 16) & 255,
                (value >> 24) & 255,
            ]),
            is_receive,
            is_real,
            InteractionKind::Memory,
            blu,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn populate_syscall(
        &mut self,
        shard: u32,
        clk: u32,
        nonce: u32,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
        is_receive: bool,
        is_real: bool,
        blu: &mut impl ByteRecord,
    ) {
        self.populate(
            SepticBlock([shard, clk, nonce, syscall_id, arg1, arg2, 0]),
            is_receive,
            is_real,
            InteractionKind::Syscall,
            blu,
        );
    }

    pub fn populate_dummy(&mut self) {
        self.offset = F::from_canonical_u32(0);
        self.y6_byte_decomp = Word::from(0);
        self.x_coordinate = SepticBlock::<F>::from_base_fn(|i| {
            F::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_X[i])
        });
        self.y_coordinate = SepticBlock::<F>::from_base_fn(|i| {
            F::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_Y[i])
        });
    }
}

impl<F: Field> GlobalInteractionOperation<F> {
    /// Constrain that the y coordinate is correct decompression, and send the resulting digest coordinate to the permutation trace.
    /// In this function, `values` should have length 7 with first value being the `shard`.
    pub fn eval_single_digest<AB: SP1AirBuilder>(
        builder: &mut AB,
        values: Vec<AB::Expr>,
        cols: GlobalInteractionOperation<AB::Var>,
        is_receive: bool,
        is_real: AB::Var,
        kind: InteractionKind,
    ) {
        // Constrain that the `is_real` is boolean.
        builder.assert_bool(is_real);

        // Constrain that the `offset` is a byte.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
            AB::Expr::zero(),
            cols.offset,
            AB::Expr::zero(),
            is_real,
        );

        // Compute the message. The first entry is value (shard) || offset || InteractionKind.
        let message = SepticExtension::<AB::Expr>::from_base_fn(|i| values[i].clone())
            + SepticExtension::<AB::Expr>::from_base(
                cols.offset.into() * AB::F::from_canonical_u32(1 << 16)
                    + AB::F::from_canonical_u32(kind as u32) * AB::F::from_canonical_u32(1 << 24),
            );

        let a_ec_logup = SepticExtension::<AB::Expr>::from_base_fn(|i| {
            AB::Expr::from_canonical_u32(A_EC_LOGUP[i])
        });

        let b_ec_logup = SepticExtension::<AB::Expr>::from_base_fn(|i| {
            AB::Expr::from_canonical_u32(B_EC_LOGUP[i])
        });

        // Compute a * m + b.
        let am_plus_b = a_ec_logup * message + b_ec_logup;

        let x = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.x_coordinate[i].into());

        // Constrain that when `is_real` is true, then `x == a * m + b`.
        builder.when(is_real).assert_septic_ext_eq(x.clone(), am_plus_b);

        // Constrain that y is a valid y-coordinate.
        let y = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.y_coordinate[i].into());

        // Constrain that `(x, y)` is a valid point on the curve.
        let y2 = y.square();
        let x3_2x_26z5 = x.cube()
            + x.clone() * AB::Expr::two()
            + SepticExtension::<AB::Expr>::from_base_slice(&[
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::from_canonical_u32(26),
                AB::Expr::zero(),
            ]);

        builder.assert_septic_ext_eq(y2, x3_2x_26z5);

        // Constrain that y6_byte_decomp is a valid Word.
        builder.slice_range_check_u8(&cols.y6_byte_decomp.0, is_real);

        let y6_value = cols.y6_byte_decomp.reduce::<AB>();

        // Constrain that y has correct sign.
        // If it's a receive: 0 <= y_6 - 1 < (p - 1) / 2 = 2^30 - 2^26
        // If it's a send: 0 <= y_6 - (p + 1) / 2 < (p - 1) / 2 = 2^30 - 2^26
        if is_receive {
            builder.when(is_real).assert_eq(y.0[6].clone(), AB::Expr::one() + y6_value);
        } else {
            builder.when(is_real).assert_eq(
                y.0[6].clone(),
                AB::Expr::from_canonical_u32((1 << 30) - (1 << 26) + 1) + y6_value,
            );
        }

        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::LTU as u8),
            AB::Expr::one(),
            cols.y6_byte_decomp[3],
            AB::Expr::from_canonical_u32(60),
            is_real,
        );
    }
}
