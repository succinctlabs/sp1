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
    septic_curve::{SepticCurve, CURVE_WITNESS_DUMMY_POINT_X, CURVE_WITNESS_DUMMY_POINT_Y},
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
    pub fn get_digest(
        values: SepticBlock<u32>,
        is_receive: bool,
        kind: InteractionKind,
    ) -> (SepticCurve<F>, u8) {
        let x_start = SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(values.0[i]))
            + SepticExtension::from_base(F::from_canonical_u32((kind as u32) << 24));
        let (point, offset) = SepticCurve::<F>::lift_x(x_start);
        if !is_receive {
            return (point.neg(), offset);
        }
        (point, offset)
    }

    pub fn populate(
        &mut self,
        values: SepticBlock<u32>,
        is_receive: bool,
        is_real: bool,
        kind: InteractionKind,
        blu: &mut impl ByteRecord,
    ) {
        if is_real {
            let (point, offset) = Self::get_digest(values, is_receive, kind);
            self.offset = F::from_canonical_u8(offset);
            self.x_coordinate = SepticBlock::<F>::from(point.x.0);
            self.y_coordinate = SepticBlock::<F>::from(point.y.0);
            let range_check_value = if is_receive {
                point.y.0[6].as_canonical_u32() - 1
            } else {
                point.y.0[6].as_canonical_u32() - (F::ORDER_U32 + 1) / 2
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
        if is_real {
            blu.add_u8_range_checks(shard, &value.to_le_bytes());
            blu.add_u16_range_check(shard, shard as u16);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn populate_syscall(
        &mut self,
        shard: u32,
        clk_16: u16,
        clk_8: u8,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
        is_receive: bool,
        is_real: bool,
        blu: &mut impl ByteRecord,
    ) {
        self.populate(
            SepticBlock([shard, clk_16.into(), clk_8.into(), syscall_id, arg1, arg2, 0]),
            is_receive,
            is_real,
            InteractionKind::Syscall,
            blu,
        );
        if is_real {
            blu.add_u16_range_checks(shard, &[shard as u16, clk_16]);
            blu.add_u8_range_checks(shard, &[clk_8, syscall_id as u8]);
        }
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
    /// The first value in `values` must be a value range checked to u16.
    fn eval_single_digest<AB: SP1AirBuilder>(
        builder: &mut AB,
        values: [AB::Expr; 7],
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

        // Compute the message.
        let message = SepticExtension(values)
            + SepticExtension::<AB::Expr>::from_base(
                cols.offset.into() * AB::F::from_canonical_u32(1 << 16)
                    + AB::F::from_canonical_u32(kind as u32) * AB::F::from_canonical_u32(1 << 24),
            );

        // Compute a * m + b.
        let am_plus_b = SepticCurve::<AB::Expr>::universal_hash(message);

        let x = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.x_coordinate[i].into());

        // Constrain that when `is_real` is true, then `x == a * m + b`.
        builder.when(is_real).assert_septic_ext_eq(x.clone(), am_plus_b);

        // Constrain that y is a valid y-coordinate.
        let y = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.y_coordinate[i].into());

        // Constrain that `(x, y)` is a valid point on the curve.
        let y2 = y.square();
        let x3_2x_26z5 = SepticCurve::<AB::Expr>::curve_formula(x);

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

    #[allow(clippy::too_many_arguments)]
    pub fn eval_single_digest_memory<AB: SP1AirBuilder>(
        builder: &mut AB,
        shard: AB::Expr,
        clk: AB::Expr,
        addr: AB::Expr,
        value: [AB::Expr; 4],
        cols: GlobalInteractionOperation<AB::Var>,
        is_receive: bool,
        is_real: AB::Var,
    ) {
        let values = [
            shard.clone(),
            clk.clone(),
            addr.clone(),
            value[0].clone(),
            value[1].clone(),
            value[2].clone(),
            value[3].clone(),
        ];

        Self::eval_single_digest(
            builder,
            values,
            cols,
            is_receive,
            is_real,
            InteractionKind::Memory,
        );

        // Range check for message space.
        // Range check shard to be a valid u16.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            shard,
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real,
        );
        // Range check the word value to be valid u8 word.
        builder.slice_range_check_u8(&value, is_real);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval_single_digest_syscall<AB: SP1AirBuilder>(
        builder: &mut AB,
        shard: AB::Expr,
        clk_16: AB::Expr,
        clk_8: AB::Expr,
        syscall_id: AB::Expr,
        arg1: AB::Expr,
        arg2: AB::Expr,
        cols: GlobalInteractionOperation<AB::Var>,
        is_receive: bool,
        is_real: AB::Var,
    ) {
        let values = [
            shard.clone(),
            clk_16.clone(),
            clk_8.clone(),
            syscall_id.clone(),
            arg1.clone(),
            arg2.clone(),
            AB::Expr::zero(),
        ];

        Self::eval_single_digest(
            builder,
            values,
            cols,
            is_receive,
            is_real,
            InteractionKind::Syscall,
        );

        // Range check for message space.
        // Range check shard to be a valid u16.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            shard,
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real,
        );

        // Range check clk_8 and syscall_id to be u8.
        builder.slice_range_check_u8(&[clk_8, syscall_id], is_real);

        // Range check clk_16 to be u16.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            clk_16,
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real,
        );
    }
}
