use crate::air::WordAirBuilder;
use p3_air::AirBuilder;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use sp1_core_executor::events::ByteRecord;
use sp1_core_executor::ByteOpcode;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::SepticExtensionAirBuilder;
use sp1_stark::{
    air::SP1AirBuilder,
    septic_curve::{SepticCurve, CURVE_WITNESS_DUMMY_POINT_X, CURVE_WITNESS_DUMMY_POINT_Y},
    septic_extension::{SepticBlock, SepticExtension},
    InteractionKind,
};

/// A set of columns needed to compute the global interaction elliptic curve digest.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct GlobalInteractionOperation<T: Copy> {
    pub offset_bits: [T; 8],
    pub x_coordinate: SepticBlock<T>,
    pub y_coordinate: SepticBlock<T>,
    pub y6_bit_decomp: [T; 30],
    pub range_check_witness: T,
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
    ) {
        if is_real {
            let (point, offset) = Self::get_digest(values, is_receive, kind);
            for i in 0..8 {
                self.offset_bits[i] = F::from_canonical_u8((offset >> i) & 1);
            }
            self.x_coordinate = SepticBlock::<F>::from(point.x.0);
            self.y_coordinate = SepticBlock::<F>::from(point.y.0);
            let range_check_value = if is_receive {
                point.y.0[6].as_canonical_u32() - 1
            } else {
                point.y.0[6].as_canonical_u32() - (F::ORDER_U32 + 1) / 2
            };
            let mut top_4_bits = F::zero();
            for i in 0..30 {
                self.y6_bit_decomp[i] = F::from_canonical_u32((range_check_value >> i) & 1);
                if i >= 26 {
                    top_4_bits += self.y6_bit_decomp[i];
                }
            }
            top_4_bits -= F::from_canonical_u32(4);
            self.range_check_witness = top_4_bits.inverse();
        } else {
            self.populate_dummy();
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn populate_memory_range_check_witness(
        &self,
        shard: u32,
        value: u32,
        is_real: bool,
        blu: &mut impl ByteRecord,
    ) {
        if is_real {
            blu.add_u8_range_checks(shard, &value.to_le_bytes());
            blu.add_u16_range_check(shard, shard as u16);
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
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn populate_syscall_range_check_witness(
        &self,
        shard: u32,
        clk_16: u16,
        clk_8: u8,
        syscall_id: u32,
        is_real: bool,
        blu: &mut impl ByteRecord,
    ) {
        if is_real {
            blu.add_u16_range_checks(shard, &[shard as u16, clk_16]);
            blu.add_u8_range_checks(shard, &[clk_8, syscall_id as u8]);
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
    ) {
        self.populate(
            SepticBlock([shard, clk_16.into(), clk_8.into(), syscall_id, arg1, arg2, 0]),
            is_receive,
            is_real,
            InteractionKind::Syscall,
        );
    }

    pub fn populate_dummy(&mut self) {
        for i in 0..8 {
            self.offset_bits[i] = F::zero();
        }
        self.x_coordinate = SepticBlock::<F>::from_base_fn(|i| {
            F::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_X[i])
        });
        self.y_coordinate = SepticBlock::<F>::from_base_fn(|i| {
            F::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_Y[i])
        });
        for i in 0..30 {
            self.y6_bit_decomp[i] = F::zero();
        }
        self.range_check_witness = F::zero();
    }
}

impl<F: Field> GlobalInteractionOperation<F> {
    /// Constrain that the y coordinate is correct decompression, and send the resulting digest coordinate to the permutation trace.
    /// The first value in `values` must be a value range checked to u16.
    pub fn eval_single_digest<AB: SP1AirBuilder>(
        builder: &mut AB,
        values: [AB::Expr; 7],
        cols: GlobalInteractionOperation<AB::Var>,
        is_receive: AB::Expr,
        is_send: AB::Expr,
        is_real: AB::Var,
        kind: InteractionKind,
    ) {
        // Constrain that the `is_real` is boolean.
        builder.assert_bool(is_real);

        // Compute the offset and range check each bits, ensuring that the offset is a byte.
        let mut offset = AB::Expr::zero();
        for i in 0..8 {
            builder.assert_bool(cols.offset_bits[i]);
            offset = offset.clone() + cols.offset_bits[i] * AB::F::from_canonical_u32(1 << i);
        }

        // Compute the message.
        let message = SepticExtension(values)
            + SepticExtension::<AB::Expr>::from_base(
                offset * AB::F::from_canonical_u32(1 << 16)
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

        let mut y6_value = AB::Expr::zero();
        let mut top_4_bits = AB::Expr::zero();
        for i in 0..30 {
            builder.assert_bool(cols.y6_bit_decomp[i]);
            y6_value = y6_value.clone() + cols.y6_bit_decomp[i] * AB::F::from_canonical_u32(1 << i);
            if i >= 26 {
                top_4_bits = top_4_bits.clone() + cols.y6_bit_decomp[i];
            }
        }
        top_4_bits = top_4_bits.clone() - AB::Expr::from_canonical_u32(4);
        builder.when(is_real).assert_eq(cols.range_check_witness * top_4_bits, AB::Expr::one());

        // Constrain that y has correct sign.
        // If it's a receive: 0 <= y_6 - 1 < (p - 1) / 2 = 2^30 - 2^26
        // If it's a send: 0 <= y_6 - (p + 1) / 2 < (p - 1) / 2 = 2^30 - 2^26
        builder
            .when(is_receive.clone())
            .assert_eq(y.0[6].clone(), AB::Expr::one() + y6_value.clone());
        builder.when(is_send).assert_eq(
            y.0[6].clone(),
            AB::Expr::from_canonical_u32((1 << 30) - (1 << 26) + 1) + y6_value.clone(),
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
        is_receive: AB::Expr,
        is_send: AB::Expr,
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
            is_send,
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
        is_receive: AB::Expr,
        is_send: AB::Expr,
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
            is_send,
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
