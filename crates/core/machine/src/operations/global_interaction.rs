use super::poseidon2::permutation::Poseidon2Cols;
use super::poseidon2::trace::populate_perm_deg3;
use super::poseidon2::Poseidon2Operation;
use super::poseidon2::{
    air::{eval_external_round, eval_internal_rounds},
    NUM_EXTERNAL_ROUNDS,
};
use p3_air::AirBuilder;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use sp1_core_executor::ByteOpcode;
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::SP1AirBuilder,
    septic_curve::{SepticCurve, CURVE_WITNESS_DUMMY_POINT_X, CURVE_WITNESS_DUMMY_POINT_Y},
    septic_extension::{SepticBlock, SepticExtension},
};

/// A set of columns needed to compute the global interaction elliptic curve digest.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct GlobalInteractionOperation<T: Copy> {
    pub offset_bits: [T; 8],
    pub x_coordinate: SepticBlock<T>,
    pub y_coordinate: SepticBlock<T>,
    pub y6_bit_decomp: [T; 30],
    pub range_check_witness: T,
    pub permutation: Poseidon2Operation<T>,
}

impl<F: PrimeField32> GlobalInteractionOperation<F> {
    pub fn get_digest(
        values: SepticBlock<u32>,
        is_receive: bool,
        kind: u8,
    ) -> (SepticCurve<F>, u8, [F; 16], [F; 16]) {
        let x_start = SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(values.0[i]))
            + SepticExtension::from_base(F::from_canonical_u32((kind as u32) << 16));
        let (point, offset, m_trial, m_hash) = SepticCurve::<F>::lift_x(x_start);
        if !is_receive {
            return (point.neg(), offset, m_trial, m_hash);
        }
        (point, offset, m_trial, m_hash)
    }

    pub fn populate(
        &mut self,
        values: SepticBlock<u32>,
        is_receive: bool,
        is_real: bool,
        kind: u8,
    ) {
        if is_real {
            let (point, offset, m_trial, m_hash) = Self::get_digest(values, is_receive, kind);
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
            self.permutation = populate_perm_deg3(m_trial, Some(m_hash));

            assert_eq!(self.x_coordinate.0[0], self.permutation.permutation.perm_output()[0]);
        } else {
            self.populate_dummy();
            assert_eq!(self.x_coordinate.0[0], self.permutation.permutation.perm_output()[0]);
        }
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
        self.permutation = populate_perm_deg3([F::zero(); 16], None);
    }
}

impl<F: Field> GlobalInteractionOperation<F> {
    /// Constrain that the elliptic curve point for the global interaction is correctly derived.
    pub fn eval_single_digest<AB: SP1AirBuilder + p3_air::PairBuilder>(
        builder: &mut AB,
        values: [AB::Expr; 7],
        cols: GlobalInteractionOperation<AB::Var>,
        is_receive: AB::Expr,
        is_send: AB::Expr,
        is_real: AB::Var,
        kind: AB::Var,
    ) {
        // Constrain that the `is_real` is boolean.
        builder.assert_bool(is_real);

        // Compute the offset and range check each bits, ensuring that the offset is a byte.
        let mut offset = AB::Expr::zero();
        for i in 0..8 {
            builder.assert_bool(cols.offset_bits[i]);
            offset = offset.clone() + cols.offset_bits[i] * AB::F::from_canonical_u32(1 << i);
        }

        // Range check the first element in the message to be a u16 so that we can encode the interaction kind in the upper 8 bits.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            values[0].clone(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real,
        );

        // Turn the message into a hash input. Only the first 8 elements are non-zero, as the rate of the Poseidon2 hash is 8.
        // Combining `values[0]` with `kind` is safe, as `values[0]` is range checked to be u16, and `kind` is known to be u8.
        let m_trial = [
            values[0].clone() + AB::Expr::from_canonical_u32(1 << 16) * kind,
            values[1].clone(),
            values[2].clone(),
            values[3].clone(),
            values[4].clone(),
            values[5].clone(),
            values[6].clone(),
            offset.clone(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ];

        // Constrain the input of the permutation to be the message.
        for i in 0..16 {
            builder.when(is_real).assert_eq(
                cols.permutation.permutation.external_rounds_state()[0][i].into(),
                m_trial[i].clone(),
            );
        }

        // Constrain the permutation.
        for r in 0..NUM_EXTERNAL_ROUNDS {
            eval_external_round(builder, &cols.permutation.permutation, r);
        }
        eval_internal_rounds(builder, &cols.permutation.permutation);

        // Constrain that when `is_real` is true, the x-coordinate is the hash of the message.
        let m_hash = cols.permutation.permutation.perm_output();
        for i in 0..7 {
            builder.when(is_real).assert_eq(cols.x_coordinate[i].into(), m_hash[i]);
        }
        let x = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.x_coordinate[i].into());
        let y = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.y_coordinate[i].into());

        // Constrain that `(x, y)` is a valid point on the curve.
        let y2 = y.square();
        let x3_2x_26z5 = SepticCurve::<AB::Expr>::curve_formula(x);
        builder.assert_septic_ext_eq(y2, x3_2x_26z5);

        // Constrain that `0 <= y6_value < (p - 1) / 2 = 2^30 - 2^26`.
        // Decompose `y6_value` into 30 bits, and then constrain that the top 4 bits cannot be all 1.
        // To do this, check that the sum of the top 4 bits is not equal to 4, which can be done by providing an inverse.
        let mut y6_value = AB::Expr::zero();
        let mut top_4_bits = AB::Expr::zero();
        for i in 0..30 {
            builder.assert_bool(cols.y6_bit_decomp[i]);
            y6_value = y6_value.clone() + cols.y6_bit_decomp[i] * AB::F::from_canonical_u32(1 << i);
            if i >= 26 {
                top_4_bits = top_4_bits.clone() + cols.y6_bit_decomp[i];
            }
        }
        // If `is_real` is true, check that `top_4_bits - 4` is non-zero, by checking `range_check_witness` is an inverse of it.
        builder.when(is_real).assert_eq(
            cols.range_check_witness * (top_4_bits - AB::Expr::from_canonical_u8(4)),
            AB::Expr::one(),
        );

        // Constrain that y has correct sign.
        // If it's a receive: `1 <= y_6 <= (p - 1) / 2`, so `0 <= y_6 - 1 = y6_value < (p - 1) / 2`.
        // If it's a send: `(p + 1) / 2 <= y_6 <= p - 1`, so `0 <= y_6 - (p + 1) / 2 = y6_value < (p - 1) / 2`.
        builder.when(is_receive).assert_eq(y.0[6].clone(), AB::Expr::one() + y6_value.clone());
        builder.when(is_send).assert_eq(
            y.0[6].clone(),
            AB::Expr::from_canonical_u32((1 << 30) - (1 << 26) + 1) + y6_value.clone(),
        );
    }
}
