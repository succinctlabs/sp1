use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{extension::BinomiallyExtendable, AbstractField};
use p3_matrix::MatrixRowSlices;

use crate::{
    air::{Extension, SP1AirBuilder, DEGREE},
    memory::MemoryCols,
    operations::DivExtOperation,
};

use super::{
    columns::{
        FriFoldCols, ALPHA_END_IDX, ALPHA_POW_ADDR_IDX, ALPHA_START_IDX, NUM_FRI_FOLD_COLS,
        NUM_INPUT_ELMS, NUM_OUTPUT_ELMS, P_AT_X_IDX, P_AT_Z_END_IDX, P_AT_Z_START_IDX, RO_ADDR_IDX,
        X_IDX, Z_END_IDX, Z_START_IDX,
    },
    FriFoldChip,
};

impl<F> BaseAir<F> for FriFoldChip {
    fn width(&self) -> usize {
        NUM_FRI_FOLD_COLS
    }
}

impl<AB> Air<AB> for FriFoldChip
where
    AB: SP1AirBuilder,
    AB::F: BinomiallyExtendable<4>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &FriFoldCols<AB::Var> = main.row_slice(0).borrow();
        let next: &FriFoldCols<AB::Var> = main.row_slice(1).borrow();

        builder.assert_bool(local.is_real);

        builder
            .when(local.is_real)
            .assert_one(local.is_input + local.is_output);

        builder.when_first_row().assert_one(local.is_input);
        builder
            .when_transition()
            .when(local.is_input)
            .assert_one(next.is_output);
        builder
            .when_transition()
            .when(local.is_output)
            .when(next.is_real)
            .assert_one(next.is_input);

        // Constrain input mem slice
        for i in 0..NUM_INPUT_ELMS as u32 {
            builder.constraint_memory_access(
                local.shard,
                local.clk,
                local.input_slice_ptr + AB::Expr::from_canonical_u32(i * 4),
                &local.input_slice_read_records[i as usize],
                local.is_input,
            );
        }

        let x: AB::Expr = local.input_slice_read_records[X_IDX].value().reduce::<AB>();
        let alpha = Extension::<AB::Expr>(
            local.input_slice_read_records[ALPHA_START_IDX..ALPHA_END_IDX + 1]
                .iter()
                .map(|record| record.value().reduce::<AB>())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        let z = Extension(
            local.input_slice_read_records[Z_START_IDX..Z_END_IDX + 1]
                .iter()
                .map(|record| record.value().reduce::<AB>())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        let p_at_z = Extension(
            local.input_slice_read_records[P_AT_Z_START_IDX..P_AT_Z_END_IDX + 1]
                .iter()
                .map(|record| record.value().reduce::<AB>())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        let p_at_x: AB::Expr = local.input_slice_read_records[P_AT_X_IDX]
            .value()
            .reduce::<AB>();

        // Constrain output mem slice
        for i in 0..NUM_OUTPUT_ELMS as u32 {
            builder.constraint_memory_access(
                local.shard,
                local.clk,
                local.output_slice_ptr + AB::Expr::from_canonical_u32(i * 4),
                &local.output_slice_read_records[i as usize],
                local.is_input,
            );
        }

        let ro_addr: AB::Expr = local.output_slice_read_records[RO_ADDR_IDX]
            .value()
            .reduce::<AB>();
        let alpha_pow_addr: AB::Expr = local.output_slice_read_records[ALPHA_POW_ADDR_IDX]
            .value()
            .reduce::<AB>();
        builder
            .when(local.is_input)
            .assert_eq(ro_addr.clone(), local.ro_addr);
        builder
            .when(local.is_input)
            .assert_eq(ro_addr.clone(), next.ro_addr);
        builder
            .when(local.is_input)
            .assert_eq(alpha_pow_addr.clone(), local.alpha_pow_addr);
        builder
            .when(local.is_input)
            .assert_eq(alpha_pow_addr.clone(), next.alpha_pow_addr);

        // Constrain ro and alpha_pow
        for i in 0..DEGREE {
            builder.constraint_memory_access(
                local.shard,
                local.clk,
                local.ro_addr + AB::Expr::from_canonical_usize(i * 4),
                &local.ro_rw_records[i],
                local.is_real,
            );

            builder.constraint_memory_access(
                local.shard,
                local.clk,
                local.alpha_pow_addr + AB::Expr::from_canonical_usize(i * 4),
                &local.alpha_pow_rw_records[i],
                local.is_real,
            );
        }

        let ro_input = Extension(
            local.ro_rw_records[0..DEGREE]
                .iter()
                .map(|record| record.value().reduce::<AB>())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        let alpha_pow_input = Extension(
            local.alpha_pow_rw_records[0..DEGREE]
                .iter()
                .map(|record| record.value().reduce::<AB>())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        // // let quotient = (-p_at_z + p_at_x) / (-z + x);
        // // ro[log_height] += alpha_pow[log_height] * quotient;
        // // alpha_pow[log_height] *= alpha;

        builder
            .when(local.is_input)
            .assert_eq(p_at_x.clone(), AB::Expr::from_canonical_u32(777132171));

        builder.when(local.is_input).assert_eq(
            p_at_z.as_base_slice()[0].clone(),
            AB::Expr::from_canonical_u32(1257978304),
        );

        let num = p_at_z.neg::<AB>().add::<AB>(&Extension::from::<AB>(p_at_x));
        let den = z
            .clone()
            .neg::<AB>()
            .add::<AB>(&Extension::from::<AB>(x.clone()));

        let ro_output = ro_input.add::<AB>(
            &alpha_pow_input
                .clone()
                .mul::<AB>(&Extension::from_var::<AB>(local.div_ext_op.result)),
        );
        let alpha_pow_output = alpha_pow_input.mul::<AB>(&alpha);

        DivExtOperation::<AB::F>::eval(builder, num, den, local.div_ext_op, local.is_input.into());

        // Verify that the calculated ro and alpha_pow are equal to their memory values in the
        // next row
        for i in 0..DEGREE {
            builder.when_transition().when(local.is_input).assert_eq(
                ro_output.0[i].clone(),
                next.ro_rw_records[i].value().reduce::<AB>(),
            );
            builder.when_transition().when(local.is_input).assert_eq(
                alpha_pow_output.0[i].clone(),
                next.alpha_pow_rw_records[i].value().reduce::<AB>(),
            );
        }
    }
}
