use p3_air::{Air, BaseAir};

use super::columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS};
use super::ShaCompressChip;
use crate::air::CurtaAirBuilder;
use crate::operations::{
    AddOperation, AndOperation, FixedRotateRightOperation, NotOperation, XorOperation,
};
use p3_matrix::MatrixRowSlices;
use std::borrow::Borrow;

impl<F> BaseAir<F> for ShaCompressChip {
    fn width(&self) -> usize {
        NUM_SHA_COMPRESS_COLS
    }
}

impl<AB> Air<AB> for ShaCompressChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ShaCompressCols<AB::Var> = main.row_slice(0).borrow();

        builder.constraint_memory_access(
            local.segment,
            local.clk,
            local.mem_addr,
            local.mem,
            local.is_initialize + local.is_compression + local.is_finalize,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.e,
            6,
            local.e_rr_6,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.e,
            11,
            local.e_rr_11,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.e,
            25,
            local.e_rr_25,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.e_rr_6.value,
            local.e_rr_11.value,
            local.s1_intermediate,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s1_intermediate.value,
            local.e_rr_25.value,
            local.s1,
        );

        AndOperation::<AB::F>::eval(builder, local.e, local.f, local.e_and_f);
        NotOperation::<AB::F>::eval(builder, local.e, local.e_not);
        AndOperation::<AB::F>::eval(builder, local.e_not.value, local.g, local.e_not_and_g);
        XorOperation::<AB::F>::eval(
            builder,
            local.e_and_f.value,
            local.e_not_and_g.value,
            local.ch,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.a,
            2,
            local.a_rr_2,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.a,
            13,
            local.a_rr_13,
            local.is_compression,
        );
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.a,
            22,
            local.a_rr_22,
            local.is_compression,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.a_rr_2.value,
            local.a_rr_13.value,
            local.s0_intermediate,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.s0_intermediate.value,
            local.a_rr_22.value,
            local.s0,
        );

        AndOperation::<AB::F>::eval(builder, local.a, local.b, local.a_and_b);
        AndOperation::<AB::F>::eval(builder, local.a, local.c, local.a_and_c);
        AndOperation::<AB::F>::eval(builder, local.b, local.c, local.b_and_c);
        XorOperation::<AB::F>::eval(
            builder,
            local.a_and_b.value,
            local.a_and_c.value,
            local.maj_intermediate,
        );
        XorOperation::<AB::F>::eval(
            builder,
            local.maj_intermediate.value,
            local.b_and_c.value,
            local.maj,
        );

        // This seems correct.
        AddOperation::<AB::F>::eval(
            builder,
            local.s0.value,
            local.maj.value,
            local.temp2,
            local.is_compression,
        );

        // This seems incorrect.
        AddOperation::<AB::F>::eval(
            builder,
            local.d,
            local.temp1.value,
            local.d_add_temp1,
            local.is_compression,
        );

        // This seems correct also.
        AddOperation::<AB::F>::eval(
            builder,
            local.temp1.value,
            local.temp2.value,
            local.temp1_add_temp2,
            local.is_compression,
        );
    }
}
