use std::ops::{Add, Mul};

use slop_algebra::{ExtensionField, Field};

use super::ZeroCheckPoly;

/// This function will set the last variable to `alpha`.
pub fn zerocheck_fix_last_variable<
    K: Field,
    F: Field,
    EF: ExtensionField<F> + Add<K, Output = EF> + Mul<K, Output = EF> + From<K> + ExtensionField<K>,
    A,
>(
    poly: ZeroCheckPoly<K, F, EF, A>,
    alpha: EF,
) -> ZeroCheckPoly<EF, F, EF, A> {
    let num_real_entries = poly.num_real_entries();
    let preprocessed_columns =
        poly.preprocessed_columns.as_ref().map(|mle| mle.fix_last_variable(alpha));
    let global_columns = poly.global_columns.as_ref().map(|mle| mle.fix_last_variable(alpha));
    let main_columns = poly.main_columns.as_ref().map(|mle| mle.fix_last_variable(alpha));

    if num_real_entries == 0 {
        // If the chip is pure padding, it's contribution to sumcheck is just zero, we don't need
        // to propagate any eq_adjustment or any other data relevant to the sumcheck.
        return ZeroCheckPoly::new(
            poly.air_data,
            poly.zeta,
            preprocessed_columns,
            global_columns,
            main_columns,
            poly.eq_adjustment,
            poly.geq_value,
            poly.padded_row_adjustment,
            poly.virtual_geq.fix_last_variable(alpha),
        );
    }

    let (rest, last) = poly.zeta.split_at(poly.zeta.dimension() - 1);
    let last = *last[0];

    // When we are fixing the last variable, we can factor out one of the eq_terms, as it will be a
    // constant. That constant is equal to (alpha * last) + (1 - alpha) * (1 - last).
    let eq_adjustment =
        poly.eq_adjustment * ((alpha * last) + (EF::one() - alpha) * (EF::one() - last));

    let has_non_padded_vars = num_real_entries > 1;

    let geq_value = if has_non_padded_vars {
        EF::zero()
    } else {
        (EF::one() - poly.geq_value) * alpha + poly.geq_value
    };

    ZeroCheckPoly::new(
        poly.air_data,
        rest,
        preprocessed_columns,
        global_columns,
        main_columns,
        eq_adjustment,
        geq_value,
        poly.padded_row_adjustment,
        poly.virtual_geq.fix_last_variable(alpha),
    )
}
