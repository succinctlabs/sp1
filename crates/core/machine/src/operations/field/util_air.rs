use p3_field::AbstractField;
use sp1_curves::params::FieldParameters;
use sp1_stark::air::{Polynomial, SP1AirBuilder};

pub fn eval_field_operation<AB: SP1AirBuilder, P: FieldParameters>(
    builder: &mut AB,
    p_vanishing: &Polynomial<AB::Expr>,
    p_witness_low: &Polynomial<AB::Expr>,
    p_witness_high: &Polynomial<AB::Expr>,
) {
    // Reconstruct and shift back the witness polynomial
    let limb: AB::Expr = AB::F::from_canonical_u32(2u32.pow(P::NB_BITS_PER_LIMB as u32)).into();

    let p_witness_shifted = p_witness_low + &(p_witness_high * limb.clone());

    // Shift down the witness polynomial. Shifting is needed to range check that each
    // coefficient w_i of the witness polynomial satisfies |w_i| < 2^WITNESS_OFFSET.
    let offset: AB::Expr = AB::F::from_canonical_u32(P::WITNESS_OFFSET as u32).into();
    let len = p_witness_shifted.coefficients().len();
    let p_witness = p_witness_shifted - Polynomial::new(vec![offset; len]);

    // Multiply by (x-2^NB_BITS_PER_LIMB) and make the constraint
    let root_monomial = Polynomial::new(vec![-limb, AB::F::one().into()]);

    let constraints = p_vanishing - &(p_witness * root_monomial);
    for constr in constraints.as_coefficients() {
        builder.assert_zero(constr);
    }
}
