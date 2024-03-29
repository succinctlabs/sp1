use p3_commit::{LagrangeSelectors, TwoAdicMultiplicativeCoset};

use p3_field::{AbstractField, TwoAdicField};
use sp1_recursion_compiler::prelude::*;

use crate::commit::PolynomialSpaceVariable;

/// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L55
#[derive(DslVariable, Clone, Copy)]
pub struct TwoAdicMultiplicativeCosetVariable<C: Config> {
    pub log_n: Var<C::N>,
    pub size: Var<C::N>,
    pub shift: Felt<C::F>,
    pub g: Felt<C::F>,
}

impl<C: Config> TwoAdicMultiplicativeCosetVariable<C> {
    /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L74
    pub fn first_point(&self) -> Felt<C::F> {
        self.shift
    }

    pub fn size(&self) -> Var<C::N> {
        self.size
    }

    pub fn gen(&self) -> Felt<C::F> {
        self.g
    }
}

impl<C: Config> FromConstant<C> for TwoAdicMultiplicativeCosetVariable<C>
where
    C::F: TwoAdicField,
{
    type Constant = TwoAdicMultiplicativeCoset<C::F>;

    fn eval_const(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        let log_d_val = value.log_n as u32;
        let g_val = C::F::two_adic_generator(value.log_n);
        // Initialize a domain.
        TwoAdicMultiplicativeCosetVariable::<C> {
            log_n: builder.eval::<Var<_>, _>(C::N::from_canonical_u32(log_d_val)),
            size: builder.eval::<Var<_>, _>(C::N::from_canonical_u32(1 << (log_d_val))),
            shift: builder.eval(value.shift),
            g: builder.eval(g_val),
        }
    }
}

pub fn new_coset<C: Config>(
    builder: &mut Builder<C>,
    log_degree: Usize<C::N>,
) -> TwoAdicMultiplicativeCosetVariable<C>
where
    C::F: TwoAdicField,
{
    let two_addicity = C::F::TWO_ADICITY;

    let is_valid: Var<_> = builder.eval(C::N::zero());
    let domain: TwoAdicMultiplicativeCosetVariable<C> = builder.uninit();
    for i in 1..=two_addicity {
        let i_f = C::N::from_canonical_usize(i);
        builder.if_eq(log_degree, i_f).then(|builder| {
            let constant = TwoAdicMultiplicativeCoset {
                log_n: i,
                shift: C::F::one(),
            };
            let domain_value: TwoAdicMultiplicativeCosetVariable<_> = builder.eval_const(constant);
            builder.assign(domain.clone(), domain_value);
            builder.assign(is_valid, C::N::one());
        });
    }

    builder.assert_var_eq(is_valid, C::N::one());

    domain
}

impl<C: Config> PolynomialSpaceVariable<C> for TwoAdicMultiplicativeCosetVariable<C>
where
    C::F: TwoAdicField,
{
    type Constant = p3_commit::TwoAdicMultiplicativeCoset<C::F>;

    /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L77
    fn next_point(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> Ext<<C as Config>::F, <C as Config>::EF> {
        builder.eval(point * self.gen())
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L112
    fn selectors_at_point(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> LagrangeSelectors<Ext<<C as Config>::F, <C as Config>::EF>> {
        let unshifted_point: Ext<_, _> = builder.eval(point * self.shift.inverse());
        let z_h_expr = builder
            .exp_power_of_2_v::<Ext<_, _>>(unshifted_point, Usize::Var(self.log_n))
            - C::EF::one();
        let z_h: Ext<_, _> = builder.eval(z_h_expr);

        LagrangeSelectors {
            is_first_row: builder.eval(z_h / (unshifted_point - C::EF::one())),
            is_last_row: builder.eval(z_h / (unshifted_point - self.gen().inverse())),
            is_transition: builder.eval(unshifted_point - self.gen().inverse()),
            inv_zeroifier: builder.eval(z_h.inverse()),
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L87
    fn zp_at_point(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> Ext<<C as Config>::F, <C as Config>::EF> {
        // Compute (point * domain.shift.inverse()).exp_power_of_2(domain.log_n) - Ext::one()
        let unshifted_power = builder
            .exp_power_of_2_v::<Ext<_, _>>(point * self.shift.inverse(), Usize::Var(self.log_n));
        builder.eval(unshifted_power - C::EF::one())
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L91
    fn split_domains(&self, builder: &mut Builder<C>, log_num_chunks: usize) -> Vec<Self> {
        let num_chunks = 1 << log_num_chunks;
        let log_n: Var<_> = builder.eval(self.log_n - C::N::from_canonical_usize(log_num_chunks));
        let size = builder.power_of_two_var(Usize::Var(log_n));

        let g_dom = self.gen();

        // We can compute a generator for the domain by computing g_dom^{log_num_chunks}
        let g = builder.exp_power_of_2_v::<Felt<C::F>>(g_dom, log_num_chunks);

        let domain_power: Felt<_> = builder.eval(C::F::one());
        let mut domains = vec![];

        for _ in 0..num_chunks {
            domains.push(TwoAdicMultiplicativeCosetVariable {
                log_n,
                size,
                shift: builder.eval(self.shift * domain_power),
                g,
            });
            builder.assign(domain_power, domain_power * g_dom);
        }
        domains
    }

    fn create_disjoint_domain(
        &self,
        builder: &mut Builder<C>,
        log_degree: Usize<<C as Config>::N>,
    ) -> Self {
        let domain = new_coset(builder, log_degree);
        builder.assign(domain.shift, self.shift * C::F::generator());

        domain
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use itertools::Itertools;
    use sp1_recursion_compiler::asm::VmBuilder;

    use super::*;
    use p3_commit::{Pcs, PolynomialSpace};
    use rand::{thread_rng, Rng};
    use sp1_core::stark::Dom;
    use sp1_core::{stark::StarkGenericConfig, utils::BabyBearPoseidon2};
    use sp1_recursion_core::runtime::Runtime;

    pub(crate) fn domain_assertions<F: TwoAdicField, C: Config<N = F, F = F>>(
        builder: &mut Builder<C>,
        domain: &TwoAdicMultiplicativeCosetVariable<C>,
        domain_val: &TwoAdicMultiplicativeCoset<F>,
        zeta_val: C::EF,
    ) {
        // Assert the domain parameters are the same.
        builder.assert_var_eq(domain.log_n, F::from_canonical_usize(domain_val.log_n));
        builder.assert_var_eq(domain.size, F::from_canonical_usize(1 << domain_val.log_n));
        builder.assert_felt_eq(domain.shift, domain_val.shift);
        // Get a random point.
        let zeta: Ext<_, _> = builder.eval(zeta_val.cons());

        // Compare the selector values of the reference and the builder.
        let sels_expected = domain_val.selectors_at_point(zeta_val);
        let sels = domain.selectors_at_point(builder, zeta);
        builder.assert_ext_eq(sels.is_first_row, sels_expected.is_first_row.cons());
        builder.assert_ext_eq(sels.is_last_row, sels_expected.is_last_row.cons());
        builder.assert_ext_eq(sels.is_transition, sels_expected.is_transition.cons());

        let zp_val = domain_val.zp_at_point(zeta_val);
        let zp = domain.zp_at_point(builder, zeta);
        builder.assert_ext_eq(zp, zp_val.cons());
    }

    #[test]
    fn test_domain() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type Challenger = <SC as StarkGenericConfig>::Challenger;
        type ScPcs = <SC as StarkGenericConfig>::Pcs;

        let mut rng = thread_rng();
        let config = SC::default();
        let pcs = config.pcs();
        let natural_domain_for_degree = |degree: usize| -> Dom<SC> {
            <ScPcs as Pcs<EF, Challenger>>::natural_domain_for_degree(pcs, degree)
        };

        // Initialize a builder.
        let mut builder = VmBuilder::<F, EF>::default();
        for i in 0..5 {
            let log_d_val = 10 + i;

            let log_quotient_degree = 2;

            // Initialize a reference doamin.
            let domain_val = natural_domain_for_degree(1 << log_d_val);
            let domain = builder.eval_const(domain_val);
            // builder.assert_felt_eq(domain.shift, domain_val.shift);
            let zeta_val = rng.gen::<EF>();
            domain_assertions(&mut builder, &domain, &domain_val, zeta_val);

            // Try a shifted domain.
            let disjoint_domain_val =
                domain_val.create_disjoint_domain(1 << (log_d_val + log_quotient_degree));
            let disjoint_domain = builder.eval_const(disjoint_domain_val);
            domain_assertions(
                &mut builder,
                &disjoint_domain,
                &disjoint_domain_val,
                zeta_val,
            );

            let log_degree: Usize<_> = builder.eval(Usize::Const(log_d_val) + log_quotient_degree);
            let disjoint_domain_gen = domain.create_disjoint_domain(&mut builder, log_degree);
            domain_assertions(
                &mut builder,
                &disjoint_domain_gen,
                &disjoint_domain_val,
                zeta_val,
            );

            // Now try splited domains
            let qc_domains_val = disjoint_domain_val.split_domains(1 << log_quotient_degree);
            for dom_val in qc_domains_val.iter() {
                let dom = builder.eval_const(*dom_val);
                domain_assertions(&mut builder, &dom, dom_val, zeta_val);
            }

            // Test the splitting of domains by the builder.
            let qc_domains = disjoint_domain.split_domains(&mut builder, log_quotient_degree);
            for (dom, dom_val) in qc_domains.iter().zip_eq(qc_domains_val.iter()) {
                domain_assertions(&mut builder, dom, dom_val, zeta_val);
            }
        }

        let program = builder.compile();

        let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
        runtime.run();
    }
}
