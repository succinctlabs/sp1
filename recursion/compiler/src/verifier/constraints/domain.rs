use p3_commit::LagrangeSelectors;

use crate::{
    ir::{Config, Felt, Usize},
    prelude::{Builder, Ext, SymbolicFelt, Var},
};
use p3_field::{AbstractField, TwoAdicField};

/// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L55
pub struct TwoAdicMultiplicativeCoset<C: Config> {
    pub log_n: Usize<C::N>,
    pub size: Usize<C::N>,
    pub shift: Felt<C::F>,
    pub g: Felt<C::F>,
}

impl<C: Config> TwoAdicMultiplicativeCoset<C> {
    /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L74
    pub fn first_point(&self) -> Felt<C::F> {
        self.shift
    }

    pub fn size(&self) -> Usize<C::N> {
        self.size
    }

    pub fn gen(&self) -> Felt<C::F> {
        self.g
    }
}

impl<C: Config> Builder<C> {
    pub fn const_domain(
        &mut self,
        domain: &p3_commit::TwoAdicMultiplicativeCoset<C::F>,
    ) -> TwoAdicMultiplicativeCoset<C>
    where
        C::F: TwoAdicField,
    {
        let log_d_val = domain.log_n as u32;
        let g_val = C::F::two_adic_generator(domain.log_n);
        // Initialize a domain.
        TwoAdicMultiplicativeCoset::<C> {
            log_n: self
                .eval::<Var<_>, _>(C::N::from_canonical_u32(log_d_val))
                .into(),
            size: self
                .eval::<Var<_>, _>(C::N::from_canonical_u32(1 << (log_d_val)))
                .into(),
            shift: self.eval(domain.shift),
            g: self.eval(g_val),
        }
    }
    /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L77
    pub fn next_point(
        &mut self,
        domain: &TwoAdicMultiplicativeCoset<C>,
        point: Ext<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        self.eval(point * domain.gen())
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L112
    pub fn selectors_at_point(
        &mut self,
        domain: &TwoAdicMultiplicativeCoset<C>,
        point: Ext<C::F, C::EF>,
    ) -> LagrangeSelectors<Ext<C::F, C::EF>> {
        let unshifted_point: Ext<_, _> = self.eval(point * domain.shift.inverse());
        let z_h_expr =
            self.exp_power_of_2_v::<Ext<_, _>>(unshifted_point, domain.log_n) - C::EF::one();
        let z_h: Ext<_, _> = self.eval(z_h_expr);

        LagrangeSelectors {
            is_first_row: self.eval(z_h / (unshifted_point - C::EF::one())),
            is_last_row: self.eval(z_h / (unshifted_point - domain.gen().inverse())),
            is_transition: self.eval(unshifted_point - domain.gen().inverse()),
            inv_zeroifier: self.eval(z_h.inverse()),
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L87
    pub fn zp_at_point(
        &mut self,
        domain: &TwoAdicMultiplicativeCoset<C>,
        point: Ext<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        // Compute (point * domain.shift.inverse()).exp_power_of_2(domain.log_n) - Ext::one()
        let unshifted_power =
            self.exp_power_of_2_v::<Ext<_, _>>(point * domain.shift.inverse(), domain.log_n);
        self.eval(unshifted_power - C::EF::one())
    }

    pub fn split_domains(
        &mut self,
        domain: &TwoAdicMultiplicativeCoset<C>,
        log_num_chunks: usize,
    ) -> Vec<TwoAdicMultiplicativeCoset<C>> {
        let num_chunks = 1 << log_num_chunks;
        let log_n = self.eval(domain.log_n - log_num_chunks);
        let size = self.power_of_two_usize(log_n);

        let g_dom = domain.gen();

        let domain_power = |i| {
            let mut result = SymbolicFelt::from(g_dom);
            for _ in 0..i {
                result *= g_dom;
            }
            result
        };

        // We can compute a generator for the domain by computing g_dom^{log_num_chunks}
        let g = self.exp_power_of_2_v::<Felt<C::F>>(g_dom, log_num_chunks.into());
        (0..num_chunks)
            .map(|i| TwoAdicMultiplicativeCoset {
                log_n,
                size,
                shift: self.eval(domain.shift * domain_power(i)),
                g,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::asm::VmBuilder;
    use crate::prelude::ExtConst;

    use super::*;
    use p3_commit::{Pcs, PolynomialSpace};
    use p3_field::TwoAdicField;
    use rand::{thread_rng, Rng};
    use sp1_core::stark::Dom;
    use sp1_core::{stark::StarkGenericConfig, utils::BabyBearPoseidon2};
    use sp1_recursion_core::runtime::Runtime;

    fn domain_assertions<F: TwoAdicField, C: Config<N = F, F = F>>(
        builder: &mut Builder<C>,
        domain: &TwoAdicMultiplicativeCoset<C>,
        domain_val: &p3_commit::TwoAdicMultiplicativeCoset<F>,
        zeta_val: C::EF,
    ) {
        // Get a random point.
        let zeta: Ext<_, _> = builder.eval(zeta_val.cons());

        // Compare the selector values of the reference and the builder.
        let sels_expected = domain_val.selectors_at_point(zeta_val);
        let sels = builder.selectors_at_point(domain, zeta);
        builder.assert_ext_eq(sels.is_first_row, sels_expected.is_first_row.cons());
        builder.assert_ext_eq(sels.is_last_row, sels_expected.is_last_row.cons());
        builder.assert_ext_eq(sels.is_transition, sels_expected.is_transition.cons());

        let zp_val = domain_val.zp_at_point(zeta_val);
        let zp = builder.zp_at_point(domain, zeta);
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
            let domain = builder.const_domain(&domain_val);
            let zeta_val = rng.gen::<EF>();
            domain_assertions(&mut builder, &domain, &domain_val, zeta_val);

            // Try a shifted domain.
            let disjoint_domain_val =
                domain_val.create_disjoint_domain(1 << (log_d_val + log_quotient_degree));
            let disjoint_domain = builder.const_domain(&disjoint_domain_val);
            domain_assertions(
                &mut builder,
                &disjoint_domain,
                &disjoint_domain_val,
                zeta_val,
            );

            // Now try splited domains
            let qc_domains_val = disjoint_domain_val.split_domains(1 << log_quotient_degree);
            for dom_val in qc_domains_val.iter() {
                let dom = builder.const_domain(dom_val);
                domain_assertions(&mut builder, &dom, dom_val, zeta_val);
            }

            // Test the splitting of domains by the builder.
            let qc_domains = builder.split_domains(&disjoint_domain, log_quotient_degree);
            for (dom, dom_val) in qc_domains.iter().zip(qc_domains_val.iter()) {
                domain_assertions(&mut builder, dom, dom_val, zeta_val);
            }
        }

        let program = builder.compile();

        let mut runtime = Runtime::<F, EF>::new(&program);
        runtime.run();
    }
}
