use p3_commit::{LagrangeSelectors, TwoAdicMultiplicativeCoset};
use p3_field::{AbstractExtensionField, AbstractField, Field, TwoAdicField};
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_program::{commit::PolynomialSpaceVariable, fri::types::FriConfigVariable};

#[derive(Clone, Copy)]
pub struct TwoAdicMultiplicativeCosetVariable<C: Config> {
    pub log_n: usize,
    pub size: usize,
    pub shift: C::F,
    pub g: C::F,
}

impl<C: Config> TwoAdicMultiplicativeCosetVariable<C> {
    pub fn gen(&self, builder: &mut Builder<C>) -> Felt<C::F> {
        builder.eval(self.g)
    }

    pub fn geninv(&self, builder: &mut Builder<C>) -> Felt<C::F> {
        builder.eval(self.g.inverse())
    }

    pub fn first_point(&self, builder: &mut Builder<C>) -> Felt<C::F> {
        builder.eval(self.shift)
    }
    pub fn zp_at_point_f(
        &self,
        builder: &mut Builder<C>,
        point: Felt<<C as Config>::F>,
    ) -> Felt<<C as Config>::F> {
        let unshifted_power = builder
            .exp_power_of_2_v::<Felt<_>>(point * self.shift.inverse(), Usize::Const(self.log_n));
        builder.eval(unshifted_power - C::F::one())
    }
}

impl<C: Config> FromConstant<C> for TwoAdicMultiplicativeCosetVariable<C>
where
    C::F: TwoAdicField,
{
    type Constant = TwoAdicMultiplicativeCoset<C::F>;

    fn constant(value: Self::Constant, _: &mut Builder<C>) -> Self {
        let g_val = C::F::two_adic_generator(value.log_n);
        TwoAdicMultiplicativeCosetVariable::<C> {
            log_n: value.log_n,
            size: 1 << value.log_n,
            shift: value.shift,
            g: g_val,
        }
    }
}

pub fn new_coset<C: Config>(
    _: &mut Builder<C>,
    log_degree: usize,
) -> TwoAdicMultiplicativeCosetVariable<C>
where
    C::F: TwoAdicField,
{
    TwoAdicMultiplicativeCosetVariable::<C> {
        log_n: log_degree,
        size: 1 << log_degree,
        shift: C::F::one(),
        g: C::F::two_adic_generator(log_degree),
    }
}

impl<C: Config> PolynomialSpaceVariable<C> for TwoAdicMultiplicativeCosetVariable<C>
where
    C::F: TwoAdicField,
{
    type Constant = p3_commit::TwoAdicMultiplicativeCoset<C::F>;

    fn next_point(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> Ext<<C as Config>::F, <C as Config>::EF> {
        let g: Felt<_> = builder.eval(self.g);
        builder.eval(point * g)
    }

    fn selectors_at_point(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> LagrangeSelectors<Ext<<C as Config>::F, <C as Config>::EF>> {
        let unshifted_point: Ext<_, _> = builder.eval(point * self.shift.inverse());
        let z_h_expr = builder
            .exp_power_of_2_v::<Ext<_, _>>(unshifted_point, Usize::Const(self.log_n))
            - C::EF::one();
        let z_h: Ext<_, _> = builder.eval(z_h_expr);
        let ginv = self.geninv(builder);
        LagrangeSelectors {
            is_first_row: builder.eval(z_h / (unshifted_point - C::EF::one())),
            is_last_row: builder.eval(z_h / (unshifted_point - ginv)),
            is_transition: builder.eval(unshifted_point - ginv),
            inv_zeroifier: builder.eval(z_h.inverse()),
        }
    }

    fn zp_at_point(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> Ext<<C as Config>::F, <C as Config>::EF> {
        let unshifted_power = builder.exp_power_of_2_v::<Ext<_, _>>(
            point
                * C::EF::from_base_slice(&[self.shift, C::F::zero(), C::F::zero(), C::F::zero()])
                    .inverse()
                    .cons(),
            Usize::Const(self.log_n),
        );
        builder.eval(unshifted_power - C::EF::one())
    }

    fn split_domains(
        &self,
        _builder: &mut Builder<C>,
        _log_num_chunks: impl Into<Usize<<C as Config>::N>>,
        _num_chunks: impl Into<Usize<<C as Config>::N>>,
    ) -> Array<C, Self> {
        unimplemented!("Not implemented for a circuit variable")
    }

    fn split_domains_const(&self, _: &mut Builder<C>, log_num_chunks: usize) -> Vec<Self> {
        let num_chunks = 1 << log_num_chunks;
        let log_n = self.log_n - log_num_chunks;
        let size = 1 << log_n;

        let g = self.g;

        let mut domain_power = C::F::one();
        let mut domains = vec![];

        for _ in 0..num_chunks {
            domains.push(TwoAdicMultiplicativeCosetVariable {
                log_n,
                size,
                shift: self.shift * domain_power,
                g,
            });
            domain_power *= g;
        }
        domains
    }

    fn create_disjoint_domain(
        &self,
        builder: &mut Builder<C>,
        log_degree: Usize<<C as Config>::N>,
        _: Option<FriConfigVariable<C>>,
    ) -> Self {
        let mut domain = match log_degree {
            Usize::Const(log_degree) => new_coset(builder, log_degree),
            _ => unreachable!(),
        };
        domain.shift = self.shift * C::F::generator();
        domain
    }
}
