// use p3_commit::TwoAdicMultiplicativeCoset;
// use p3_field::{AbstractField, TwoAdicField};
// use sp1_recursion_derive::DslVariable;

// use crate::prelude::*;
// use crate::{
//     ir::{Config, Felt, Usize},
//     prelude::{Builder, Var},
// };

// /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L55
// #[derive(DslVariable, Clone, Copy)]
// pub struct TwoAdicMultiplicativeCosetVariable<C: Config> {
//     pub log_n: Var<C::N>,
//     pub size: Var<C::N>,
//     pub shift: Felt<C::F>,
//     pub g: Felt<C::F>,
// }

// impl<C: Config> TwoAdicMultiplicativeCosetVariable<C> {
//     /// Reference: https://github.com/Plonky3/Plonky3/blob/main/commit/src/domain.rs#L74
//     pub fn first_point(&self) -> Felt<C::F> {
//         self.shift
//     }

//     pub fn size(&self) -> Var<C::N> {
//         self.size
//     }

//     pub fn gen(&self) -> Felt<C::F> {
//         self.g
//     }
// }

// impl<C: Config> Builder<C> {
//     pub fn const_domain(
//         &mut self,
//         domain: &p3_commit::TwoAdicMultiplicativeCoset<C::F>,
//     ) -> TwoAdicMultiplicativeCosetVariable<C>
//     where
//         C::F: TwoAdicField,
//     {
//         let log_d_val = domain.log_n as u32;
//         let g_val = C::F::two_adic_generator(domain.log_n);
//         // Initialize a domain.
//         TwoAdicMultiplicativeCosetVariable::<C> {
//             log_n: self.eval::<Var<_>, _>(C::N::from_canonical_u32(log_d_val)),
//             size: self.eval::<Var<_>, _>(C::N::from_canonical_u32(1 << (log_d_val))),
//             shift: self.eval(domain.shift),
//             g: self.eval(g_val),
//         }
//     }
// }

// impl<C: Config> FromConstant<C> for TwoAdicMultiplicativeCosetVariable<C>
// where
//     C::F: TwoAdicField,
// {
//     type Constant = TwoAdicMultiplicativeCoset<C::F>;

//     fn eval_const(value: Self::Constant, builder: &mut Builder<C>) -> Self {
//         let log_d_val = value.log_n as u32;
//         let g_val = C::F::two_adic_generator(value.log_n);
//         // Initialize a domain.
//         TwoAdicMultiplicativeCosetVariable::<C> {
//             log_n: builder.eval::<Var<_>, _>(C::N::from_canonical_u32(log_d_val)),
//             size: builder.eval::<Var<_>, _>(C::N::from_canonical_u32(1 << (log_d_val))),
//             shift: builder.eval(value.shift),
//             g: builder.eval(g_val),
//         }
//     }
// }
