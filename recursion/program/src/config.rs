// use p3_field::{ExtensionField, Field};
// use sp1_recursion_compiler::ir::Config;

// use crate::commit::PolynomialDomainVariable;

// pub trait StarkConfigVariable {
//     type C: Config;

//     type Domain: PolynomialDomainVariable;

//     /// The challenger (Fiat-Shamir) implementation used.
//     type Challenger: FieldChallenger<Val<Self>>
//         + CanObserve<<Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment>
//         + CanSample<Self::Challenge>;

//     type Pcs;

//     /// Get the PCS used by this configuration.
//     fn pcs(&self) -> &Self::Pcs;
// }
