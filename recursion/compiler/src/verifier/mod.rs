pub mod challenger;
pub mod constraints;
pub mod fri;

pub use constraints::*;

use p3_field::PrimeField;
use sp1_core::stark::StarkGenericConfig;
use std::marker::PhantomData;

use crate::prelude::Config;

#[derive(Clone)]
pub struct StarkGenericBuilderConfig<N, SC> {
    marker: PhantomData<(N, SC)>,
}

impl<N: PrimeField, SC: StarkGenericConfig + Clone> Config for StarkGenericBuilderConfig<N, SC> {
    type N = N;
    type F = SC::Val;
    type EF = SC::Challenge;
}
