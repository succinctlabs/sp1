use std::marker::PhantomData;

use p3_field::{ExtensionField, PrimeField32, TwoAdicField};

use crate::prelude::Config;

/// An assembly code configuration given a field and an extension field.
#[derive(Debug, Clone, Default)]
pub struct AsmConfig<F, EF>(PhantomData<(F, EF)>);

impl<F: PrimeField32 + TwoAdicField, EF: ExtensionField<F> + TwoAdicField> Config
    for AsmConfig<F, EF>
{
    type N = F;
    type F = F;
    type EF = EF;
}
