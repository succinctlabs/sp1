use std::marker::PhantomData;

use p3_field::{ExtensionField, PrimeField32, TwoAdicField};

use crate::{ir::Builder, prelude::Config};

/// An assembly code configuration given a field and an extension field.
#[derive(Debug, Clone, Default)]
pub struct AsmConfig<F, EF>(PhantomData<(F, EF)>);

pub type AsmBuilder<F, EF> = Builder<AsmConfig<F, EF>>;

impl<F: PrimeField32 + TwoAdicField, EF: ExtensionField<F> + TwoAdicField> Config
    for AsmConfig<F, EF>
{
    type N = F;
    type F = F;
    type EF = EF;
}
