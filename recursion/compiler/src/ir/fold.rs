use crate::ir::{Array, Config};
use crate::prelude::*;

#[derive(DslVariable, Debug, Clone)]
pub struct FriFoldInput<C: Config> {
    m: Var<C::N>,
    z: Var<C::N>,
    x: Felt<C::F>,
    mat_opening: Array<C, Ext<C::F, C::EF>>,
    ps_at_z: Array<C, Ext<C::F, C::EF>>,
    alpha_pow: Array<C, Ext<C::F, C::EF>>,
    ro: Array<C, Ext<C::F, C::EF>>,
}
