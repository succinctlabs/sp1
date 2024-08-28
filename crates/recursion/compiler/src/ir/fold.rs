use sp1_recursion_derive::DslVariable;

use super::{Ext, Felt, Var};
use crate::ir::{Array, Builder, Config, MemIndex, MemVariable, Ptr, Variable};

#[derive(DslVariable, Debug, Clone)]
pub struct FriFoldInput<C: Config> {
    pub z: Ext<C::F, C::EF>,
    pub alpha: Ext<C::F, C::EF>,
    pub x: Felt<C::F>,
    pub log_height: Var<C::N>,
    pub mat_opening: Array<C, Ext<C::F, C::EF>>,
    pub ps_at_z: Array<C, Ext<C::F, C::EF>>,
    pub alpha_pow: Array<C, Ext<C::F, C::EF>>,
    pub ro: Array<C, Ext<C::F, C::EF>>,
}

#[derive(Debug, Clone)]
pub struct CircuitV2FriFoldInput<C: Config> {
    pub z: Ext<C::F, C::EF>,
    pub alpha: Ext<C::F, C::EF>,
    pub x: Felt<C::F>,
    pub mat_opening: Vec<Ext<C::F, C::EF>>,
    pub ps_at_z: Vec<Ext<C::F, C::EF>>,
    pub alpha_pow_input: Vec<Ext<C::F, C::EF>>,
    pub ro_input: Vec<Ext<C::F, C::EF>>,
}

#[derive(Debug, Clone)]
pub struct CircuitV2FriFoldOutput<C: Config> {
    pub alpha_pow_output: Vec<Ext<C::F, C::EF>>,
    pub ro_output: Vec<Ext<C::F, C::EF>>,
}
