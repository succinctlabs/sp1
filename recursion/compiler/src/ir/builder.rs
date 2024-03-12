use super::{Config, DslIR};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Builder<C: Config> {
    pub(crate) felt_count: u32,
    pub(crate) ext_count: u32,
    pub(crate) var_count: u32,
    pub(crate) operations: Vec<DslIR<C>>,
}
