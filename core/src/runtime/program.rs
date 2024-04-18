use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::Instruction;

/// A program that can be executed by the VM.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Program {
    /// The instructions of the program.
    pub instructions: Vec<Instruction>,

    /// The start address of the program.
    pub pc_start: u32,

    /// The base address of the program.
    pub pc_base: u32,

    /// The initial memory image, useful for global constants.
    pub memory_image: BTreeMap<u32, u32>,
}
