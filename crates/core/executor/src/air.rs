use std::ops::{Index, IndexMut};

use enum_map::{Enum, EnumMap};
use p3_field::Field;
use serde::{Deserialize, Serialize};

/// Core AIR types.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Enum,
)]
#[repr(u8)]
pub enum CoreAir {
    /// The program chip
    Program = 0,
    /// The byte lookup chip
    Byte = 1,
    /// The cpu chip.
    Cpu = 2,
    /// The add/sub chip.
    AddSub = 3,
    /// The bitwise chip.
    Bitwise = 4,
    /// The mul chip.
    Mul = 5,
    /// The div/rem chip.
    DivRem = 6,
    /// The lt chip.
    Lt = 7,
    /// The shift right chip.
    ShiftRight = 8,
    /// The shift left chip.
    ShiftLeft = 9,
    /// The memory local chip.
    MemoryLocal = 10,
    /// The global chip.
    Global = 11,
    /// The syscall core chip.
    SyscallCore = 12,
    /// The memory instructions chip.
    MemoryInstrs = 13,
    /// The auipc chip.
    Auipc = 14,
    /// The branch chip.
    Branch = 15,
    /// The jump chip.
    Jump = 16,
    /// The syscall instructions chip.
    SyscallInstrs = 17,
}

impl CoreAir {
    /// Create a `CoreAir` from a chip name.
    ///
    /// This function panics if the name is not a valid chip name.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name {
            "Program" => Self::Program,
            "Byte" => Self::Byte,
            "CPU" => Self::Cpu,
            "AddSub" => Self::AddSub,
            "Lt" => Self::Lt,
            "MemoryLocal" => Self::MemoryLocal,
            "DivRem" => Self::DivRem,
            "Bitwise" => Self::Bitwise,
            "Mul" => Self::Mul,
            "ShiftRight" => Self::ShiftRight,
            "ShiftLeft" => Self::ShiftLeft,
            "MemoryInstrs" => Self::MemoryInstrs,
            "Auipc" => Self::Auipc,
            "Branch" => Self::Branch,
            "Jump" => Self::Jump,
            "SyscallInstrs" => Self::SyscallInstrs,
            "Global" => Self::Global,
            "SyscallCore" => Self::SyscallCore,
            _ => unreachable!(),
        }
    }

    /// Get the chip name of the `CoreAir`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Program => "Program",
            Self::Byte => "Byte",
            Self::Cpu => "CPU",
            Self::AddSub => "AddSub",
            Self::Lt => "Lt",
            Self::MemoryLocal => "MemoryLocal",
            Self::DivRem => "DivRem",
            Self::Bitwise => "Bitwise",
            Self::Mul => "Mul",
            Self::ShiftRight => "ShiftRight",
            Self::ShiftLeft => "ShiftLeft",
            Self::MemoryInstrs => "MemoryInstrs",
            Self::Auipc => "Auipc",
            Self::Branch => "Branch",
            Self::Jump => "Jump",
            Self::SyscallInstrs => "SyscallInstrs",
            Self::Global => "Global",
            Self::SyscallCore => "SyscallCore",
        }
    }
}

/// The costs of different air types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct CoreAirCosts<F> {
    costs: EnumMap<CoreAir, usize>,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> CoreAirCosts<F> {
    /// Create a new `CoreAirCosts` instance, with all costs set to 0.
    #[must_use]
    pub fn new() -> Self {
        Self { costs: EnumMap::default(), _marker: std::marker::PhantomData }
    }
}

impl<F> Index<CoreAir> for CoreAirCosts<F> {
    type Output = usize;

    fn index(&self, index: CoreAir) -> &Self::Output {
        &self.costs[index]
    }
}

impl<F> IndexMut<CoreAir> for CoreAirCosts<F> {
    fn index_mut(&mut self, index: CoreAir) -> &mut Self::Output {
        &mut self.costs[index]
    }
}

impl<F: Field> Default for CoreAirCosts<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F> IntoIterator for CoreAirCosts<F> {
    type Item = (CoreAir, usize);
    type IntoIter = <EnumMap<CoreAir, usize> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.costs.into_iter()
    }
}
