use std::mem::{size_of, transmute};

use sp1_core_machine::utils::indices_arr;
use sp1_derive::AlignedBorrow;

use self::{
    control_flow::ControlFlow,
    memory::Memory,
    opcode_workspace::OpcodeWorkspace,
    permutation::{Permutation, PermutationNoSbox, PermutationSBox},
    syscall_params::SyscallParams,
};

use super::WIDTH;

pub mod control_flow;
pub mod memory;
pub mod opcode_workspace;
pub mod permutation;
pub mod syscall_params;

/// Trait for getter methods for Poseidon2 columns.
pub trait Poseidon2<'a, T: Copy + 'a> {
    fn control_flow(&self) -> &ControlFlow<T>;

    fn syscall_params(&self) -> &SyscallParams<T>;

    fn memory(&self) -> &Memory<T>;

    fn opcode_workspace(&self) -> &OpcodeWorkspace<T>;

    fn permutation(&self) -> Box<dyn Permutation<T> + 'a>;
}

/// Trait for setter methods for Poseidon2 columns.
pub trait Poseidon2Mut<'a, T: Copy + 'a> {
    fn control_flow_mut(&mut self) -> &mut ControlFlow<T>;

    fn syscall_params_mut(&mut self) -> &mut SyscallParams<T>;

    fn memory_mut(&mut self) -> &mut Memory<T>;

    fn opcode_workspace_mut(&mut self) -> &mut OpcodeWorkspace<T>;
}

/// Enum to enable dynamic dispatch for the Poseidon2 columns.
#[allow(dead_code)]
enum Poseidon2Enum<T: Copy> {
    P2Degree3(Poseidon2Degree3<T>),
    P2Degree9(Poseidon2Degree9<T>),
}

impl<'a, T: Copy + 'a> Poseidon2<'a, T> for Poseidon2Enum<T> {
    // type Perm = PermutationSBox<T>;

    fn control_flow(&self) -> &ControlFlow<T> {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.control_flow(),
            Poseidon2Enum::P2Degree9(p) => p.control_flow(),
        }
    }

    fn syscall_params(&self) -> &SyscallParams<T> {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.syscall_params(),
            Poseidon2Enum::P2Degree9(p) => p.syscall_params(),
        }
    }

    fn memory(&self) -> &Memory<T> {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.memory(),
            Poseidon2Enum::P2Degree9(p) => p.memory(),
        }
    }

    fn opcode_workspace(&self) -> &OpcodeWorkspace<T> {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.opcode_workspace(),
            Poseidon2Enum::P2Degree9(p) => p.opcode_workspace(),
        }
    }

    fn permutation(&self) -> Box<dyn Permutation<T> + 'a> {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.permutation(),
            Poseidon2Enum::P2Degree9(p) => p.permutation(),
        }
    }
}

/// Enum to enable dynamic dispatch for the Poseidon2 columns.
#[allow(dead_code)]
enum Poseidon2MutEnum<'a, T: Copy> {
    P2Degree3(&'a mut Poseidon2Degree3<T>),
    P2Degree9(&'a mut Poseidon2Degree9<T>),
}

impl<'a, T: Copy + 'a> Poseidon2Mut<'a, T> for Poseidon2MutEnum<'a, T> {
    fn control_flow_mut(&mut self) -> &mut ControlFlow<T> {
        match self {
            Poseidon2MutEnum::P2Degree3(p) => p.control_flow_mut(),
            Poseidon2MutEnum::P2Degree9(p) => p.control_flow_mut(),
        }
    }

    fn syscall_params_mut(&mut self) -> &mut SyscallParams<T> {
        match self {
            Poseidon2MutEnum::P2Degree3(p) => p.syscall_params_mut(),
            Poseidon2MutEnum::P2Degree9(p) => p.syscall_params_mut(),
        }
    }

    fn memory_mut(&mut self) -> &mut Memory<T> {
        match self {
            Poseidon2MutEnum::P2Degree3(p) => p.memory_mut(),
            Poseidon2MutEnum::P2Degree9(p) => p.memory_mut(),
        }
    }

    fn opcode_workspace_mut(&mut self) -> &mut OpcodeWorkspace<T> {
        match self {
            Poseidon2MutEnum::P2Degree3(p) => p.opcode_workspace_mut(),
            Poseidon2MutEnum::P2Degree9(p) => p.opcode_workspace_mut(),
        }
    }
}

pub const NUM_POSEIDON2_DEGREE3_COLS: usize = size_of::<Poseidon2Degree3<u8>>();

const fn make_col_map_degree3() -> Poseidon2Degree3<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE3_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE3_COLS], Poseidon2Degree3<usize>>(indices_arr)
    }
}
pub const POSEIDON2_DEGREE3_COL_MAP: Poseidon2Degree3<usize> = make_col_map_degree3();

/// Struct for the poseidon2 chip that contains sbox columns.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Degree3<T: Copy> {
    pub control_flow: ControlFlow<T>,
    pub syscall_input: SyscallParams<T>,
    pub memory: Memory<T>,
    pub opcode_specific_cols: OpcodeWorkspace<T>,
    pub permutation_cols: PermutationSBox<T>,
    pub state_cursor: [T; WIDTH / 2], // Only used for absorb
}

impl<'a, T: Copy + 'a> Poseidon2<'a, T> for Poseidon2Degree3<T> {
    fn control_flow(&self) -> &ControlFlow<T> {
        &self.control_flow
    }

    fn syscall_params(&self) -> &SyscallParams<T> {
        &self.syscall_input
    }

    fn memory(&self) -> &Memory<T> {
        &self.memory
    }

    fn opcode_workspace(&self) -> &OpcodeWorkspace<T> {
        &self.opcode_specific_cols
    }

    fn permutation(&self) -> Box<dyn Permutation<T> + 'a> {
        Box::new(self.permutation_cols)
    }
}

impl<'a, T: Copy + 'a> Poseidon2Mut<'a, T> for &'a mut Poseidon2Degree3<T> {
    fn control_flow_mut(&mut self) -> &mut ControlFlow<T> {
        &mut self.control_flow
    }

    fn syscall_params_mut(&mut self) -> &mut SyscallParams<T> {
        &mut self.syscall_input
    }

    fn memory_mut(&mut self) -> &mut Memory<T> {
        &mut self.memory
    }

    fn opcode_workspace_mut(&mut self) -> &mut OpcodeWorkspace<T> {
        &mut self.opcode_specific_cols
    }
}

pub const NUM_POSEIDON2_DEGREE9_COLS: usize = size_of::<Poseidon2Degree9<u8>>();
const fn make_col_map_degree9() -> Poseidon2Degree9<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE9_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE9_COLS], Poseidon2Degree9<usize>>(indices_arr)
    }
}
pub const POSEIDON2_DEGREE9_COL_MAP: Poseidon2Degree9<usize> = make_col_map_degree9();

/// Struct for the poseidon2 chip that doesn't contain sbox columns.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Degree9<T: Copy> {
    pub control_flow: ControlFlow<T>,
    pub syscall_input: SyscallParams<T>,
    pub memory: Memory<T>,
    pub opcode_specific_cols: OpcodeWorkspace<T>,
    pub permutation_cols: PermutationNoSbox<T>,
}

impl<'a, T: Copy + 'a> Poseidon2<'a, T> for Poseidon2Degree9<T> {
    fn control_flow(&self) -> &ControlFlow<T> {
        &self.control_flow
    }

    fn syscall_params(&self) -> &SyscallParams<T> {
        &self.syscall_input
    }

    fn memory(&self) -> &Memory<T> {
        &self.memory
    }

    fn opcode_workspace(&self) -> &OpcodeWorkspace<T> {
        &self.opcode_specific_cols
    }

    fn permutation(&self) -> Box<dyn Permutation<T> + 'a> {
        Box::new(self.permutation_cols)
    }
}

impl<'a, T: Copy + 'a> Poseidon2Mut<'a, T> for &'a mut Poseidon2Degree9<T> {
    fn control_flow_mut(&mut self) -> &mut ControlFlow<T> {
        &mut self.control_flow
    }

    fn syscall_params_mut(&mut self) -> &mut SyscallParams<T> {
        &mut self.syscall_input
    }

    fn memory_mut(&mut self) -> &mut Memory<T> {
        &mut self.memory
    }

    fn opcode_workspace_mut(&mut self) -> &mut OpcodeWorkspace<T> {
        &mut self.opcode_specific_cols
    }
}
