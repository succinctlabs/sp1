use std::mem::{size_of, transmute};

use memory::MemoryPreprocessed;
use permutation::{Permutation, PermutationNoSbox, PermutationSBox};
use sp1_core::utils::indices_arr;
use sp1_derive::AlignedBorrow;

use self::memory::Memory;

pub mod memory;
pub mod permutation;

/// Trait for getter methods for Poseidon2 columns.
pub trait Poseidon2<'a, T: Copy + 'a> {
    fn memory(&self) -> &Memory<T>;

    fn permutation(&self) -> Box<dyn Permutation<T> + 'a>;

    // fn memory_prepr(&self) -> &MemoryPreprocessed<T>;
}

/// Trait for setter methods for Poseidon2 columns. Only need the memory columns are populated mutably.
pub trait Poseidon2Mut<'a, T: Copy + 'a> {
    fn memory_mut(&mut self) -> &mut Memory<T>;
}

/// Enum to enable dynamic dispatch for the Poseidon2 columns.
#[allow(dead_code)]
enum Poseidon2Enum<T: Copy> {
    P2Degree3(Poseidon2Degree3<T>),
    P2Degree9(Poseidon2Degree9<T>),
}

impl<'a, T: Copy + 'a> Poseidon2<'a, T> for Poseidon2Enum<T> {
    fn memory(&self) -> &Memory<T> {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.memory(),
            Poseidon2Enum::P2Degree9(p) => p.memory(),
        }
    }
    fn permutation(&self) -> Box<dyn Permutation<T> + 'a> {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.permutation(),
            Poseidon2Enum::P2Degree9(p) => p.permutation(),
        }
    }

    // fn memory_prepr(&self) -> &MemoryPreprocessed<T> {
    //     match self {
    //         Poseidon2Enum::P2Degree3(p) => p.memory_prepr(),
    //         Poseidon2Enum::P2Degree9(p) => p.memory_prepr(),
    //     }
    // }
}

/// Enum to enable dynamic dispatch for the Poseidon2 columns.
#[allow(dead_code)]
enum Poseidon2MutEnum<'a, T: Copy> {
    P2Degree3(&'a mut Poseidon2Degree3<T>),
    P2Degree9(&'a mut Poseidon2Degree9<T>),
}

impl<'a, T: Copy + 'a> Poseidon2Mut<'a, T> for Poseidon2MutEnum<'a, T> {
    fn memory_mut(&mut self) -> &mut Memory<T> {
        match self {
            Poseidon2MutEnum::P2Degree3(p) => p.memory_mut(),
            Poseidon2MutEnum::P2Degree9(p) => p.memory_mut(),
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
    pub memory: Memory<T>,
    // pub memory_prepr: MemoryPreprocessed<T>,
    pub permutation_cols: PermutationSBox<T>,
}
impl<'a, T: Copy + 'a> Poseidon2<'a, T> for Poseidon2Degree3<T> {
    fn memory(&self) -> &Memory<T> {
        &self.memory
    }

    fn permutation(&self) -> Box<dyn Permutation<T> + 'a> {
        Box::new(self.permutation_cols)
    }

    // fn memory_prepr(&self) -> &MemoryPreprocessed<T> {
    //     &self.memory_prepr
    // }
}

impl<'a, T: Copy + 'a> Poseidon2Mut<'a, T> for &'a mut Poseidon2Degree3<T> {
    fn memory_mut(&mut self) -> &mut Memory<T> {
        &mut self.memory
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
    pub memory: Memory<T>,
    // pub memory_prepr: MemoryPreprocessed<T>,
    pub permutation_cols: PermutationNoSbox<T>,
}

impl<'a, T: Copy + 'a> Poseidon2<'a, T> for Poseidon2Degree9<T> {
    fn memory(&self) -> &Memory<T> {
        &self.memory
    }

    fn permutation(&self) -> Box<dyn Permutation<T> + 'a> {
        Box::new(self.permutation_cols)
    }

    // fn memory_prepr(&self) -> &MemoryPreprocessed<T> {
    //     &self.memory_prepr
    // }
}

impl<'a, T: Copy + 'a> Poseidon2Mut<'a, T> for &'a mut Poseidon2Degree9<T> {
    fn memory_mut(&mut self) -> &mut Memory<T> {
        &mut self.memory
    }
}
