use crate::*;
use p3_field::Field;
use serde::{Deserialize, Serialize};
use shape::RecursionShape;
use sp1_stark::{
    air::{MachineAir, MachineProgram},
    septic_digest::SepticDigest,
};
use std::ops::Deref;

pub use basic_block::BasicBlock;
pub use raw::RawProgram;
pub use seq_block::SeqBlock;

/// A well-formed recursion program. See [`Self::new_unchecked`] for guaranteed (safety) invariants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(transparent)]
pub struct RecursionProgram<F>(RootProgram<F>);

impl<F> RecursionProgram<F> {
    /// # Safety
    /// The given program must be well formed. This is defined as the following:
    /// - reads are performed after writes, according to a "happens-before" relation; and
    /// - an address is written to at most once.
    ///
    /// The "happens-before" relation is defined as follows:
    /// - It is a strict partial order, meaning it is transitive, irreflexive, and asymmetric.
    /// - Instructions in a `BasicBlock` are linearly ordered.
    /// - `SeqBlock`s in a `RawProgram` are linearly ordered, meaning:
    ///     - Each `SeqBlock` has a set of initial instructions `I` and final instructions `O`.
    ///     - For `SeqBlock::Basic`:
    ///         - `I` is the singleton consisting of the first instruction in the enclosed
    ///           `BasicBlock`.
    ///         - `O` is the singleton consisting of the last instruction in the enclosed
    ///           `BasicBlock`.
    ///     - For `SeqBlock::Parallel`:
    ///         - `I` is the set of initial instructions `I` in the first `SeqBlock` of the enclosed
    ///           `RawProgram`.
    ///         - `O` is the set of final instructions in the last `SeqBlock` of the enclosed
    ///           `RawProgram`.
    ///     - For consecutive `SeqBlock`s, each element of the first one's `O` happens before the
    ///       second one's `I`.
    pub unsafe fn new_unchecked(program: RootProgram<F>) -> Self {
        Self(program)
    }

    pub fn into_inner(self) -> RootProgram<F> {
        self.0
    }

    pub fn shape_mut(&mut self) -> &mut Option<RecursionShape> {
        &mut self.0.shape
    }
}

impl<F> Default for RecursionProgram<F> {
    fn default() -> Self {
        // SAFETY: An empty program is always well formed.
        unsafe { Self::new_unchecked(RootProgram::default()) }
    }
}

impl<F> Deref for RecursionProgram<F> {
    type Target = RootProgram<F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: Field> MachineProgram<F> for RecursionProgram<F> {
    fn pc_start(&self) -> F {
        F::zero()
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        SepticDigest::<F>::zero()
    }
}

impl<F: Field> RecursionProgram<F> {
    #[inline]
    pub fn fixed_log2_rows<A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.0
            .shape
            .as_ref()
            .map(|shape| {
                shape
                    .inner
                    .get(&air.name())
                    .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
            })
            .copied()
    }
}

#[cfg(any(test, feature = "program_validation"))]
pub use validation::*;

#[cfg(any(test, feature = "program_validation"))]
mod validation {
    use super::*;

    use std::{fmt::Debug, iter, mem};

    use p3_field::PrimeField32;
    use range_set_blaze::{MultiwayRangeSetBlazeRef, RangeSetBlaze};
    use smallvec::{smallvec, SmallVec};
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum StructureError<F: Debug> {
        #[error("tried to read from uninitialized address {addr:?}. instruction: {instr:?}")]
        ReadFromUninit { addr: Address<F>, instr: Instruction<F> },
    }

    #[derive(Error, Debug)]
    pub enum SummaryError {
        #[error("`total_memory` is insufficient. configured: {configured}. required: {required}")]
        OutOfMemory { configured: usize, required: usize },
    }

    #[derive(Error, Debug)]
    pub enum ValidationError<F: Debug> {
        Structure(#[from] StructureError<F>),
        Summary(#[from] SummaryError),
    }

    impl<F: PrimeField32> RecursionProgram<F> {
        /// Validate the program without modifying its summary metadata.
        pub fn try_new_unmodified(
            program: RootProgram<F>,
        ) -> Result<Self, Box<ValidationError<F>>> {
            let written_addrs = try_written_addrs(smallvec![], &program.inner)
                .map_err(|e| ValidationError::from(*e))?;
            if let Some(required) = written_addrs.last().map(|x| x as usize + 1) {
                let configured = program.total_memory;
                if required > configured {
                    Err(Box::new(SummaryError::OutOfMemory { configured, required }.into()))?
                }
            }
            // SAFETY: We just checked all the invariants.
            Ok(unsafe { Self::new_unchecked(program) })
        }

        /// Validate the program, modifying summary metadata if necessary.
        pub fn try_new(mut program: RootProgram<F>) -> Result<Self, Box<StructureError<F>>> {
            let written_addrs = try_written_addrs(smallvec![], &program.inner)?;
            program.total_memory = written_addrs.last().map(|x| x as usize + 1).unwrap_or_default();
            // SAFETY: We just checked/enforced all the invariants.
            Ok(unsafe { Self::new_unchecked(program) })
        }
    }

    fn try_written_addrs<F: PrimeField32>(
        readable_addrs: SmallVec<[&RangeSetBlaze<u32>; 3]>,
        program: &RawProgram<Instruction<F>>,
    ) -> Result<RangeSetBlaze<u32>, Box<StructureError<F>>> {
        let mut written_addrs = RangeSetBlaze::<u32>::new();
        for block in &program.seq_blocks {
            match block {
                SeqBlock::Basic(basic_block) => {
                    for instr in &basic_block.instrs {
                        let (inputs, outputs) = instr.io_addrs();
                        inputs.into_iter().try_for_each(|i| {
                            let i_u32 = i.0.as_canonical_u32();
                            iter::once(&written_addrs)
                                .chain(readable_addrs.iter().copied())
                                .any(|s| s.contains(i_u32))
                                .then_some(())
                                .ok_or_else(|| {
                                    Box::new(StructureError::ReadFromUninit {
                                        addr: i,
                                        instr: instr.clone(),
                                    })
                                })
                        })?;
                        written_addrs.extend(outputs.iter().map(|o| o.0.as_canonical_u32()));
                    }
                }
                SeqBlock::Parallel(programs) => {
                    let par_written_addrs = programs
                        .iter()
                        .map(|subprogram| {
                            let sub_readable_addrs = iter::once(&written_addrs)
                                .chain(readable_addrs.iter().copied())
                                .collect();

                            try_written_addrs(sub_readable_addrs, subprogram)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    written_addrs =
                        iter::once(mem::take(&mut written_addrs)).chain(par_written_addrs).union();
                }
            }
        }
        Ok(written_addrs)
    }

    impl<F: PrimeField32> RootProgram<F> {
        pub fn validate(self) -> Result<RecursionProgram<F>, Box<StructureError<F>>> {
            RecursionProgram::try_new(self)
        }
    }

    #[cfg(test)]
    pub fn linear_program<F: PrimeField32>(
        instrs: Vec<Instruction<F>>,
    ) -> Result<RecursionProgram<F>, Box<StructureError<F>>> {
        RootProgram {
            inner: RawProgram { seq_blocks: vec![SeqBlock::Basic(BasicBlock { instrs })] },
            total_memory: 0, // Will be filled in.
            shape: None,
        }
        .validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootProgram<F> {
    pub inner: raw::RawProgram<Instruction<F>>,
    pub total_memory: usize,
    pub shape: Option<RecursionShape>,
}

// `Default` without bounds on the type parameter.
impl<F> Default for RootProgram<F> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            total_memory: Default::default(),
            shape: Default::default(),
        }
    }
}

pub mod raw {
    use std::iter::Flatten;

    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RawProgram<T> {
        pub seq_blocks: Vec<SeqBlock<T>>,
    }

    // `Default` without bounds on the type parameter.
    impl<T> Default for RawProgram<T> {
        fn default() -> Self {
            Self { seq_blocks: Default::default() }
        }
    }

    impl<T> RawProgram<T> {
        pub fn iter(&self) -> impl Iterator<Item = &'_ T> {
            self.seq_blocks.iter().flatten()
        }
        pub fn iter_mut(&mut self) -> impl Iterator<Item = &'_ mut T> {
            self.seq_blocks.iter_mut().flatten()
        }
    }

    impl<T> IntoIterator for RawProgram<T> {
        type Item = T;

        type IntoIter = Flatten<<Vec<SeqBlock<T>> as IntoIterator>::IntoIter>;

        fn into_iter(self) -> Self::IntoIter {
            self.seq_blocks.into_iter().flatten()
        }
    }

    impl<'a, T> IntoIterator for &'a RawProgram<T> {
        type Item = &'a T;

        type IntoIter = Flatten<<&'a Vec<SeqBlock<T>> as IntoIterator>::IntoIter>;

        fn into_iter(self) -> Self::IntoIter {
            self.seq_blocks.iter().flatten()
        }
    }

    impl<'a, T> IntoIterator for &'a mut RawProgram<T> {
        type Item = &'a mut T;

        type IntoIter = Flatten<<&'a mut Vec<SeqBlock<T>> as IntoIterator>::IntoIter>;

        fn into_iter(self) -> Self::IntoIter {
            self.seq_blocks.iter_mut().flatten()
        }
    }
}

pub mod seq_block {
    use std::iter::Flatten;

    use super::*;

    /// Segments that may be sequentially composed.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum SeqBlock<T> {
        /// One basic block.
        Basic(BasicBlock<T>),
        /// Many blocks to be run in parallel.
        Parallel(Vec<RawProgram<T>>),
    }

    impl<T> SeqBlock<T> {
        pub fn iter(&self) -> Iter<'_, T> {
            self.into_iter()
        }

        pub fn iter_mut(&mut self) -> IterMut<'_, T> {
            self.into_iter()
        }
    }

    // Bunch of iterator boilerplate.
    #[derive(Debug)]
    pub enum Iter<'a, T> {
        Basic(<&'a Vec<T> as IntoIterator>::IntoIter),
        Parallel(Box<Flatten<<&'a Vec<RawProgram<T>> as IntoIterator>::IntoIter>>),
    }

    impl<'a, T> Iterator for Iter<'a, T> {
        type Item = &'a T;

        fn next(&mut self) -> Option<Self::Item> {
            match self {
                Iter::Basic(it) => it.next(),
                Iter::Parallel(it) => it.next(),
            }
        }
    }

    impl<'a, T> IntoIterator for &'a SeqBlock<T> {
        type Item = &'a T;

        type IntoIter = Iter<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            match self {
                SeqBlock::Basic(basic_block) => Iter::Basic(basic_block.instrs.iter()),
                SeqBlock::Parallel(vec) => Iter::Parallel(Box::new(vec.iter().flatten())),
            }
        }
    }

    #[derive(Debug)]
    pub enum IterMut<'a, T> {
        Basic(<&'a mut Vec<T> as IntoIterator>::IntoIter),
        Parallel(Box<Flatten<<&'a mut Vec<RawProgram<T>> as IntoIterator>::IntoIter>>),
    }

    impl<'a, T> Iterator for IterMut<'a, T> {
        type Item = &'a mut T;

        fn next(&mut self) -> Option<Self::Item> {
            match self {
                IterMut::Basic(it) => it.next(),
                IterMut::Parallel(it) => it.next(),
            }
        }
    }

    impl<'a, T> IntoIterator for &'a mut SeqBlock<T> {
        type Item = &'a mut T;

        type IntoIter = IterMut<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            match self {
                SeqBlock::Basic(basic_block) => IterMut::Basic(basic_block.instrs.iter_mut()),
                SeqBlock::Parallel(vec) => IterMut::Parallel(Box::new(vec.iter_mut().flatten())),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum IntoIter<T> {
        Basic(<Vec<T> as IntoIterator>::IntoIter),
        Parallel(Box<Flatten<<Vec<RawProgram<T>> as IntoIterator>::IntoIter>>),
    }

    impl<T> Iterator for IntoIter<T> {
        type Item = T;

        fn next(&mut self) -> Option<Self::Item> {
            match self {
                IntoIter::Basic(it) => it.next(),
                IntoIter::Parallel(it) => it.next(),
            }
        }
    }

    impl<T> IntoIterator for SeqBlock<T> {
        type Item = T;

        type IntoIter = IntoIter<T>;

        fn into_iter(self) -> Self::IntoIter {
            match self {
                SeqBlock::Basic(basic_block) => IntoIter::Basic(basic_block.instrs.into_iter()),
                SeqBlock::Parallel(vec) => IntoIter::Parallel(Box::new(vec.into_iter().flatten())),
            }
        }
    }
}

pub mod basic_block {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BasicBlock<T> {
        pub instrs: Vec<T>,
    }

    // Less restrictive trait bounds.
    impl<T> Default for BasicBlock<T> {
        fn default() -> Self {
            Self { instrs: Default::default() }
        }
    }
}
