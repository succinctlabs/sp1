use std::{
    array,
    cell::UnsafeCell,
    mem::MaybeUninit,
    ops::{Add, AddAssign},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_hypercube::{air::SP1AirBuilder, InteractionKind, MachineRecord, PROOF_MAX_NUM_PVS};

use crate::{
    instruction::{HintBitsInstr, HintExt2FeltsInstr, HintInstr},
    public_values::RecursionPublicValues,
    ExtFeltEvent, Instruction, Poseidon2LinearLayerEvent, Poseidon2SBoxEvent, PrefixSumChecksEvent,
};

use super::{
    BaseAluEvent, CommitPublicValuesEvent, ExtAluEvent, MemEvent, Poseidon2Event, RecursionProgram,
    SelectEvent,
};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ExecutionRecord<F> {
    pub program: Arc<RecursionProgram<F>>,
    /// The index of the shard.
    pub index: u32,

    pub base_alu_events: Vec<BaseAluEvent<F>>,
    pub ext_alu_events: Vec<ExtAluEvent<F>>,
    pub mem_const_count: usize,
    pub mem_var_events: Vec<MemEvent<F>>,
    /// The public values.
    pub public_values: RecursionPublicValues<F>,

    pub ext_felt_conversion_events: Vec<ExtFeltEvent<F>>,
    pub poseidon2_events: Vec<Poseidon2Event<F>>,
    pub poseidon2_linear_layer_events: Vec<Poseidon2LinearLayerEvent<F>>,
    pub poseidon2_sbox_events: Vec<Poseidon2SBoxEvent<F>>,
    pub select_events: Vec<SelectEvent<F>>,
    pub prefix_sum_checks_events: Vec<PrefixSumChecksEvent<F>>,
    pub commit_pv_hash_events: Vec<CommitPublicValuesEvent<F>>,
}

#[derive(Debug)]
pub struct UnsafeRecord<F> {
    pub base_alu_events: Vec<MaybeUninit<UnsafeCell<BaseAluEvent<F>>>>,
    pub ext_alu_events: Vec<MaybeUninit<UnsafeCell<ExtAluEvent<F>>>>,
    // Can be computed by the analysis step.
    pub mem_const_count: usize,
    pub mem_var_events: Vec<MaybeUninit<UnsafeCell<MemEvent<F>>>>,
    /// The public values.
    pub public_values: MaybeUninit<UnsafeCell<RecursionPublicValues<F>>>,

    pub ext_felt_conversion_events: Vec<MaybeUninit<UnsafeCell<ExtFeltEvent<F>>>>,
    pub poseidon2_events: Vec<MaybeUninit<UnsafeCell<Poseidon2Event<F>>>>,
    pub poseidon2_linear_layer_events: Vec<MaybeUninit<UnsafeCell<Poseidon2LinearLayerEvent<F>>>>,
    pub poseidon2_sbox_events: Vec<MaybeUninit<UnsafeCell<Poseidon2SBoxEvent<F>>>>,
    pub select_events: Vec<MaybeUninit<UnsafeCell<SelectEvent<F>>>>,
    pub prefix_sum_checks_events: Vec<MaybeUninit<UnsafeCell<PrefixSumChecksEvent<F>>>>,
    pub commit_pv_hash_events: Vec<MaybeUninit<UnsafeCell<CommitPublicValuesEvent<F>>>>,
}

impl<F> UnsafeRecord<F> {
    /// # Safety
    ///
    /// The caller must ensure that the `UnsafeRecord` is fully initialized, this is
    /// done by the executor.
    pub unsafe fn into_record(
        self,
        program: Arc<RecursionProgram<F>>,
        index: u32,
    ) -> ExecutionRecord<F> {
        // SAFETY: `T` and `MaybeUninit<UnsafeCell<T>>` have the same memory layout.
        #[allow(clippy::missing_transmute_annotations)]
        ExecutionRecord {
            program,
            index,
            base_alu_events: std::mem::transmute(self.base_alu_events),
            ext_alu_events: std::mem::transmute(self.ext_alu_events),
            mem_const_count: self.mem_const_count,
            mem_var_events: std::mem::transmute(self.mem_var_events),
            public_values: self.public_values.assume_init().into_inner(),
            ext_felt_conversion_events: std::mem::transmute(self.ext_felt_conversion_events),
            poseidon2_events: std::mem::transmute(self.poseidon2_events),
            poseidon2_linear_layer_events: std::mem::transmute(self.poseidon2_linear_layer_events),
            poseidon2_sbox_events: std::mem::transmute(self.poseidon2_sbox_events),
            select_events: std::mem::transmute(self.select_events),
            prefix_sum_checks_events: std::mem::transmute(self.prefix_sum_checks_events),
            commit_pv_hash_events: std::mem::transmute(self.commit_pv_hash_events),
        }
    }

    pub fn new(event_counts: RecursionAirEventCount) -> Self
    where
        F: Field,
    {
        #[inline]
        fn create_uninit_vec<T>(len: usize) -> Vec<MaybeUninit<T>> {
            let mut vec = Vec::with_capacity(len);
            // SAFETY: The vector has enough capacity to hold the elements as we just allocated it,
            // and the type `T` is `MaybeUninit` which implies that an "uninitialized" value is OK.
            unsafe { vec.set_len(len) };
            vec
        }

        Self {
            base_alu_events: create_uninit_vec(event_counts.base_alu_events),
            ext_alu_events: create_uninit_vec(event_counts.ext_alu_events),
            mem_const_count: event_counts.mem_const_events,
            mem_var_events: create_uninit_vec(event_counts.mem_var_events),
            public_values: MaybeUninit::uninit(),
            ext_felt_conversion_events: create_uninit_vec(event_counts.ext_felt_conversion_events),
            poseidon2_events: create_uninit_vec(event_counts.poseidon2_wide_events),
            poseidon2_linear_layer_events: create_uninit_vec(
                event_counts.poseidon2_linear_layer_events,
            ),
            poseidon2_sbox_events: create_uninit_vec(event_counts.poseidon2_sbox_events),
            select_events: create_uninit_vec(event_counts.select_events),
            prefix_sum_checks_events: create_uninit_vec(event_counts.prefix_sum_checks_events),
            commit_pv_hash_events: create_uninit_vec(event_counts.commit_pv_hash_events),
        }
    }
}

unsafe impl<F> Sync for UnsafeRecord<F> {}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    fn stats(&self) -> hashbrown::HashMap<String, usize> {
        [
            ("base_alu_events", self.base_alu_events.len()),
            ("ext_alu_events", self.ext_alu_events.len()),
            ("mem_const_count", self.mem_const_count),
            ("mem_var_events", self.mem_var_events.len()),
            ("ext_felt_conversion_events", self.ext_felt_conversion_events.len()),
            ("poseidon2_events", self.poseidon2_events.len()),
            ("poseidon2_linear_layer_events", self.poseidon2_linear_layer_events.len()),
            ("poseidon2_sbox_events", self.poseidon2_sbox_events.len()),
            ("select_events", self.select_events.len()),
            ("prefix_sum_checks_events", self.prefix_sum_checks_events.len()),
            ("commit_pv_hash_events", self.commit_pv_hash_events.len()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }

    fn append(&mut self, other: &mut Self) {
        // Exhaustive destructuring for refactoring purposes.
        let Self {
            program: _,
            index: _,
            base_alu_events,
            ext_alu_events,
            mem_const_count,
            mem_var_events,
            public_values: _,
            ext_felt_conversion_events,
            poseidon2_events,
            poseidon2_linear_layer_events,
            poseidon2_sbox_events,
            select_events,
            prefix_sum_checks_events,
            commit_pv_hash_events,
        } = self;
        base_alu_events.append(&mut other.base_alu_events);
        ext_alu_events.append(&mut other.ext_alu_events);
        *mem_const_count += other.mem_const_count;
        mem_var_events.append(&mut other.mem_var_events);
        ext_felt_conversion_events.append(&mut other.ext_felt_conversion_events);
        poseidon2_events.append(&mut other.poseidon2_events);
        poseidon2_linear_layer_events.append(&mut other.poseidon2_linear_layer_events);
        poseidon2_sbox_events.append(&mut other.poseidon2_sbox_events);
        select_events.append(&mut other.select_events);
        prefix_sum_checks_events.append(&mut other.prefix_sum_checks_events);
        commit_pv_hash_events.append(&mut other.commit_pv_hash_events);
    }

    fn public_values<T: AbstractField>(&self) -> Vec<T> {
        let pv_elms = self.public_values.as_array();

        let ret: [T; PROOF_MAX_NUM_PVS] = array::from_fn(|i| {
            if i < pv_elms.len() {
                T::from_canonical_u32(pv_elms[i].as_canonical_u32())
            } else {
                T::zero()
            }
        });

        ret.to_vec()
    }

    // No public value constraints for recursion public values.
    fn eval_public_values<AB: SP1AirBuilder>(_builder: &mut AB) {}

    fn interactions_in_public_values() -> Vec<InteractionKind> {
        vec![]
    }
}

impl<F: Field> ExecutionRecord<F> {
    pub fn compute_event_counts<'a>(
        instrs: impl Iterator<Item = &'a Instruction<F>> + 'a,
    ) -> RecursionAirEventCount {
        instrs.fold(RecursionAirEventCount::default(), Add::add)
    }
}

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecursionAirEventCount {
    pub mem_const_events: usize,
    pub mem_var_events: usize,
    pub base_alu_events: usize,
    pub ext_alu_events: usize,
    pub ext_felt_conversion_events: usize,
    pub poseidon2_wide_events: usize,
    pub poseidon2_linear_layer_events: usize,
    pub poseidon2_sbox_events: usize,
    pub select_events: usize,
    pub prefix_sum_checks_events: usize,
    pub commit_pv_hash_events: usize,
}

impl RecursionAirEventCount {
    /// Claims the starting offset in the relevant event vector for `instr`'s events, advancing
    /// the corresponding counter. The executor writes events at these offsets without
    /// synchronization; see [`crate::analyzed`] for the safety argument.
    #[inline]
    pub fn claim_offset<F>(&mut self, instr: &Instruction<F>) -> usize {
        /// Increment a counter and return the previous value.
        #[inline]
        fn incr(num: &mut usize, amt: usize) -> usize {
            let start = *num;
            *num += amt;
            start
        }

        match instr {
            Instruction::BaseAlu(_) => incr(&mut self.base_alu_events, 1),
            Instruction::ExtAlu(_) => incr(&mut self.ext_alu_events, 1),
            Instruction::Mem(_) => incr(&mut self.mem_const_events, 1),
            Instruction::ExtFelt(_) => incr(&mut self.ext_felt_conversion_events, 1),
            Instruction::Poseidon2(_) => incr(&mut self.poseidon2_wide_events, 1),
            Instruction::Poseidon2LinearLayer(_) => {
                incr(&mut self.poseidon2_linear_layer_events, 1)
            }
            Instruction::Poseidon2SBox(_) => incr(&mut self.poseidon2_sbox_events, 1),
            Instruction::Select(_) => incr(&mut self.select_events, 1),
            Instruction::Hint(HintInstr { output_addrs_mults })
            | Instruction::HintBits(HintBitsInstr {
                output_addrs_mults,
                input_addr: _, // No receive interaction for the hint operation
            }) => incr(&mut self.mem_var_events, output_addrs_mults.len()),
            Instruction::HintExt2Felts(HintExt2FeltsInstr {
                output_addrs_mults,
                input_addr: _, // No receive interaction for the hint operation
            }) => incr(&mut self.mem_var_events, output_addrs_mults.len()),
            Instruction::PrefixSumChecks(instr) => {
                incr(&mut self.prefix_sum_checks_events, instr.addrs.x1.len())
            }
            Instruction::HintAddCurve(instr) => incr(
                &mut self.mem_var_events,
                instr.output_x_addrs_mults.len() + instr.output_y_addrs_mults.len(),
            ),
            Instruction::CommitPublicValues(_) => incr(&mut self.commit_pv_hash_events, 1),
            // Placeholder; the executor does not create events for these instructions.
            Instruction::Print(_) | Instruction::DebugBacktrace(_) => 0,
        }
    }
}

impl<F> AddAssign<&Instruction<F>> for RecursionAirEventCount {
    #[inline]
    fn add_assign(&mut self, rhs: &Instruction<F>) {
        match rhs {
            Instruction::BaseAlu(_) => self.base_alu_events += 1,
            Instruction::ExtAlu(_) => self.ext_alu_events += 1,
            Instruction::ExtFelt(_) => self.ext_felt_conversion_events += 1,
            Instruction::Mem(_) => self.mem_const_events += 1,
            Instruction::Poseidon2(_) => self.poseidon2_wide_events += 1,
            Instruction::Poseidon2LinearLayer(_) => self.poseidon2_linear_layer_events += 1,
            Instruction::Poseidon2SBox(_) => self.poseidon2_sbox_events += 1,
            Instruction::Select(_) => self.select_events += 1,
            Instruction::Hint(HintInstr { output_addrs_mults })
            | Instruction::HintBits(HintBitsInstr {
                output_addrs_mults,
                input_addr: _, // No receive interaction for the hint operation
            }) => self.mem_var_events += output_addrs_mults.len(),
            Instruction::HintExt2Felts(HintExt2FeltsInstr {
                output_addrs_mults,
                input_addr: _, // No receive interaction for the hint operation
            }) => self.mem_var_events += output_addrs_mults.len(),
            Instruction::PrefixSumChecks(instr) => {
                self.prefix_sum_checks_events += instr.addrs.x1.len()
            }
            Instruction::HintAddCurve(instr) => {
                self.mem_var_events += instr.output_x_addrs_mults.len();
                self.mem_var_events += instr.output_y_addrs_mults.len();
            }
            Instruction::CommitPublicValues(_) => self.commit_pv_hash_events += 1,
            Instruction::Print(_) | Instruction::DebugBacktrace(_) => {}
        }
    }
}

impl<F> Add<&Instruction<F>> for RecursionAirEventCount {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Instruction<F>) -> Self::Output {
        self += rhs;
        self
    }
}
