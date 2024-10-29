use std::{array, sync::Arc};

use hashbrown::HashMap;
use p3_field::{AbstractField, Field, PrimeField32};
use sp1_stark::{air::MachineAir, MachineRecord, SP1CoreOpts, PROOF_MAX_NUM_PVS};

use super::{
    BaseAluEvent, CommitPublicValuesEvent, ExpReverseBitsEvent, ExtAluEvent, FriFoldEvent,
    MemEvent, Poseidon2Event, RecursionProgram, RecursionPublicValues, SelectEvent,
};

#[derive(Clone, Default, Debug)]
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

    pub poseidon2_events: Vec<Poseidon2Event<F>>,
    pub select_events: Vec<SelectEvent<F>>,
    pub exp_reverse_bits_len_events: Vec<ExpReverseBitsEvent<F>>,
    pub fri_fold_events: Vec<FriFoldEvent<F>>,
    pub commit_pv_hash_events: Vec<CommitPublicValuesEvent<F>>,
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = SP1CoreOpts;

    fn stats(&self) -> hashbrown::HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("base_alu_events".to_string(), self.base_alu_events.len());
        stats.insert("ext_alu_events".to_string(), self.ext_alu_events.len());
        stats.insert("mem_var_events".to_string(), self.mem_var_events.len());

        stats.insert("poseidon2_events".to_string(), self.poseidon2_events.len());
        stats.insert("exp_reverse_bits_events".to_string(), self.exp_reverse_bits_len_events.len());
        stats.insert("fri_fold_events".to_string(), self.fri_fold_events.len());

        stats
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
            poseidon2_events,
            select_events,
            exp_reverse_bits_len_events,
            fri_fold_events,
            commit_pv_hash_events,
        } = self;
        base_alu_events.append(&mut other.base_alu_events);
        ext_alu_events.append(&mut other.ext_alu_events);
        *mem_const_count += other.mem_const_count;
        mem_var_events.append(&mut other.mem_var_events);
        poseidon2_events.append(&mut other.poseidon2_events);
        select_events.append(&mut other.select_events);
        exp_reverse_bits_len_events.append(&mut other.exp_reverse_bits_len_events);
        fri_fold_events.append(&mut other.fri_fold_events);
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
}

impl<F: Field> ExecutionRecord<F> {
    #[inline]
    pub fn fixed_log2_rows<A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.program.fixed_log2_rows(air)
    }
}
