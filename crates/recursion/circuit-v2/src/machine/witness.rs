use std::borrow::Borrow;

use p3_challenger::DuplexChallenger;
use p3_symmetric::Hash;

use p3_field::AbstractField;
use sp1_recursion_compiler::ir::{Builder, Config};
use sp1_stark::{
    baby_bear_poseidon2::BabyBearPoseidon2, InnerChallenge, InnerPerm, InnerVal, StarkVerifyingKey,
};

use sp1_recursion_compiler::ir::Felt;

use crate::{
    challenger::DuplexChallengerVariable, witness::Witnessable, CircuitConfig, VerifyingKeyVariable,
};

use super::{
    SP1CompressWitnessValues, SP1CompressWitnessVariable, SP1DeferredWitnessValues,
    SP1DeferredWitnessVariable, SP1RecursionWitnessValues, SP1RecursionWitnessVariable,
};

impl<C> Witnessable<C> for DuplexChallenger<InnerVal, InnerPerm, 16, 8>
where
    C: Config<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = DuplexChallengerVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let sponge_state = self.sponge_state.read(builder);
        let input_buffer = self.input_buffer.read(builder);
        let output_buffer = self.output_buffer.read(builder);
        DuplexChallengerVariable { sponge_state, input_buffer, output_buffer }
    }

    fn write(&self) -> Vec<crate::witness::Witness<C>> {
        [
            Witnessable::<C>::write(&self.sponge_state),
            Witnessable::<C>::write(&self.input_buffer),
            Witnessable::<C>::write(&self.output_buffer),
        ]
        .concat()
    }
}

impl<C, F, W, const DIGEST_ELEMENTS: usize> Witnessable<C> for Hash<F, W, DIGEST_ELEMENTS>
where
    C: Config<F = InnerVal, EF = InnerChallenge>,
    W: Witnessable<C>,
{
    type WitnessVariable = [W::WitnessVariable; DIGEST_ELEMENTS];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.read(builder)
    }

    fn write(&self) -> Vec<crate::witness::Witness<C>> {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.write()
    }
}

impl<C> Witnessable<C> for StarkVerifyingKey<BabyBearPoseidon2>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>>,
{
    type WitnessVariable = VerifyingKeyVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let commitment = self.commit.read(builder);
        let pc_start = self.pc_start.read(builder);
        let chip_information = self.chip_information.clone();
        let chip_ordering = self.chip_ordering.clone();
        VerifyingKeyVariable { commitment, pc_start, chip_information, chip_ordering }
    }

    fn write(&self) -> Vec<crate::witness::Witness<C>> {
        [Witnessable::<C>::write(&self.commit), Witnessable::<C>::write(&self.pc_start)].concat()
    }
}

impl<C> Witnessable<C> for SP1RecursionWitnessValues<BabyBearPoseidon2>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>>,
{
    type WitnessVariable = SP1RecursionWitnessVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let vk = self.vk.read(builder);
        let shard_proofs = self.shard_proofs.read(builder);
        let leaf_challenger = self.leaf_challenger.read(builder);
        // let initial_reconstruct_challenger = self.initial_reconstruct_challenger.read(builder);
        let is_complete = InnerVal::from_bool(self.is_complete).read(builder);
        SP1RecursionWitnessVariable {
            vk,
            shard_proofs,
            leaf_challenger,
            // initial_reconstruct_challenger,
            is_complete,
        }
    }

    fn write(&self) -> Vec<crate::witness::Witness<C>> {
        [
            Witnessable::<C>::write(&self.vk),
            Witnessable::<C>::write(&self.shard_proofs),
            Witnessable::<C>::write(&self.leaf_challenger),
            // Witnessable::<C>::write(&self.initial_reconstruct_challenger),
            Witnessable::<C>::write(&InnerVal::from_bool(self.is_complete)),
        ]
        .concat()
    }
}

impl<C> Witnessable<C> for SP1CompressWitnessValues<BabyBearPoseidon2>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>>,
{
    type WitnessVariable = SP1CompressWitnessVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let vks_and_proofs = self.vks_and_proofs.read(builder);
        let is_complete = InnerVal::from_bool(self.is_complete).read(builder);

        SP1CompressWitnessVariable { vks_and_proofs, is_complete }
    }

    fn write(&self) -> Vec<crate::witness::Witness<C>> {
        [
            Witnessable::<C>::write(&self.vks_and_proofs),
            Witnessable::<C>::write(&InnerVal::from_bool(self.is_complete)),
        ]
        .concat()
    }
}

impl<C> Witnessable<C> for SP1DeferredWitnessValues<BabyBearPoseidon2>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>>,
{
    type WitnessVariable = SP1DeferredWitnessVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let vks_and_proofs = self.vks_and_proofs.read(builder);
        let start_reconstruct_deferred_digest =
            self.start_reconstruct_deferred_digest.read(builder);
        let sp1_vk = self.sp1_vk.read(builder);
        let leaf_challenger = self.leaf_challenger.read(builder);
        let committed_value_digest = self.committed_value_digest.read(builder);
        let deferred_proofs_digest = self.deferred_proofs_digest.read(builder);
        let end_pc = self.end_pc.read(builder);
        let end_shard = self.end_shard.read(builder);
        let end_execution_shard = self.end_execution_shard.read(builder);
        let init_addr_bits = self.init_addr_bits.read(builder);
        let finalize_addr_bits = self.finalize_addr_bits.read(builder);
        let is_complete = InnerVal::from_bool(self.is_complete).read(builder);

        SP1DeferredWitnessVariable {
            vks_and_proofs,
            start_reconstruct_deferred_digest,
            sp1_vk,
            leaf_challenger,
            committed_value_digest,
            deferred_proofs_digest,
            end_pc,
            end_shard,
            end_execution_shard,
            init_addr_bits,
            finalize_addr_bits,
            is_complete,
        }
    }

    fn write(&self) -> Vec<crate::witness::Witness<C>> {
        [
            Witnessable::<C>::write(&self.vks_and_proofs),
            Witnessable::<C>::write(&self.start_reconstruct_deferred_digest),
            Witnessable::<C>::write(&self.sp1_vk),
            Witnessable::<C>::write(&self.leaf_challenger),
            Witnessable::<C>::write(&self.committed_value_digest),
            Witnessable::<C>::write(&self.deferred_proofs_digest),
            Witnessable::<C>::write(&self.end_pc),
            Witnessable::<C>::write(&self.end_shard),
            Witnessable::<C>::write(&self.end_execution_shard),
            Witnessable::<C>::write(&self.init_addr_bits),
            Witnessable::<C>::write(&self.finalize_addr_bits),
            Witnessable::<C>::write(&InnerVal::from_bool(self.is_complete)),
        ]
        .concat()
    }
}
