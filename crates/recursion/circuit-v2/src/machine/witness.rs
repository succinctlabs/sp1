use std::borrow::Borrow;

use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_symmetric::Hash;

use p3_field::AbstractField;
use sp1_recursion_compiler::ir::Builder;
use sp1_stark::{
    air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, InnerChallenge, InnerPerm, InnerVal,
    StarkVerifyingKey,
};

use sp1_recursion_compiler::ir::Felt;

use crate::{
    challenger::DuplexChallengerVariable,
    witness::{WitnessWriter, Witnessable},
    CircuitConfig, VerifyingKeyVariable,
};

use super::{SP1RecursionMemoryLayout, SP1RecursionWitnessVariable};

impl<C> Witnessable<C> for DuplexChallenger<InnerVal, InnerPerm, 16, 8>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = DuplexChallengerVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let sponge_state = self.sponge_state.read(builder);
        let input_buffer = self.input_buffer.read(builder);
        let output_buffer = self.output_buffer.read(builder);
        DuplexChallengerVariable { sponge_state, input_buffer, output_buffer }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.sponge_state.write(witness);
        self.input_buffer.write(witness);
        self.output_buffer.write(witness);
    }
}

impl<C, F, W, const DIGEST_ELEMENTS: usize> Witnessable<C> for Hash<F, W, DIGEST_ELEMENTS>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    W: Witnessable<C>,
{
    type WitnessVariable = [W::WitnessVariable; DIGEST_ELEMENTS];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.write(witness);
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

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.commit.write(witness);
        self.pc_start.write(witness);
    }
}

impl<'a, C, A> Witnessable<C> for SP1RecursionMemoryLayout<'a, BabyBearPoseidon2, A>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>>,
    A: MachineAir<BabyBear>,
{
    type WitnessVariable = SP1RecursionWitnessVariable<C, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let vk = self.vk.read(builder);
        let shard_proofs = self.shard_proofs.read(builder);
        let leaf_challenger = self.leaf_challenger.read(builder);
        let initial_reconstruct_challenger = self.initial_reconstruct_challenger.read(builder);
        let is_complete = InnerVal::from_bool(self.is_complete).read(builder);
        SP1RecursionWitnessVariable {
            vk,
            shard_proofs,
            leaf_challenger,
            initial_reconstruct_challenger,
            is_complete,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.vk.write(witness);
        self.shard_proofs.write(witness);
        self.leaf_challenger.write(witness);
        self.initial_reconstruct_challenger.write(witness);
        self.is_complete.write(witness);
    }
}
