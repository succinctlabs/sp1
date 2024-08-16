use std::borrow::Borrow;

use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_field::AbstractField;
use p3_symmetric::Hash;

use sp1_core::air::MachineAir;
use sp1_core::stark::StarkVerifyingKey;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_core::utils::InnerChallenge;
use sp1_core::utils::InnerPerm;
use sp1_core::utils::InnerVal;

use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_compiler::ir::Config;
use sp1_recursion_compiler::ir::Felt;

use crate::challenger::DuplexChallengerVariable;
use crate::witness::Witnessable;
use crate::CircuitConfig;
use crate::VerifyingKeyVariable;

use super::SP1RecursionMemoryLayout;
use super::SP1RecursionWitnessVariable;

impl<C> Witnessable<C> for DuplexChallenger<InnerVal, InnerPerm, 16, 8>
where
    C: Config<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = DuplexChallengerVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let sponge_state = self.sponge_state.read(builder);
        let input_buffer = self.input_buffer.read(builder);
        let output_buffer = self.output_buffer.read(builder);
        DuplexChallengerVariable {
            sponge_state,
            input_buffer,
            output_buffer,
        }
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
        VerifyingKeyVariable {
            commitment,
            pc_start,
            chip_information,
            chip_ordering,
        }
    }

    fn write(&self) -> Vec<crate::witness::Witness<C>> {
        [
            Witnessable::<C>::write(&self.commit),
            Witnessable::<C>::write(&self.pc_start),
        ]
        .concat()
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

    fn write(&self) -> Vec<crate::witness::Witness<C>> {
        [
            Witnessable::<C>::write(&self.vk),
            Witnessable::<C>::write(&self.shard_proofs),
            Witnessable::<C>::write(&self.leaf_challenger),
            Witnessable::<C>::write(&self.initial_reconstruct_challenger),
            Witnessable::<C>::write(&InnerVal::from_bool(self.is_complete)),
        ]
        .concat()
    }
}
