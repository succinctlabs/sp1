use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::TwoAdicField;
use p3_field::{AbstractExtensionField, AbstractField};
use sp1_core::air::{MachineAir, Word, PV_DIGEST_NUM_WORDS};
use sp1_core::stark::StarkGenericConfig;
use sp1_core::stark::{
    AirOpenedValues, ChipOpenedValues, Com, RiscvAir, ShardCommitment, ShardOpenedValues,
};
use sp1_core::utils::{
    BabyBearPoseidon2, InnerChallenge, InnerDigest, InnerDigestHash, InnerPcsProof, InnerPerm,
    InnerVal,
};
use sp1_recursion_compiler::{
    config::InnerConfig,
    ir::{Array, Builder, Config, Ext, Felt, MemVariable, Var},
};
use sp1_recursion_core::air::Block;
use sp1_recursion_core::runtime::PERMUTATION_WIDTH;

use crate::challenger::DuplexChallengerVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::machine::*;
use crate::stark::{ShardProofHint, VerifyingKeyHint};
use crate::types::{
    AirOpenedValuesVariable, ChipOpenedValuesVariable, Sha256DigestVariable,
    ShardCommitmentVariable, ShardOpenedValuesVariable, ShardProofVariable, VerifyingKeyVariable,
};
use crate::types::{QuotientData, QuotientDataValues};
use crate::utils::{get_chip_quotient_data, get_preprocessed_data, get_sorted_indices};

pub trait Hintable<C: Config> {
    type HintVariable: MemVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable;

    fn write(&self) -> Vec<Vec<Block<C::F>>>;

    fn witness(variable: &Self::HintVariable, builder: &mut Builder<C>) {
        let target = Self::read(builder);
        builder.assign(variable.clone(), target);
    }
}

type C = InnerConfig;

impl Hintable<C> for usize {
    type HintVariable = Var<InnerVal>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_var()
    }

    fn write(&self) -> Vec<Vec<Block<InnerVal>>> {
        vec![vec![Block::from(InnerVal::from_canonical_usize(*self))]]
    }
}

impl Hintable<C> for InnerVal {
    type HintVariable = Felt<InnerVal>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_felt()
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![vec![Block::from(*self)]]
    }
}

impl Hintable<C> for InnerChallenge {
    type HintVariable = Ext<InnerVal, InnerChallenge>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_ext()
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![vec![Block::from((*self).as_base_slice())]]
    }
}

impl Hintable<C> for [Word<BabyBear>; PV_DIGEST_NUM_WORDS] {
    type HintVariable = Sha256DigestVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let bytes = builder.hint_felts();
        Sha256DigestVariable { bytes }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![self
            .iter()
            .flat_map(|w| w.0.iter().map(|f| Block::from(*f)))
            .collect::<Vec<_>>()]
    }
}

impl Hintable<C> for QuotientDataValues {
    type HintVariable = QuotientData<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let log_quotient_degree = usize::read(builder);
        let quotient_size = usize::read(builder);

        QuotientData {
            log_quotient_degree,
            quotient_size,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut buffer = Vec::new();
        buffer.extend(usize::write(&self.log_quotient_degree));
        buffer.extend(usize::write(&self.quotient_size));

        buffer
    }
}

impl Hintable<C> for TwoAdicMultiplicativeCoset<InnerVal> {
    type HintVariable = TwoAdicMultiplicativeCosetVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let log_n = usize::read(builder);
        let shift = InnerVal::read(builder);
        let g_val = InnerVal::read(builder);
        let size = usize::read(builder);

        // Initialize a domain.
        TwoAdicMultiplicativeCosetVariable::<C> {
            log_n,
            size,
            shift,
            g: g_val,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut vec = Vec::new();
        vec.extend(usize::write(&self.log_n));
        vec.extend(InnerVal::write(&self.shift));
        vec.extend(InnerVal::write(&InnerVal::two_adic_generator(self.log_n)));
        vec.extend(usize::write(&(1usize << (self.log_n))));
        vec
    }
}

trait VecAutoHintable<C: Config>: Hintable<C> {}

impl<'a, A: MachineAir<BabyBear>> VecAutoHintable<C> for ShardProofHint<'a, BabyBearPoseidon2, A> {}
impl VecAutoHintable<C> for TwoAdicMultiplicativeCoset<InnerVal> {}
impl VecAutoHintable<C> for Vec<usize> {}
impl VecAutoHintable<C> for QuotientDataValues {}
impl VecAutoHintable<C> for Vec<QuotientDataValues> {}
impl VecAutoHintable<C> for Vec<InnerVal> {}

impl<I: VecAutoHintable<C>> VecAutoHintable<C> for &I {}

impl<H: Hintable<C>> Hintable<C> for &H {
    type HintVariable = H::HintVariable;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        H::read(builder)
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        H::write(self)
    }
}

impl<I: VecAutoHintable<C>> Hintable<C> for Vec<I> {
    type HintVariable = Array<C, I::HintVariable>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = I::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|i| {
            let comm = I::write(i);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<C> for Vec<usize> {
    type HintVariable = Array<C, Var<InnerVal>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_vars()
    }

    fn write(&self) -> Vec<Vec<Block<InnerVal>>> {
        vec![self
            .iter()
            .map(|x| Block::from(InnerVal::from_canonical_usize(*x)))
            .collect()]
    }
}

impl Hintable<C> for Vec<InnerVal> {
    type HintVariable = Array<C, Felt<InnerVal>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![self.iter().map(|x| Block::from(*x)).collect()]
    }
}

impl Hintable<C> for Vec<InnerChallenge> {
    type HintVariable = Array<C, Ext<InnerVal, InnerChallenge>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_exts()
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![self
            .iter()
            .map(|x| Block::from((*x).as_base_slice()))
            .collect()]
    }
}

impl Hintable<C> for AirOpenedValues<InnerChallenge> {
    type HintVariable = AirOpenedValuesVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let local = Vec::<InnerChallenge>::read(builder);
        let next = Vec::<InnerChallenge>::read(builder);
        AirOpenedValuesVariable { local, next }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.local.write());
        stream.extend(self.next.write());
        stream
    }
}

impl Hintable<C> for Vec<Vec<InnerChallenge>> {
    type HintVariable = Array<C, Array<C, Ext<InnerVal, InnerChallenge>>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = Vec::<InnerChallenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = Vec::<InnerChallenge>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<C> for ChipOpenedValues<InnerChallenge> {
    type HintVariable = ChipOpenedValuesVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let preprocessed = AirOpenedValues::<InnerChallenge>::read(builder);
        let main = AirOpenedValues::<InnerChallenge>::read(builder);
        let permutation = AirOpenedValues::<InnerChallenge>::read(builder);
        let quotient = Vec::<Vec<InnerChallenge>>::read(builder);
        let cumulative_sum = InnerChallenge::read(builder);
        let log_degree = builder.hint_var();
        ChipOpenedValuesVariable {
            preprocessed,
            main,
            permutation,
            quotient,
            cumulative_sum,
            log_degree,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.preprocessed.write());
        stream.extend(self.main.write());
        stream.extend(self.permutation.write());
        stream.extend(self.quotient.write());
        stream.extend(self.cumulative_sum.write());
        stream.extend(self.log_degree.write());
        stream
    }
}

impl Hintable<C> for Vec<ChipOpenedValues<InnerChallenge>> {
    type HintVariable = Array<C, ChipOpenedValuesVariable<C>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = ChipOpenedValues::<InnerChallenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = ChipOpenedValues::<InnerChallenge>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<C> for ShardOpenedValues<InnerChallenge> {
    type HintVariable = ShardOpenedValuesVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let chips = Vec::<ChipOpenedValues<InnerChallenge>>::read(builder);
        ShardOpenedValuesVariable { chips }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.chips.write());
        stream
    }
}

impl Hintable<C> for ShardCommitment<InnerDigestHash> {
    type HintVariable = ShardCommitmentVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let main_commit = InnerDigest::read(builder);
        let permutation_commit = InnerDigest::read(builder);
        let quotient_commit = InnerDigest::read(builder);
        ShardCommitmentVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        let h: InnerDigest = self.main_commit.into();
        stream.extend(h.write());
        let h: InnerDigest = self.permutation_commit.into();
        stream.extend(h.write());
        let h: InnerDigest = self.quotient_commit.into();
        stream.extend(h.write());
        stream
    }
}

impl Hintable<C> for DuplexChallenger<InnerVal, InnerPerm, 16, 8> {
    type HintVariable = DuplexChallengerVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let sponge_state = builder.hint_felts();
        let nb_inputs = builder.hint_var();
        let input_buffer = builder.hint_felts();
        let nb_outputs = builder.hint_var();
        let output_buffer = builder.hint_felts();
        DuplexChallengerVariable {
            sponge_state,
            nb_inputs,
            input_buffer,
            nb_outputs,
            output_buffer,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.sponge_state.to_vec().write());
        stream.extend(self.input_buffer.len().write());
        let mut input_padded = self.input_buffer.to_vec();
        input_padded.resize(PERMUTATION_WIDTH, InnerVal::zero());
        stream.extend(input_padded.write());
        stream.extend(self.output_buffer.len().write());
        let mut output_padded = self.output_buffer.to_vec();
        output_padded.resize(PERMUTATION_WIDTH, InnerVal::zero());
        stream.extend(output_padded.write());
        stream
    }
}

impl<
        'a,
        SC: StarkGenericConfig<
            Pcs = <BabyBearPoseidon2 as StarkGenericConfig>::Pcs,
            Challenge = <BabyBearPoseidon2 as StarkGenericConfig>::Challenge,
            Challenger = <BabyBearPoseidon2 as StarkGenericConfig>::Challenger,
        >,
        A: MachineAir<SC::Val>,
    > Hintable<C> for VerifyingKeyHint<'a, SC, A>
{
    type HintVariable = VerifyingKeyVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let commitment = InnerDigest::read(builder);
        let pc_start = InnerVal::read(builder);
        let preprocessed_sorted_idxs = Vec::<usize>::read(builder);
        let prep_domains = Vec::<TwoAdicMultiplicativeCoset<InnerVal>>::read(builder);
        VerifyingKeyVariable {
            commitment,
            pc_start,
            preprocessed_sorted_idxs,
            prep_domains,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let (preprocessed_sorted_idxs, prep_domains) = get_preprocessed_data(self.machine, self.vk);

        let mut stream = Vec::new();
        let h: InnerDigest = self.vk.commit.into();
        stream.extend(h.write());
        stream.extend(self.vk.pc_start.write());
        stream.extend(preprocessed_sorted_idxs.write());
        stream.extend(prep_domains.write());
        stream
    }
}

// Implement Hintable<C> for ShardProof where SC is equivalent to BabyBearPoseidon2
impl<
        'a,
        SC: StarkGenericConfig<
            Pcs = <BabyBearPoseidon2 as StarkGenericConfig>::Pcs,
            Challenge = <BabyBearPoseidon2 as StarkGenericConfig>::Challenge,
            Challenger = <BabyBearPoseidon2 as StarkGenericConfig>::Challenger,
        >,
        A: MachineAir<SC::Val>,
    > Hintable<C> for ShardProofHint<'a, SC, A>
where
    ShardCommitment<Com<SC>>: Hintable<C>,
{
    type HintVariable = ShardProofVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let commitment = ShardCommitment::read(builder);
        let opened_values = ShardOpenedValues::read(builder);
        let opening_proof = InnerPcsProof::read(builder);
        let public_values = Vec::<InnerVal>::read(builder);
        let quotient_data = Vec::<QuotientDataValues>::read(builder);
        let sorted_idxs = Vec::<usize>::read(builder);
        ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            public_values,
            quotient_data,
            sorted_idxs,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let quotient_data = get_chip_quotient_data(self.machine, self.proof);
        let sorted_indices = get_sorted_indices(self.machine, self.proof);

        let mut stream = Vec::new();
        stream.extend(self.proof.commitment.write());
        stream.extend(self.proof.opened_values.write());
        stream.extend(self.proof.opening_proof.write());
        stream.extend(self.proof.public_values.write());
        stream.extend(quotient_data.write());
        stream.extend(sorted_indices.write());

        stream
    }
}

impl<'a, A: MachineAir<BabyBear>> Hintable<C>
    for SP1RecursionMemoryLayout<'a, BabyBearPoseidon2, A>
{
    type HintVariable = SP1RecursionMemoryLayoutVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let vk = VerifyingKeyHint::<'a, BabyBearPoseidon2, A>::read(builder);
        let shard_proofs = Vec::<ShardProofHint<'a, BabyBearPoseidon2, A>>::read(builder);
        let leaf_challenger = DuplexChallenger::<InnerVal, InnerPerm, 16, 8>::read(builder);
        let initial_reconstruct_challenger =
            DuplexChallenger::<InnerVal, InnerPerm, 16, 8>::read(builder);
        let is_complete = builder.hint_var();
        let total_core_shards = builder.hint_var();

        SP1RecursionMemoryLayoutVariable {
            vk,
            shard_proofs,
            leaf_challenger,
            initial_reconstruct_challenger,
            is_complete,
            total_core_shards,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let vk_hint = VerifyingKeyHint::<'a, BabyBearPoseidon2, _>::new(self.machine, self.vk);

        let proof_hints = self
            .shard_proofs
            .iter()
            .map(|proof| ShardProofHint::<BabyBearPoseidon2, A>::new(self.machine, proof))
            .collect::<Vec<_>>();

        stream.extend(vk_hint.write());
        stream.extend(proof_hints.write());
        stream.extend(self.leaf_challenger.write());
        stream.extend(self.initial_reconstruct_challenger.write());
        stream.extend((self.is_complete as usize).write());
        stream.extend(self.total_core_shards.write());

        stream
    }
}

impl<'a, A: MachineAir<BabyBear>> Hintable<C> for SP1ReduceMemoryLayout<'a, BabyBearPoseidon2, A> {
    type HintVariable = SP1ReduceMemoryLayoutVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let compress_vk = VerifyingKeyHint::<'a, BabyBearPoseidon2, A>::read(builder);
        let shard_proofs = Vec::<ShardProofHint<'a, BabyBearPoseidon2, A>>::read(builder);
        let kinds = Vec::<usize>::read(builder);
        let is_complete = builder.hint_var();
        let total_core_shards = builder.hint_var();

        SP1ReduceMemoryLayoutVariable {
            compress_vk,
            shard_proofs,
            kinds,
            is_complete,
            total_core_shards,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let compress_vk_hint = VerifyingKeyHint::<'a, BabyBearPoseidon2, _>::new(
            self.recursive_machine,
            self.compress_vk,
        );

        let proof_hints = self
            .shard_proofs
            .iter()
            .map(|proof| ShardProofHint::<BabyBearPoseidon2, A>::new(self.recursive_machine, proof))
            .collect::<Vec<_>>();

        let kinds = self.kinds.iter().map(|k| *k as usize).collect::<Vec<_>>();

        stream.extend(compress_vk_hint.write());
        stream.extend(proof_hints.write());
        stream.extend(kinds.write());
        stream.extend((self.is_complete as usize).write());
        stream.extend(self.total_core_shards.write());

        stream
    }
}

impl<'a, A: MachineAir<BabyBear>> Hintable<C> for SP1RootMemoryLayout<'a, BabyBearPoseidon2, A> {
    type HintVariable = SP1RootMemoryLayoutVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let proof = ShardProofHint::<'a, BabyBearPoseidon2, A>::read(builder);
        let is_reduce = builder.hint_var();

        SP1RootMemoryLayoutVariable { proof, is_reduce }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let proof_hint = ShardProofHint::<BabyBearPoseidon2, A>::new(self.machine, &self.proof);

        stream.extend(proof_hint.write());
        stream.extend((self.is_reduce as usize).write());

        stream
    }
}

impl<'a, A: MachineAir<BabyBear>> Hintable<C>
    for SP1DeferredMemoryLayout<'a, BabyBearPoseidon2, A>
{
    type HintVariable = SP1DeferredMemoryLayoutVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let compress_vk = VerifyingKeyHint::<'a, BabyBearPoseidon2, A>::read(builder);
        let proofs = Vec::<ShardProofHint<'a, BabyBearPoseidon2, A>>::read(builder);
        let start_reconstruct_deferred_digest = Vec::<BabyBear>::read(builder);
        let is_complete = builder.hint_var();

        let sp1_vk = VerifyingKeyHint::<'a, BabyBearPoseidon2, RiscvAir<_>>::read(builder);
        let committed_value_digest = Vec::<Vec<InnerVal>>::read(builder);
        let deferred_proofs_digest = Vec::<InnerVal>::read(builder);
        let leaf_challenger = DuplexChallenger::<InnerVal, InnerPerm, 16, 8>::read(builder);
        let end_pc = InnerVal::read(builder);
        let end_shard = InnerVal::read(builder);
        let total_core_shards = builder.hint_var();

        SP1DeferredMemoryLayoutVariable {
            compress_vk,
            proofs,
            start_reconstruct_deferred_digest,
            is_complete,
            sp1_vk,
            committed_value_digest,
            deferred_proofs_digest,
            leaf_challenger,
            end_pc,
            end_shard,
            total_core_shards,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let sp1_vk_hint =
            VerifyingKeyHint::<'a, BabyBearPoseidon2, _>::new(self.sp1_machine, self.sp1_vk);

        let compress_vk_hint =
            VerifyingKeyHint::<'a, BabyBearPoseidon2, _>::new(self.machine, self.compress_vk);

        let proof_hints = self
            .proofs
            .iter()
            .map(|proof| ShardProofHint::<BabyBearPoseidon2, A>::new(self.machine, proof))
            .collect::<Vec<_>>();

        let committed_value_digest = self
            .committed_value_digest
            .iter()
            .map(|w| w.0.to_vec())
            .collect::<Vec<_>>();

        stream.extend(compress_vk_hint.write());
        stream.extend(proof_hints.write());
        stream.extend(self.start_reconstruct_deferred_digest.write());
        stream.extend((self.is_complete as usize).write());

        stream.extend(sp1_vk_hint.write());
        stream.extend(committed_value_digest.write());
        stream.extend(self.deferred_proofs_digest.write());
        stream.extend(self.leaf_challenger.write());
        stream.extend(self.end_pc.write());
        stream.extend(self.end_shard.write());
        stream.extend(self.total_core_shards.write());

        stream
    }
}
