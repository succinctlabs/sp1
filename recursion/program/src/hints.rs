use crate::fri::{BatchOpeningVariable, TwoAdicPcsProofVariable};
use crate::types::{
    Commitment, FriCommitPhaseProofStepVariable, FriProofVariable, FriQueryProofVariable,
};
use p3_field::{AbstractExtensionField, AbstractField};
use sp1_recursion_compiler::ir::{Ext, Felt};
use sp1_recursion_compiler::InnerConfig;
use sp1_recursion_compiler::{
    asm::AsmConfig,
    ir::{Array, Builder, Config, MemVariable},
};
use sp1_recursion_core::stark::config::{
    InnerBatchOpening, InnerCommitPhaseStep, InnerDigest, InnerFriProof, InnerPcsProof,
    InnerQueryProof,
};
use sp1_recursion_core::{
    air::Block,
    runtime::DIGEST_SIZE,
    stark::config::{InnerChallenge, InnerVal},
};

pub trait Hintable<C: Config> {
    type HintVariable: MemVariable<C>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable;

    fn hint_serialize(&self) -> Vec<Vec<Block<C::F>>>;
}

type C = InnerConfig;

impl Hintable<C> for InnerVal {
    type HintVariable = Felt<InnerVal>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_felt()
    }

    fn hint_serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![vec![Block::from(*self)]]
    }
}

impl Hintable<C> for InnerChallenge {
    type HintVariable = Ext<InnerVal, InnerChallenge>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_ext()
    }

    fn hint_serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![vec![Block::from((*self).as_base_slice())]]
    }
}

impl<T: Hintable<C>> Hintable<C> for Vec<T> {
    type HintVariable = Array<C, T::HintVariable>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = T::hint(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn hint_serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = T::hint_serialize(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<C> for InnerDigest {
    type HintVariable = Commitment<C>;

    fn hint(builder: &mut Builder<AsmConfig<InnerVal, InnerChallenge>>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn hint_serialize(&self) -> Vec<Vec<Block<InnerVal>>> {
        let h: [InnerVal; DIGEST_SIZE] = (*self).into();
        vec![h.iter().map(|x| Block::from(*x)).collect()]
    }
}

impl Hintable<C> for InnerCommitPhaseStep {
    type HintVariable = FriCommitPhaseProofStepVariable<C>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable {
        let sibling_value = builder.hint_ext();
        let opening_proof = Vec::<InnerDigest>::hint(builder);
        Self::HintVariable {
            sibling_value,
            opening_proof,
        }
    }

    fn hint_serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let sibling_value: &[InnerVal] = self.sibling_value.as_base_slice();
        let sibling_value = Block::from(sibling_value);
        stream.push(vec![sibling_value]);

        stream.extend(Vec::<InnerDigest>::hint_serialize(&self.opening_proof));

        stream
    }
}

impl Hintable<C> for InnerQueryProof {
    type HintVariable = FriQueryProofVariable<C>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable {
        let commit_phase_openings = Vec::<InnerCommitPhaseStep>::hint(builder);
        Self::HintVariable {
            commit_phase_openings,
        }
    }

    fn hint_serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        stream.extend(Vec::<InnerCommitPhaseStep>::hint_serialize(
            &self.commit_phase_openings,
        ));

        stream
    }
}

impl Hintable<C> for InnerFriProof {
    type HintVariable = FriProofVariable<C>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable {
        let commit_phase_commits = Vec::<InnerDigest>::hint(builder);
        let query_proofs = Vec::<InnerQueryProof>::hint(builder);
        let final_poly = builder.hint_ext();
        let pow_witness = builder.hint_felt();
        Self::HintVariable {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        }
    }

    fn hint_serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        stream.extend(Vec::<InnerDigest>::hint_serialize(
            &self
                .commit_phase_commits
                .iter()
                .map(|x| (*x).into())
                .collect(),
        ));
        stream.extend(Vec::<InnerQueryProof>::hint_serialize(&self.query_proofs));
        let final_poly: &[InnerVal] = self.final_poly.as_base_slice();
        let final_poly = Block::from(final_poly);
        stream.push(vec![final_poly]);
        let pow_witness = Block::from(self.pow_witness);
        stream.push(vec![pow_witness]);

        stream
    }
}

impl Hintable<C> for InnerBatchOpening {
    type HintVariable = BatchOpeningVariable<C>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable {
        let opened_values = Vec::<Vec<InnerChallenge>>::hint(builder);
        let opening_proof = Vec::<InnerDigest>::hint(builder);
        Self::HintVariable {
            opened_values,
            opening_proof,
        }
    }

    fn hint_serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(Vec::<Vec<InnerChallenge>>::hint_serialize(
            &self
                .opened_values
                .iter()
                .map(|v| v.iter().map(|x| InnerChallenge::from_base(*x)).collect())
                .collect(),
        ));
        stream.extend(Vec::<InnerDigest>::hint_serialize(&self.opening_proof));
        stream
    }
}

impl Hintable<C> for InnerPcsProof {
    type HintVariable = TwoAdicPcsProofVariable<C>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable {
        let fri_proof = InnerFriProof::hint(builder);
        let query_openings = Vec::<Vec<InnerBatchOpening>>::hint(builder);
        Self::HintVariable {
            fri_proof,
            query_openings,
        }
    }

    fn hint_serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.fri_proof.hint_serialize());
        stream.extend(self.query_openings.hint_serialize());
        stream
    }
}
