use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use sp1_core::utils::{
    InnerBatchOpening, InnerChallenge, InnerCommitPhaseStep, InnerDigest, InnerFriProof,
    InnerPcsProof, InnerQueryProof, InnerVal,
};
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_compiler::{
    asm::AsmConfig,
    ir::{Array, Builder, Config},
};
use sp1_recursion_core::{air::Block, runtime::DIGEST_SIZE};

use super::types::{BatchOpeningVariable, TwoAdicPcsProofVariable};
use crate::fri::types::{
    DigestVariable, FriCommitPhaseProofStepVariable, FriProofVariable, FriQueryProofVariable,
};
use crate::hints::Hintable;

type C = InnerConfig;

impl Hintable<C> for InnerDigest {
    type HintVariable = DigestVariable<C>;

    fn read(builder: &mut Builder<AsmConfig<InnerVal, InnerChallenge>>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn write(&self) -> Vec<Vec<Block<InnerVal>>> {
        let h: [InnerVal; DIGEST_SIZE] = *self;
        vec![h.iter().map(|x| Block::from(*x)).collect()]
    }
}

impl Hintable<C> for Vec<InnerDigest> {
    type HintVariable = Array<C, DigestVariable<C>>;

    fn read(builder: &mut Builder<AsmConfig<InnerVal, InnerChallenge>>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = InnerDigest::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<InnerVal>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = InnerDigest::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<C> for InnerCommitPhaseStep {
    type HintVariable = FriCommitPhaseProofStepVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let sibling_value = builder.hint_ext();
        let opening_proof = Vec::<InnerDigest>::read(builder);
        Self::HintVariable {
            sibling_value,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let sibling_value: &[InnerVal] = self.sibling_value.as_base_slice();
        let sibling_value = Block::from(sibling_value);
        stream.push(vec![sibling_value]);

        stream.extend(Vec::<InnerDigest>::write(&self.opening_proof));

        stream
    }
}

impl Hintable<C> for Vec<InnerCommitPhaseStep> {
    type HintVariable = Array<C, FriCommitPhaseProofStepVariable<C>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = InnerCommitPhaseStep::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = InnerCommitPhaseStep::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<C> for InnerQueryProof {
    type HintVariable = FriQueryProofVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let commit_phase_openings = Vec::<InnerCommitPhaseStep>::read(builder);
        Self::HintVariable {
            commit_phase_openings,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        stream.extend(Vec::<InnerCommitPhaseStep>::write(
            &self.commit_phase_openings,
        ));

        stream
    }
}

impl Hintable<C> for Vec<InnerQueryProof> {
    type HintVariable = Array<C, FriQueryProofVariable<C>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = InnerQueryProof::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = InnerQueryProof::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<C> for InnerFriProof {
    type HintVariable = FriProofVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let commit_phase_commits = Vec::<InnerDigest>::read(builder);
        let query_proofs = Vec::<InnerQueryProof>::read(builder);
        let final_poly = builder.hint_ext();
        let pow_witness = builder.hint_felt();
        Self::HintVariable {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        stream.extend(Vec::<InnerDigest>::write(
            &self
                .commit_phase_commits
                .iter()
                .map(|x| (*x).into())
                .collect(),
        ));
        stream.extend(Vec::<InnerQueryProof>::write(&self.query_proofs));
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

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let opened_values = Vec::<Vec<InnerChallenge>>::read(builder);
        let opening_proof = Vec::<InnerDigest>::read(builder);
        Self::HintVariable {
            opened_values,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(Vec::<Vec<InnerChallenge>>::write(
            &self
                .opened_values
                .iter()
                .map(|v| v.iter().map(|x| InnerChallenge::from_base(*x)).collect())
                .collect(),
        ));
        stream.extend(Vec::<InnerDigest>::write(&self.opening_proof));
        stream
    }
}

impl Hintable<C> for Vec<InnerBatchOpening> {
    type HintVariable = Array<C, BatchOpeningVariable<C>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = InnerBatchOpening::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = InnerBatchOpening::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<C> for Vec<Vec<InnerBatchOpening>> {
    type HintVariable = Array<C, Array<C, BatchOpeningVariable<C>>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = Vec::<InnerBatchOpening>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = Vec::<InnerBatchOpening>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<C> for InnerPcsProof {
    type HintVariable = TwoAdicPcsProofVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let fri_proof = InnerFriProof::read(builder);
        let query_openings = Vec::<Vec<InnerBatchOpening>>::read(builder);
        Self::HintVariable {
            fri_proof,
            query_openings,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.fri_proof.write());
        stream.extend(self.query_openings.write());
        stream
    }
}
