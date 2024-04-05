use crate::types::{Commitment, FriCommitPhaseProofStepVariable, FriQueryProofVariable};
use p3_field::{AbstractExtensionField, AbstractField};
use p3_fri::QueryProof;
use p3_symmetric::Hash;
use sp1_recursion_compiler::{
    asm::AsmConfig,
    ir::{Array, Builder, Config, MemVariable},
};
use sp1_recursion_core::stark::config::{InnerCommitPhaseStep, InnerDigest, InnerQueryProof};
use sp1_recursion_core::{
    air::Block,
    runtime::DIGEST_SIZE,
    stark::config::{InnerChallenge, InnerVal},
};

trait Hintable<C: Config> {
    type HintVariable: MemVariable<C>;

    fn hint(builder: &mut Builder<C>) -> Self::HintVariable;

    fn serialize(&self) -> Vec<Vec<Block<C::F>>>;
}

type C = AsmConfig<InnerVal, InnerChallenge>;

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

    fn serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = T::serialize(arr);
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

    fn serialize(&self) -> Vec<Vec<Block<InnerVal>>> {
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

    fn serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let sibling_value: &[InnerVal] = self.sibling_value.as_base_slice();
        let sibling_value = Block::from(sibling_value);
        stream.push(vec![sibling_value]);

        stream.extend(Vec::<InnerDigest>::serialize(&self.opening_proof));

        stream
    }
}

// impl Hintable<C> for InnerQueryProof {
//     type HintVariable = FriQueryProofVariable<C>;

//     fn hint(builder: &mut Builder<C>) -> Self::HintVariable {
//         let commit_phase_openings =
//     }

//     fn serialize(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
//         todo!()
//     }
// }
