use p3_field::{AbstractExtensionField, AbstractField};
use sp1_core::stark::{AirOpenedValues, ChipOpenedValues};
use sp1_recursion_compiler::{
    ir::{Array, Builder, Config, Ext, Felt, MemVariable, Var},
    InnerConfig,
};
use sp1_recursion_core::{
    air::Block,
    stark::config::{InnerChallenge, InnerVal},
};

use crate::types::{AirOpenedValuesVariable, ChipOpenedValuesVariable};

pub trait Hintable<C: Config> {
    type HintVariable: MemVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable;

    fn write(&self) -> Vec<Vec<Block<C::F>>>;
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

impl<T: Hintable<C>> Hintable<C> for Vec<T> {
    type HintVariable = Array<C, T::HintVariable>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = T::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = T::write(arr);
            stream.extend(comm);
        });

        stream
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
