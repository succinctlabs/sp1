use std::marker::PhantomData;

use p3_uni_stark::StarkConfig;

pub struct Verifier<SC>(PhantomData<SC>);

impl<SC: StarkConfig> Verifier<SC> {}
