pub struct SP1DeferredVerifier<C, SC, A> {
    _phantom: std::marker::PhantomData<(C, SC, A)>,
}

pub struct SP1DeferredWitnessValues<SC> {
    _marker: std::marker::PhantomData<SC>,
}
