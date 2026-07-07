pub use p3_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, ExtensionBuilder, FilteredAirBuilder,
    PairBuilder, PermutationAirBuilder,
};

pub trait GlobalBuilder: AirBuilder {
    fn global(&self) -> Self::M;
}

impl<AB: GlobalBuilder> GlobalBuilder for FilteredAirBuilder<'_, AB> {
    fn global(&self) -> Self::M {
        self.inner.global()
    }
}
