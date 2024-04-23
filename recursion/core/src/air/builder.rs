use p3_air::AirBuilderWithPublicValues;
use sp1_core::air::{BaseAirBuilder, ExtensionAirBuilder};

/// Builder for the SP1 recursion machine AIRs.
pub trait SP1RecursionAirBuilder:
    BaseAirBuilder + ExtensionAirBuilder + AirBuilderWithPublicValues
{
}

impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> SP1RecursionAirBuilder for AB {}
