use p3_air::AirBuilderWithPublicValues;
use sp1_core::air::{BaseAirBuilder, ExtensionAirBuilder};

pub trait SP1RecursionAirBuilder:
    BaseAirBuilder + ExtensionAirBuilder + AirBuilderWithPublicValues
{
}

impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> SP1RecursionAirBuilder for AB {}
