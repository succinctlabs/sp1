use p3_air::AirBuilderWithPublicValues;
use sp1_core::air::{BaseAirBuilder, MachineAirBuilder};

/// Builder for the SP1 recursion machine AIRs.
pub trait SP1RecursionAirBuilder: MachineAirBuilder {}

impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> SP1RecursionAirBuilder for AB {}
