use sp1_core::{
    stark::{Challenge, Dom, StarkGenericConfig, Val},
    utils::BabyBearPoseidon2,
};
use sp1_recursion_compiler::{
    asm::AsmConfig,
    ir::{Builder, Config},
};

use crate::{
    challenger::{CanObserveVariable, DuplexChallengerVariable, FeltChallenger},
    commit::{PcsVariable, PolynomialSpaceVariable},
    fri::{TwoAdicFriPcsVariable, TwoAdicMultiplicativeCosetVariable},
};

type F<C> = <C as Config>::F;
type EF<C> = <C as Config>::EF;

pub trait RecursiveStarkConfig {
    type C: Config;
    type SC: StarkGenericConfig<Val = F<Self::C>, Challenge = EF<Self::C>>;

    type Domain: PolynomialSpaceVariable<Self::C, Constant = Dom<Self::SC>>;

    type Challenger: FeltChallenger<Self::C>
        + CanObserveVariable<
            Self::C,
            <Self::Pcs as PcsVariable<Self::C, Self::Challenger>>::Commitment,
        >;

    type Pcs: PcsVariable<Self::C, Self::Challenger>;

    fn pcs(&self) -> &Self::Pcs;

    fn challenger(&self, builder: &mut Builder<Self::C>) -> Self::Challenger;
}

pub struct VmTwoAdicFriConfig<SC: StarkGenericConfig> {
    pcs: TwoAdicFriPcsVariable<AsmConfig<SC::Val, SC::Challenge>>,
}

impl RecursiveStarkConfig for VmTwoAdicFriConfig<BabyBearPoseidon2> {
    type C = AsmConfig<Val<BabyBearPoseidon2>, Challenge<BabyBearPoseidon2>>;
    type SC = BabyBearPoseidon2;

    type Domain = TwoAdicMultiplicativeCosetVariable<Self::C>;

    type Challenger = DuplexChallengerVariable<Self::C>;

    type Pcs = TwoAdicFriPcsVariable<Self::C>;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self, builder: &mut Builder<Self::C>) -> Self::Challenger {
        DuplexChallengerVariable::new(builder)
    }
}
