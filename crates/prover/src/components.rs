use std::sync::Arc;

use sp1_core_executor::HEIGHT_THRESHOLD;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    prover::{AirProver, CpuShardProver, SP1InnerPcsProver, SP1OuterPcsProver},
    MachineVerifier, SP1InnerPcs, SP1OuterPcs, SP1Pcs, ShardContextImpl, ShardVerifier,
};
use sp1_primitives::{
    fri_params::{core_fri_config, recursion_fri_config, shrink_fri_config, wrap_fri_config},
    SP1Field, SP1GlobalContext, SP1OuterGlobalContext,
};
use sp1_verifier::compressed::{RECURSION_LOG_STACKING_HEIGHT, RECURSION_MAX_LOG_ROW_COUNT};
use static_assertions::const_assert;

pub const CORE_LOG_STACKING_HEIGHT: u32 = 21;
pub const CORE_MAX_LOG_ROW_COUNT: usize = 22;

const_assert!(HEIGHT_THRESHOLD <= (1 << CORE_MAX_LOG_ROW_COUNT));

use sp1_recursion_machine::RecursionAir;

const COMPRESS_DEGREE: usize = 3;
const SHRINK_DEGREE: usize = 3;
const WRAP_DEGREE: usize = 3;

pub type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE, 2>;
pub type ShrinkAir<F> = RecursionAir<F, SHRINK_DEGREE, 2>;
pub type WrapAir<F> = RecursionAir<F, WRAP_DEGREE, 1>;

pub const RECURSION_LOG_TRACE_AREA: usize = 27;
const SHRINK_LOG_STACKING_HEIGHT: u32 = 18;
pub(crate) const SHRINK_MAX_LOG_ROW_COUNT: usize = 19;

pub(crate) const WRAP_LOG_STACKING_HEIGHT: u32 = 21;

pub type CoreSC = ShardContextImpl<SP1GlobalContext, SP1Pcs<SP1GlobalContext>, RiscvAir<SP1Field>>;

pub type RecursionSC =
    ShardContextImpl<SP1GlobalContext, SP1Pcs<SP1GlobalContext>, CompressAir<SP1Field>>;
pub type ShrinkSC =
    ShardContextImpl<SP1GlobalContext, SP1Pcs<SP1GlobalContext>, ShrinkAir<SP1Field>>;

pub type WrapSC =
    ShardContextImpl<SP1OuterGlobalContext, SP1Pcs<SP1OuterGlobalContext>, WrapAir<SP1Field>>;

pub trait CoreProver: AirProver<SP1GlobalContext, CoreSC> {
    /// The default verifier for the core prover.
    ///
    /// The verifier fixes the parameters of the underlying proof system.
    fn verifier() -> MachineVerifier<SP1GlobalContext, CoreSC> {
        let core_log_stacking_height = CORE_LOG_STACKING_HEIGHT;
        let core_max_log_row_count = CORE_MAX_LOG_ROW_COUNT;

        let machine = RiscvAir::machine();

        let core_verifier = ShardVerifier::from_basefold_parameters(
            core_fri_config(),
            core_log_stacking_height,
            core_max_log_row_count,
            machine.clone(),
        );

        MachineVerifier::new(core_verifier)
    }
}

impl<C> CoreProver for C where C: AirProver<SP1GlobalContext, CoreSC> {}

pub trait RecursionProver: AirProver<SP1GlobalContext, RecursionSC> {
    fn verifier() -> MachineVerifier<SP1GlobalContext, RecursionSC> {
        let compress_log_stacking_height = RECURSION_LOG_STACKING_HEIGHT;
        let compress_max_log_row_count = RECURSION_MAX_LOG_ROW_COUNT;

        let machine = CompressAir::<SP1Field>::compress_machine();
        let recursion_shard_verifier = ShardVerifier::from_basefold_parameters(
            recursion_fri_config(),
            compress_log_stacking_height,
            compress_max_log_row_count,
            machine.clone(),
        );

        MachineVerifier::new(recursion_shard_verifier)
    }

    fn shrink_verifier() -> MachineVerifier<SP1GlobalContext, ShrinkSC> {
        let shrink_log_stacking_height = SHRINK_LOG_STACKING_HEIGHT;
        let shrink_max_log_row_count = SHRINK_MAX_LOG_ROW_COUNT;

        let machine = CompressAir::<SP1Field>::shrink_machine();
        let recursion_shard_verifier = ShardVerifier::from_basefold_parameters(
            shrink_fri_config(),
            shrink_log_stacking_height,
            shrink_max_log_row_count,
            machine.clone(),
        );

        MachineVerifier::new(recursion_shard_verifier)
    }
}

pub trait WrapProver: AirProver<SP1OuterGlobalContext, WrapSC> {
    fn wrap_verifier() -> MachineVerifier<SP1OuterGlobalContext, WrapSC> {
        let wrap_log_stacking_height = WRAP_LOG_STACKING_HEIGHT;
        let wrap_max_log_row_count = RECURSION_MAX_LOG_ROW_COUNT;

        let machine = WrapAir::<SP1Field>::wrap_machine();
        let wrap_shard_verifier = ShardVerifier::from_basefold_parameters(
            wrap_fri_config(),
            wrap_log_stacking_height,
            wrap_max_log_row_count,
            machine.clone(),
        );

        MachineVerifier::new(wrap_shard_verifier)
    }
}

impl<C> RecursionProver for C where C: AirProver<SP1GlobalContext, RecursionSC> {}

impl<C> WrapProver for C where C: AirProver<SP1OuterGlobalContext, WrapSC> {}

pub trait WrapProverBuilder<C: SP1ProverComponents>: Send + Sync + 'static {
    fn build(&self) -> Arc<C::WrapProver>;
}

pub struct ReadyWrapProverBuilder<C: SP1ProverComponents> {
    prover: Arc<C::WrapProver>,
}

impl<C: SP1ProverComponents> ReadyWrapProverBuilder<C> {
    pub fn new(prover: Arc<C::WrapProver>) -> Self {
        Self { prover }
    }
}

impl<C: SP1ProverComponents> WrapProverBuilder<C> for ReadyWrapProverBuilder<C> {
    fn build(&self) -> Arc<C::WrapProver> {
        self.prover.clone()
    }
}

pub trait SP1ProverComponents: Send + Sync + 'static + Sized {
    /// The prover for making SP1 core proofs.
    type CoreProver: CoreProver;
    /// The prover for making SP1 recursive proofs.
    type RecursionProver: RecursionProver;
    type WrapProver: WrapProver;
    type WrapProverBuilder: WrapProverBuilder<Self>;

    fn core_verifier() -> MachineVerifier<SP1GlobalContext, CoreSC> {
        <Self::CoreProver as CoreProver>::verifier()
    }

    fn compress_verifier() -> MachineVerifier<SP1GlobalContext, RecursionSC> {
        <Self::RecursionProver as RecursionProver>::verifier()
    }

    fn shrink_verifier() -> MachineVerifier<SP1GlobalContext, ShrinkSC> {
        <Self::RecursionProver as RecursionProver>::shrink_verifier()
    }

    fn wrap_verifier() -> MachineVerifier<SP1OuterGlobalContext, WrapSC> {
        <Self::WrapProver as WrapProver>::wrap_verifier()
    }
}

pub struct CpuSP1ProverComponents;

pub struct CpuWrapProverBuilder;

impl WrapProverBuilder<CpuSP1ProverComponents> for CpuWrapProverBuilder {
    fn build(&self) -> Arc<<CpuSP1ProverComponents as SP1ProverComponents>::WrapProver> {
        let wrap_verifier = CpuSP1ProverComponents::wrap_verifier();
        Arc::new(CpuShardProver::new(wrap_verifier.shard_verifier().clone()))
    }
}

impl SP1ProverComponents for CpuSP1ProverComponents {
    type CoreProver = CpuShardProver<
        SP1GlobalContext,
        SP1Pcs<SP1GlobalContext>,
        SP1InnerPcsProver,
        RiscvAir<SP1Field>,
    >;
    type RecursionProver =
        CpuShardProver<SP1GlobalContext, SP1InnerPcs, SP1InnerPcsProver, CompressAir<SP1Field>>;
    type WrapProver =
        CpuShardProver<SP1OuterGlobalContext, SP1OuterPcs, SP1OuterPcsProver, WrapAir<SP1Field>>;
    type WrapProverBuilder = CpuWrapProverBuilder;
}
