use serde::{Deserialize, Serialize};
use slop_algebra::{Field, PrimeField, PrimeField31, PrimeField64};
use slop_challenger::GrindingChallenger;
use slop_symmetric::CryptographicPermutation;
use sp1_gpu_challenger::{grind_koala_bear_challenger_on_device, KoalaBearDuplexChallenger};
use sp1_gpu_cudart::TaskScope;

/// A [`GrindingChallenger`] that can also grind on device.
pub trait DeviceGrindingChallenger: GrindingChallenger {
    /// Grinds on device.
    fn grind_device(&mut self, bits: usize, scope: &TaskScope) -> Self::Witness;
}

// Concrete implementation for KoalaBear DuplexChallenger - uses GPU grinding
impl DeviceGrindingChallenger for KoalaBearDuplexChallenger {
    fn grind_device(&mut self, bits: usize, scope: &TaskScope) -> Self::Witness {
        grind_koala_bear_challenger_on_device(self, bits, scope)
    }
}

// Generic implementation for MultiField32Challenger - uses CPU grinding
impl<F, PF, P, const WIDTH: usize, const RATE: usize> DeviceGrindingChallenger
    for slop_challenger::MultiField32Challenger<F, PF, P, WIDTH, RATE>
where
    F: PrimeField64 + PrimeField31 + Send + Sync,
    PF: PrimeField + Field + Send + Sync,
    P: CryptographicPermutation<[PF; WIDTH]> + Send + Sync,
{
    fn grind_device(&mut self, bits: usize, _scope: &TaskScope) -> Self::Witness {
        // Use CPU grinding for MultiField32Challenger
        self.grind(bits)
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct GrindingPowCudaProver;

impl GrindingPowCudaProver {
    pub fn grind<C: DeviceGrindingChallenger + Send + Sync>(
        challenger: &mut C,
        bits: usize,
        scope: &TaskScope,
    ) -> C::Witness {
        challenger.grind_device(bits, scope)
    }
}

#[cfg(test)]
mod tests {
    use crate::grinding_challenger::DeviceGrindingChallenger;
    use slop_algebra::AbstractField;
    use slop_challenger::{CanObserve, CanSample, GrindingChallenger};
    use slop_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use sp1_hypercube::inner_perm;
    use sp1_primitives::{SP1DiffusionMatrix, SP1Field};

    pub type Perm = Poseidon2<SP1Field, Poseidon2ExternalMatrixGeneral, SP1DiffusionMatrix, 16, 3>;

    #[test]
    fn test_grinding() {
        sp1_gpu_cudart::run_sync_in_place(|t| {
            for bits in 1..20 {
                let default_perm = inner_perm();
                let mut challenger =
                    slop_challenger::DuplexChallenger::<SP1Field, Perm, 16, 8>::new(default_perm);

                // Observe 7 elements to make the input buffer almost full and trigger duplexing on
                challenger.observe(SP1Field::from_canonical_u32(0));
                challenger.observe(SP1Field::from_canonical_u32(1));
                challenger.observe(SP1Field::from_canonical_u32(2));
                challenger.observe(SP1Field::from_canonical_u32(3));
                challenger.observe(SP1Field::from_canonical_u32(4));
                challenger.observe(SP1Field::from_canonical_u32(5));
                challenger.observe(SP1Field::from_canonical_u32(6));
                challenger.observe(SP1Field::from_canonical_u32(7));

                // Make another challenger that also samples before grinding (this empties the input buffer).
                let mut challenger_2 = challenger.clone();
                let _: SP1Field = challenger.sample();

                let mut original_challenger = challenger.clone();
                let result = challenger.grind_device(bits, &t);

                assert!(original_challenger.check_witness(bits, result));

                let mut original_challenger_2 = challenger_2.clone();
                let result_2 = challenger_2.grind_device(bits, &t);

                assert!(original_challenger_2.check_witness(bits, result_2));

                // Checks to make sure the pow witness was properly observed in `grind_on_device`.
                assert!(original_challenger_2.sponge_state == challenger_2.sponge_state);
                assert!(original_challenger_2.input_buffer == challenger_2.input_buffer);
                assert!(original_challenger_2.output_buffer == challenger_2.output_buffer);
            }
        })
        .unwrap()
    }
}
