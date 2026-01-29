#![allow(clippy::disallowed_types)]

use crate::DuplexChallenger;
use slop_algebra::PrimeField64;
use slop_challenger::GrindingChallenger;
use slop_koala_bear::KoalaBear;
use slop_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use slop_symmetric::CryptographicPermutation;
use sp1_gpu_cudart::sys::challenger::grind_koala_bear;
use sp1_gpu_cudart::sys::runtime::KernelPtr;
use sp1_gpu_cudart::{args, DeviceBuffer, TaskScope};
use sp1_primitives::SP1DiffusionMatrix;

/// Poseidon2 permutation type for KoalaBear grinding.
pub type KoalaBearPerm =
    Poseidon2<KoalaBear, Poseidon2ExternalMatrixGeneral, SP1DiffusionMatrix, 16, 3>;

/// The standard duplex challenger type for KoalaBear.
pub type KoalaBearDuplexChallenger =
    slop_challenger::DuplexChallenger<KoalaBear, KoalaBearPerm, 16, 8>;

/// Returns the grinding kernel for KoalaBear.
fn koala_bear_grind_kernel() -> KernelPtr {
    unsafe { grind_koala_bear() }
}

/// Grinds on device synchronously for a DuplexChallenger.
///
/// This is a sync version that replaces the async `DeviceGrindingChallenger` trait.
pub fn grind_duplex_challenger_on_device<F, P, const WIDTH: usize, const RATE: usize>(
    challenger: &mut slop_challenger::DuplexChallenger<F, P, WIDTH, RATE>,
    bits: usize,
    grind_kernel: fn() -> KernelPtr,
    scope: &TaskScope,
) -> F
where
    F: PrimeField64 + Send + Sync,
    P: CryptographicPermutation<[F; WIDTH]> + Send + Sync,
{
    let cpu_challenger: DuplexChallenger<F, _> = challenger.clone().into();

    let mut result = DeviceBuffer::with_capacity_in(1, scope.clone());
    let mut found_flag = DeviceBuffer::<bool>::with_capacity_in(1, scope.clone());
    let mut gpu_challenger = cpu_challenger.to_device_sync(scope).unwrap();

    let block_dim: usize = 512;
    let grid_dim: usize = 1;
    let n = F::ORDER_U64;

    unsafe {
        result.assume_init();
        found_flag.assume_init();
        let args = args!(
            gpu_challenger.as_mut_raw(),
            result.as_mut_ptr(),
            bits,
            n,
            found_flag.as_mut_ptr()
        );
        scope.launch_kernel(grind_kernel(), (grid_dim, 1, 1), block_dim, &args, 0).unwrap();
    }

    // Copy result back to host synchronously
    let result = result.to_host().unwrap();
    // });

    let witness = *result.first().unwrap();

    // Check the witness. This is necessary because it changes the internal state of the
    // challenger, and the CPU version of the challenger does this as well. It's also necessary
    // for the security of the protocol.
    assert!(challenger.check_witness(bits, witness));
    witness
}

/// Convenience function to grind a KoalaBear duplex challenger on device.
pub fn grind_koala_bear_challenger_on_device(
    challenger: &mut KoalaBearDuplexChallenger,
    bits: usize,
    scope: &TaskScope,
) -> KoalaBear {
    grind_duplex_challenger_on_device(challenger, bits, koala_bear_grind_kernel, scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use slop_algebra::AbstractField;
    use slop_challenger::{CanObserve, CanSample, GrindingChallenger};
    use sp1_hypercube::inner_perm;

    #[test]
    fn test_grinding() {
        sp1_gpu_cudart::run_sync_in_place(|t| {
            for bits in 1..20 {
                let default_perm = inner_perm();
                let mut challenger = KoalaBearDuplexChallenger::new(default_perm);

                // Observe 7 elements to make the input buffer almost full and trigger duplexing on
                challenger.observe(KoalaBear::from_canonical_u32(0));
                challenger.observe(KoalaBear::from_canonical_u32(1));
                challenger.observe(KoalaBear::from_canonical_u32(2));
                challenger.observe(KoalaBear::from_canonical_u32(3));
                challenger.observe(KoalaBear::from_canonical_u32(4));
                challenger.observe(KoalaBear::from_canonical_u32(5));
                challenger.observe(KoalaBear::from_canonical_u32(6));
                challenger.observe(KoalaBear::from_canonical_u32(7));

                // Make another challenger that also samples before grinding (this empties the input buffer).
                let mut challenger_2 = challenger.clone();
                let _: KoalaBear = challenger.sample();

                let mut original_challenger = challenger.clone();
                let result = grind_koala_bear_challenger_on_device(&mut challenger, bits, &t);

                assert!(original_challenger.check_witness(bits, result));

                let mut original_challenger_2 = challenger_2.clone();
                let result_2 = grind_koala_bear_challenger_on_device(&mut challenger_2, bits, &t);

                assert!(original_challenger_2.check_witness(bits, result_2));

                // Checks to make sure the pow witness was properly observed in `grind_on_device`.
                assert!(original_challenger_2.sponge_state == challenger_2.sponge_state);
                assert!(original_challenger_2.input_buffer == challenger_2.input_buffer);
                assert!(original_challenger_2.output_buffer == challenger_2.output_buffer);
            }
        })
        .unwrap();
    }
}
