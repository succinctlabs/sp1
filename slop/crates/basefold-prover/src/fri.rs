use std::{marker::PhantomData, sync::Arc};

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, ExtensionField, Field, TwoAdicField};
use slop_alloc::{Backend, Buffer, CpuBackend};
use slop_basefold::RsCodeWord;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_commit::Message;
pub use slop_fri::fold_even_odd as host_fold_even_odd;
use slop_merkle_tree::TensorCsProver;
use slop_multilinear::Mle;
use slop_tensor::Tensor;

pub struct MleBatch<F: Field, EF: ExtensionField<F>, A: Backend = CpuBackend> {
    pub batched_poly: Mle<F, A>,
    _marker: PhantomData<EF>,
}

#[derive(
    Debug, Clone, Default, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct FriCpuProver<GC, P>(pub PhantomData<(GC, P)>);

impl<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
        P: TensorCsProver<GC, CpuBackend> + Send + Sync + 'static,
    > FriCpuProver<GC, P>
{
    #[allow(clippy::type_complexity)]
    pub fn commit_phase_round(
        &self,
        current_mle: Mle<GC::EF, CpuBackend>,
        current_codeword: RsCodeWord<GC::F, CpuBackend>,
        tcs_prover: &P,
        challenger: &mut GC::Challenger,
    ) -> Result<
        (GC::EF, Mle<GC::EF>, RsCodeWord<GC::F>, GC::Digest, Arc<Tensor<GC::F>>, P::ProverData),
        P::ProverError,
    > {
        // Perform a single round of the FRI commit phase, returning the commitment, folded
        // codeword, and folding parameter.
        let original_sizes = current_codeword.data.sizes().to_vec();
        // On CPU, the current codeword is in row-major form, which means that in order to put
        // even and odd entries together all we need to do is rehsape it to multiply the number of
        // columns by 2 and divide the number of rows by 2.
        let leaves = Arc::new(
            current_codeword.data.clone().reshape([original_sizes[0] / 2, 2 * original_sizes[1]]),
        );
        let (commit, prover_data) =
            tcs_prover.commit_tensors(Message::<Tensor<_, _>>::from(leaves.clone()))?;
        // Observe the commitment.
        challenger.observe(commit);

        let beta: GC::EF = challenger.sample_ext_element();

        // To get the original codeword back, we need to reshape it to its original size.
        let current_codeword_vec =
            current_codeword.data.into_buffer().into_extension::<GC::EF>().into_vec();
        let folded_codeword_vec = host_fold_even_odd(current_codeword_vec, beta);
        let folded_codeword_storage = Buffer::from(folded_codeword_vec).flatten_to_base::<GC::F>();
        let mut new_size = original_sizes;
        new_size[0] /= 2;
        let folded_code_word_data = Tensor::from(folded_codeword_storage).reshape(new_size);
        let folded_codeword = RsCodeWord::new(folded_code_word_data);

        // Fold the mle.
        let folded_mle = current_mle.fold(beta);

        Ok((beta, folded_mle, folded_codeword, commit, leaves, prover_data))
    }

    pub fn final_poly(&self, final_codeword: RsCodeWord<GC::F, CpuBackend>) -> GC::EF {
        GC::EF::from_base_slice(&final_codeword.data.storage.as_slice()[0..GC::EF::D])
    }
}
