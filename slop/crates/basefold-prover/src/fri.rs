use std::{marker::PhantomData, sync::Arc};

use itertools::Itertools;

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, ExtensionField, Field, TwoAdicField};
use slop_alloc::{Backend, Buffer, CpuBackend};
use slop_basefold::RsCodeWord;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_commit::Message;
pub use slop_fri::fold_even_odd as host_fold_even_odd;
use slop_futures::OwnedBorrow;
use slop_merkle_tree::TensorCsProver;
use slop_multilinear::{Mle, MleEval};
use slop_tensor::Tensor;

use crate::CpuDftEncoder;

pub struct MleBatch<F: Field, EF: ExtensionField<F>, A: Backend = CpuBackend> {
    pub batched_poly: Mle<F, A>,
    _marker: PhantomData<EF>,
}

#[derive(
    Debug, Clone, Default, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct FriCpuProver<GC, P>(pub PhantomData<(GC, P)>);

impl<GC: IopCtx<F: TwoAdicField>, P: TensorCsProver<GC, CpuBackend>> FriCpuProver<GC, P> {
    #[allow(clippy::type_complexity)]
    pub(crate) fn batch<M, Code>(
        &self,
        batching_coefficients: &Tensor<GC::EF>,
        mles: Message<M>,
        _codewords: Message<Code>,
        evaluation_claims: Vec<MleEval<GC::EF, CpuBackend>>,
        encoder: &CpuDftEncoder<GC::F>,
    ) -> (Mle<GC::EF, CpuBackend>, RsCodeWord<GC::F, CpuBackend>, GC::EF)
    where
        M: OwnedBorrow<Mle<GC::F>>,
        Code: OwnedBorrow<RsCodeWord<GC::F>>,
    {
        let encoder = encoder.clone();
        let num_variables = mles.first().unwrap().as_ref().borrow().num_variables() as usize;

        let mut batching_coefficients_iter = batching_coefficients.as_slice().iter();

        // Compute the random linear combination of the MLEs of the columns of the matrices
        let mut batch_mle = Mle::from(vec![GC::EF::zero(); 1 << num_variables]);
        for mle in mles.iter() {
            let mle: &Mle<_, _> = mle.as_ref().borrow();
            let batch_size = mle.num_polynomials();
            let coeffs = batching_coefficients_iter.by_ref().take(batch_size).collect::<Vec<_>>();
            // Batch the mles as an inner product.
            batch_mle.guts_mut().as_mut_slice().iter_mut().zip_eq(mle.hypercube_iter()).for_each(
                |(batch, row)| {
                    let batch_row =
                        coeffs.iter().zip_eq(row).map(|(a, b)| **a * *b).sum::<GC::EF>();
                    *batch += batch_row;
                },
            );
        }

        let batched_eval_claim = evaluation_claims
            .iter()
            .flat_map(|batch_claims| unsafe {
                batch_claims.evaluations().storage.copy_into_host_vec()
            })
            .zip(batching_coefficients.as_slice())
            .map(|(eval, batch_power)| eval * *batch_power)
            .sum::<GC::EF>();

        let batch_mle_f = Buffer::from(batch_mle.clone().into_guts().storage.as_slice().to_vec())
            .flatten_to_base::<GC::F>();
        let batch_mle_f = Tensor::from(batch_mle_f).reshape([1 << num_variables, GC::EF::D]);
        let batch_codeword = encoder.encode_batch(Message::from(Mle::new(batch_mle_f))).unwrap();
        let batch_codeword = (*batch_codeword[0]).clone();

        (batch_mle, batch_codeword, batched_eval_claim)
    }
}

impl<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
        P: TensorCsProver<GC, CpuBackend> + Send + Sync + 'static,
    > FriCpuProver<GC, P>
{
    #[allow(clippy::type_complexity)]
    pub(crate) fn commit_phase_round(
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

    pub(crate) fn final_poly(&self, final_codeword: RsCodeWord<GC::F, CpuBackend>) -> GC::EF {
        GC::EF::from_base_slice(&final_codeword.data.storage.as_slice()[0..GC::EF::D])
    }
}
