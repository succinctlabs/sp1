use std::sync::Arc;

use slop_algebra::TwoAdicField;
use slop_basefold::{FriConfig, RsCodeWord};
use slop_commit::Message;
use slop_dft::{p3::Radix2DitParallel, Dft, DftOrdering};
use slop_futures::OwnedBorrow;
use slop_multilinear::{Mle, MleEncoder};

#[derive(Debug, Clone)]
pub struct CpuDftEncoder<F> {
    pub config: FriConfig<F>,
    pub dft: Arc<Radix2DitParallel>,
}

impl<F: TwoAdicField> CpuDftEncoder<F> {
    #[inline]
    pub fn config(&self) -> FriConfig<F> {
        self.config
    }

    /// Reed–Solomon encode a batch of MLEs at an arbitrary `log_blowup`, bypassing the encoder's
    /// configured blowup.
    ///
    /// This is the general batch-encoding primitive; [`Self::encode_batch`] is the specialization at
    /// the encoder's configured blowup.
    pub fn encode_batch_with_log_blowup<M>(
        &self,
        data: Message<M>,
        log_blowup: usize,
    ) -> Message<RsCodeWord<F>>
    where
        M: OwnedBorrow<Mle<F>>,
    {
        let dft = &self.dft;
        let mut results = Vec::with_capacity(data.len());
        for data in data.iter() {
            let data = data.borrow().guts();
            assert_eq!(data.sizes().len(), 2, "Expected a 2D tensor");
            // Perform a DFT along the first axis of the tensor (assumed to be the long dimension),
            // encoding at the next power-of-two height. For an already-power-of-two input (the usual
            // case) this is an ordinary DFT; a non-power-of-two input (e.g. a ZK-padded commitment)
            // is zero-extended inside the DFT's own work buffer, so no padded copy is allocated here.
            let padded_len = data.sizes()[0].next_power_of_two();
            let dft_result = dft
                .dft_zero_padded(data, padded_len, log_blowup, DftOrdering::BitReversed, 0)
                .unwrap();
            results.push(Arc::new(RsCodeWord { data: dft_result }));
        }
        Message::from(results)
    }

    /// Reed–Solomon encode a batch of MLEs at the encoder's configured blowup.
    pub fn encode_batch<M>(&self, data: Message<M>) -> Message<RsCodeWord<F>>
    where
        M: OwnedBorrow<Mle<F>>,
    {
        self.encode_batch_with_log_blowup(data, self.config.log_blowup())
    }
}

impl<F: TwoAdicField> MleEncoder<F> for CpuDftEncoder<F> {
    type Codeword = RsCodeWord<F>;

    fn log_blowup(&self) -> usize {
        self.config.log_blowup()
    }

    fn encode_with_log_blowup(&self, mle: Mle<F>, log_blowup: usize) -> Self::Codeword {
        // Single-MLE specialization of the batch primitive; unwrap the one codeword.
        let codewords = self.encode_batch_with_log_blowup(Message::from(mle), log_blowup);
        (*codewords[0]).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use slop_algebra::AbstractField;
    use slop_baby_bear::BabyBear;
    use slop_basefold::FriConfig;
    use slop_tensor::Tensor;

    /// Encoding a non-power-of-two-height MLE (whose rows the encoder zero-extends internally) must
    /// produce exactly the same codeword as first padding it with zero rows to the next power of two
    /// and encoding that. This is what lets the ZK commit path skip materializing a padded copy.
    #[test]
    fn encode_zero_pads_like_explicit_padding() {
        type F = BabyBear;
        let mut rng = thread_rng();
        let encoder = CpuDftEncoder::<F> {
            config: FriConfig::default_fri_config(),
            dft: Arc::new(Radix2DitParallel),
        };
        let log_blowup = 2;

        // A deliberately non-power-of-two row count (a power of two plus a few "hiding" rows), with
        // several columns to exercise the row-major layout.
        let rows: usize = (1 << 7) + 9;
        let cols: usize = 5;
        let padded_rows = rows.next_power_of_two();

        let data: Vec<F> = (0..rows * cols).map(|_| rng.gen()).collect();
        let unpadded = Mle::new(Tensor::from(data.clone()).reshape([rows, cols]));

        let mut padded_data = data;
        padded_data.resize(padded_rows * cols, F::zero());
        let padded = Mle::new(Tensor::from(padded_data).reshape([padded_rows, cols]));

        let from_internal =
            encoder.encode_batch_with_log_blowup(Message::from(unpadded), log_blowup);
        let from_explicit = encoder.encode_batch_with_log_blowup(Message::from(padded), log_blowup);

        assert_eq!(from_internal[0].data.sizes(), from_explicit[0].data.sizes());
        assert_eq!(from_internal[0].data.as_slice(), from_explicit[0].data.as_slice());
    }
}
