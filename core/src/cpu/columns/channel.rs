use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;
use sp1_derive::AlignedBorrow;

use crate::{bytes::NUM_BYTE_LOOKUP_CHANNELS, stark::SP1AirBuilder};

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ChannelSelectorCols<T> {
    pub channel_selectors: [T; NUM_BYTE_LOOKUP_CHANNELS as usize],
}

impl<F: Field> ChannelSelectorCols<F> {
    #[inline(always)]
    pub fn populate(&mut self, channel: u8) {
        self.channel_selectors = [F::zero(); NUM_BYTE_LOOKUP_CHANNELS as usize];
        self.channel_selectors[channel as usize] = F::one();
    }
}

pub fn eval_channel_selectors<AB: SP1AirBuilder>(
    builder: &mut AB,
    local: &ChannelSelectorCols<AB::Var>,
    next: &ChannelSelectorCols<AB::Var>,
    channel: impl Into<AB::Expr> + Clone,
    local_is_real: impl Into<AB::Expr> + Clone,
    next_is_real: impl Into<AB::Expr> + Clone,
) {
    // Constrain:
    // - the value of the channel is given by the channel selectors.
    // - all selectors are boolean and disjoint.
    let mut sum = AB::Expr::zero();
    let mut reconstruct_channel = AB::Expr::zero();
    for (i, selector) in local.channel_selectors.into_iter().enumerate() {
        // Constrain that the selector is boolean.
        builder.assert_bool(selector);
        // Accumulate the sum of the selectors.
        sum += selector.into();
        // Accumulate the reconstructed channel.
        reconstruct_channel += selector.into() * AB::Expr::from_canonical_u32(i as u32);
    }
    // Assert that the reconstructed channel is the same as the channel.
    builder.assert_eq(reconstruct_channel, channel.clone());
    // For disjointness, assert the sum of the selectors is 1.
    builder
        .when(local_is_real.clone())
        .assert_eq(sum, AB::Expr::one());

    // Constrain the first row by asserting that the first selector on the first line is true.
    builder
        .when_first_row()
        .assert_one(local.channel_selectors[0]);

    // Constrain the transition by asserting that the selectors satisfy the recursion relation:
    // selectors_next[(i + 1) % NUM_BYTE_LOOKUP_CHANNELS] = selectors[i]
    for i in 0..NUM_BYTE_LOOKUP_CHANNELS as usize {
        builder
            .when_transition()
            .when(next_is_real.clone())
            .assert_eq(
                local.channel_selectors[i],
                next.channel_selectors[(i + 1) % NUM_BYTE_LOOKUP_CHANNELS as usize],
            );
    }
}
