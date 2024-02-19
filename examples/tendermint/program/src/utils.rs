use tendermint::block::CommitSig;

use crate::BlockValidatorSet;

pub fn filter_top_signatures_by_power(
    signatures: Vec<CommitSig>,
    validators: &BlockValidatorSet,
) -> Vec<CommitSig> {
    let mut signatures_by_desc_power = signatures.clone();
    signatures_by_desc_power.sort_by(|a, b| {
        let validator_a = validators
            .validators
            .iter()
            .find(|v| v.address == a.validator_address().unwrap())
            .unwrap();

        let validator_b = validators
            .validators
            .iter()
            .find(|v| v.address == b.validator_address().unwrap())
            .unwrap();

        validator_b.power().cmp(&validator_a.power())
    });
    signatures_by_desc_power
}
