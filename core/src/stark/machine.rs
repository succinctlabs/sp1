use super::Com;
use super::StarkConfig;

pub struct StarkData<SC: StarkConfig> {
    config: SC,
    preprocessed_commitment: Option<Com<SC>>,
}
