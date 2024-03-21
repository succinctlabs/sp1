use sp1_core::stark::{AirOpenedValues, ChipOpenedValues};

use crate::prelude::{Builder, Config, Ext, ExtConst, Usize};

#[derive(Debug, Clone)]
pub struct ChipOpening<C: Config> {
    pub preprocessed: AirOpenedValues<Ext<C::F, C::EF>>,
    pub main: AirOpenedValues<Ext<C::F, C::EF>>,
    pub permutation: AirOpenedValues<Ext<C::F, C::EF>>,
    pub quotient: Vec<Vec<Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_degree: Usize<C::N>,
}

impl<C: Config> Builder<C> {
    pub fn const_chip_opening(&mut self, opening: &ChipOpenedValues<C::EF>) -> ChipOpening<C> {
        ChipOpening {
            preprocessed: self.const_opened_values(&opening.preprocessed),
            main: self.const_opened_values(&opening.main),
            permutation: self.const_opened_values(&opening.permutation),
            quotient: opening
                .quotient
                .iter()
                .map(|q| q.iter().map(|s| self.eval(s.cons())).collect())
                .collect(),
            cumulative_sum: self.eval(opening.cumulative_sum.cons()),
            log_degree: self.eval(opening.log_degree),
        }
    }
}
