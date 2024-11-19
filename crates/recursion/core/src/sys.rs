use crate::air::Block;
use crate::chips::alu_base::BaseAluValueCols;
use crate::chips::alu_ext::ExtAluValueCols;
use crate::chips::batch_fri::BatchFRICols;
use crate::chips::exp_reverse_bits::ExpReverseBitsLenCols;
use crate::chips::fri_fold::FriFoldCols;
use crate::chips::public_values::PublicValuesCols;
use crate::chips::select::SelectCols;
use crate::BaseAluIo;
use crate::BatchFRIEvent;
use crate::CommitPublicValuesEvent;
use crate::ExpReverseBitsEventC;
use crate::ExtAluIo;
use crate::FriFoldEvent;
use crate::SelectEvent;
use p3_baby_bear::BabyBear;

#[link(name = "sp1_recursion_core_sys", kind = "static")]
extern "C-unwind" {
    pub fn alu_base_event_to_row_babybear(
        io: &BaseAluIo<BabyBear>,
        cols: &mut BaseAluValueCols<BabyBear>,
    );
    pub fn alu_ext_event_to_row_babybear(
        io: &ExtAluIo<Block<BabyBear>>,
        cols: &mut ExtAluValueCols<BabyBear>,
    );
    pub fn batch_fri_event_to_row_babybear(
        io: &BatchFRIEvent<BabyBear>,
        cols: &mut BatchFRICols<BabyBear>,
    );
    pub fn exp_reverse_bits_event_to_row_babybear(
        io: &ExpReverseBitsEventC<BabyBear>,
        i: usize,
        cols: &mut ExpReverseBitsLenCols<BabyBear>,
    );
    pub fn fri_fold_event_to_row_babybear(
        io: &FriFoldEvent<BabyBear>,
        cols: &mut FriFoldCols<BabyBear>,
    );
    pub fn public_values_event_to_row_babybear(
        io: &CommitPublicValuesEvent<BabyBear>,
        digest_idx: usize,
        cols: &mut PublicValuesCols<BabyBear>,
    );
    pub fn select_event_to_row_babybear(
        io: &SelectEvent<BabyBear>,
        cols: &mut SelectCols<BabyBear>,
    );
}
