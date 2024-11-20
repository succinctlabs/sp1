use crate::{
    air::Block,
    chips::{
        alu_base::{BaseAluAccessCols, BaseAluValueCols},
        alu_ext::{ExtAluAccessCols, ExtAluValueCols},
        batch_fri::{BatchFRICols, BatchFRIPreprocessedCols},
        exp_reverse_bits::{ExpReverseBitsLenCols, ExpReverseBitsLenPreprocessedCols},
        fri_fold::{FriFoldCols, FriFoldPreprocessedCols},
        public_values::{PublicValuesCols, PublicValuesPreprocessedCols},
        select::{SelectCols, SelectPreprocessedCols},
    },
    BaseAluInstr, BaseAluIo, BatchFRIEvent, BatchFRIInstrC, CommitPublicValuesEvent,
    CommitPublicValuesInstr, ExpReverseBitsEventC, ExpReverseBitsInstrC, ExtAluInstr, ExtAluIo,
    FriFoldEvent, FriFoldInstrC, SelectEvent, SelectInstr,
};
use p3_baby_bear::BabyBear;

#[link(name = "sp1_recursion_core_sys", kind = "static")]
extern "C-unwind" {
    pub fn alu_base_event_to_row_babybear(
        io: &BaseAluIo<BabyBear>,
        cols: &mut BaseAluValueCols<BabyBear>,
    );
    pub fn alu_base_instr_to_row_babybear(
        instr: &BaseAluInstr<BabyBear>,
        cols: &mut BaseAluAccessCols<BabyBear>,
    );

    pub fn alu_ext_event_to_row_babybear(
        io: &ExtAluIo<Block<BabyBear>>,
        cols: &mut ExtAluValueCols<BabyBear>,
    );
    pub fn alu_ext_instr_to_row_babybear(
        instr: &ExtAluInstr<BabyBear>,
        cols: &mut ExtAluAccessCols<BabyBear>,
    );

    pub fn batch_fri_event_to_row_babybear(
        io: &BatchFRIEvent<BabyBear>,
        cols: &mut BatchFRICols<BabyBear>,
    );
    pub fn batch_fri_instr_to_row_babybear(
        instr: &BatchFRIInstrC<BabyBear>,
        cols: &mut BatchFRIPreprocessedCols<BabyBear>,
    );

    pub fn exp_reverse_bits_event_to_row_babybear(
        io: &ExpReverseBitsEventC<BabyBear>,
        i: usize,
        cols: &mut ExpReverseBitsLenCols<BabyBear>,
    );
    pub fn exp_reverse_bits_instr_to_row_babybear(
        instr: &ExpReverseBitsInstrC<BabyBear>,
        i: usize,
        len: usize,
        cols: &mut ExpReverseBitsLenPreprocessedCols<BabyBear>,
    );

    pub fn fri_fold_event_to_row_babybear(
        io: &FriFoldEvent<BabyBear>,
        cols: &mut FriFoldCols<BabyBear>,
    );
    pub fn fri_fold_instr_to_row_babybear(
        instr: &FriFoldInstrC<BabyBear>,
        i: usize,
        cols: &mut FriFoldPreprocessedCols<BabyBear>,
    );

    pub fn public_values_event_to_row_babybear(
        io: &CommitPublicValuesEvent<BabyBear>,
        digest_idx: usize,
        cols: &mut PublicValuesCols<BabyBear>,
    );
    pub fn public_values_instr_to_row_babybear(
        instr: &CommitPublicValuesInstr<BabyBear>,
        digest_idx: usize,
        cols: &mut PublicValuesPreprocessedCols<BabyBear>,
    );

    pub fn select_event_to_row_babybear(
        io: &SelectEvent<BabyBear>,
        cols: &mut SelectCols<BabyBear>,
    );
    pub fn select_instr_to_row_babybear(
        instr: &SelectInstr<BabyBear>,
        cols: &mut SelectPreprocessedCols<BabyBear>,
    );
}
