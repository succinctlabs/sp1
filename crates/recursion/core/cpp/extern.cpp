#include "bb31_t.hpp"
#include "sys.hpp"

namespace sp1_recursion_core_sys {
using namespace poseidon2;

extern void alu_base_event_to_row_babybear(const BaseAluIo<BabyBearP3>* io,
                                           BaseAluValueCols<BabyBearP3>* cols) {
  alu_base::event_to_row<bb31_t>(
      *reinterpret_cast<const BaseAluIo<bb31_t>*>(io),
      *reinterpret_cast<BaseAluValueCols<bb31_t>*>(cols));
}
extern void alu_base_instr_to_row_babybear(
    const BaseAluInstr<BabyBearP3>* instr,
    BaseAluAccessCols<BabyBearP3>* access) {
  alu_base::instr_to_row<bb31_t>(
      *reinterpret_cast<const BaseAluInstr<bb31_t>*>(instr),
      *reinterpret_cast<BaseAluAccessCols<bb31_t>*>(access));
}

extern void alu_ext_event_to_row_babybear(const ExtAluIo<Block<BabyBearP3>>* io,
                                          ExtAluValueCols<BabyBearP3>* cols) {
  alu_ext::event_to_row<bb31_t>(
      *reinterpret_cast<const ExtAluIo<Block<bb31_t>>*>(io),
      *reinterpret_cast<ExtAluValueCols<bb31_t>*>(cols));
}
extern void alu_ext_instr_to_row_babybear(
    const ExtAluInstr<BabyBearP3>* instr,
    ExtAluAccessCols<BabyBearP3>* access) {
  alu_ext::instr_to_row<bb31_t>(
      *reinterpret_cast<const ExtAluInstr<bb31_t>*>(instr),
      *reinterpret_cast<ExtAluAccessCols<bb31_t>*>(access));
}

extern void batch_fri_event_to_row_babybear(const BatchFRIEvent<BabyBearP3>* io,
                                            BatchFRICols<BabyBearP3>* cols) {
  batch_fri::event_to_row<bb31_t>(
      *reinterpret_cast<const BatchFRIEvent<bb31_t>*>(io),
      *reinterpret_cast<BatchFRICols<bb31_t>*>(cols));
}
extern void batch_fri_instr_to_row_babybear(
    const BatchFRIInstrFFI<BabyBearP3>* instr,
    BatchFRIPreprocessedCols<BabyBearP3>* cols, size_t index) {
  batch_fri::instr_to_row<bb31_t>(
      *reinterpret_cast<const BatchFRIInstrFFI<bb31_t>*>(instr),
      *reinterpret_cast<BatchFRIPreprocessedCols<bb31_t>*>(cols), index);
}

extern void exp_reverse_bits_event_to_row_babybear(
    const ExpReverseBitsEventFFI<BabyBearP3>* io, size_t i,
    ExpReverseBitsLenCols<BabyBearP3>* cols) {
  exp_reverse_bits::event_to_row<bb31_t>(
      *reinterpret_cast<const ExpReverseBitsEventFFI<bb31_t>*>(io), i,
      *reinterpret_cast<ExpReverseBitsLenCols<bb31_t>*>(cols));
}
extern void exp_reverse_bits_instr_to_row_babybear(
    const ExpReverseBitsInstrFFI<BabyBearP3>* instr, size_t i, size_t len,
    ExpReverseBitsLenPreprocessedCols<BabyBearP3>* cols) {
  exp_reverse_bits::instr_to_row<bb31_t>(
      *reinterpret_cast<const ExpReverseBitsInstrFFI<bb31_t>*>(instr), i, len,
      *reinterpret_cast<ExpReverseBitsLenPreprocessedCols<bb31_t>*>(cols));
}

extern void fri_fold_event_to_row_babybear(const FriFoldEvent<BabyBearP3>* io,
                                           FriFoldCols<BabyBearP3>* cols) {
  fri_fold::event_to_row<bb31_t>(
      *reinterpret_cast<const FriFoldEvent<bb31_t>*>(io),
      *reinterpret_cast<FriFoldCols<bb31_t>*>(cols));
}
extern void fri_fold_instr_to_row_babybear(
    const FriFoldInstrFFI<BabyBearP3>* instr, size_t i,
    FriFoldPreprocessedCols<BabyBearP3>* cols) {
  fri_fold::instr_to_row<bb31_t>(
      *reinterpret_cast<const FriFoldInstrFFI<bb31_t>*>(instr), i,
      *reinterpret_cast<FriFoldPreprocessedCols<bb31_t>*>(cols));
}

extern void public_values_event_to_row_babybear(
    const CommitPublicValuesEvent<BabyBearP3>* io, size_t digest_idx,
    PublicValuesCols<BabyBearP3>* cols) {
  public_values::event_to_row<bb31_t>(
      *reinterpret_cast<const CommitPublicValuesEvent<bb31_t>*>(io), digest_idx,
      *reinterpret_cast<PublicValuesCols<bb31_t>*>(cols));
}
extern void public_values_instr_to_row_babybear(
    const CommitPublicValuesInstr<BabyBearP3>* instr, size_t digest_idx,
    PublicValuesPreprocessedCols<BabyBearP3>* cols) {
  public_values::instr_to_row<bb31_t>(
      *reinterpret_cast<const CommitPublicValuesInstr<bb31_t>*>(instr),
      digest_idx,
      *reinterpret_cast<PublicValuesPreprocessedCols<bb31_t>*>(cols));
}

extern void select_event_to_row_babybear(const SelectEvent<BabyBearP3>* io,
                                         SelectCols<BabyBearP3>* cols) {
  select::event_to_row<bb31_t>(
      *reinterpret_cast<const SelectEvent<bb31_t>*>(io),
      *reinterpret_cast<SelectCols<bb31_t>*>(cols));
}
extern void select_instr_to_row_babybear(
    const SelectInstr<BabyBearP3>* instr,
    SelectPreprocessedCols<BabyBearP3>* cols) {
  select::instr_to_row<bb31_t>(
      *reinterpret_cast<const SelectInstr<bb31_t>*>(instr),
      *reinterpret_cast<SelectPreprocessedCols<bb31_t>*>(cols));
}

extern void poseidon2_skinny_event_to_row_babybear(
    const Poseidon2Event<BabyBearP3>* event,
    Poseidon2<BabyBearP3> cols[OUTPUT_ROUND_IDX + 1]) {
  poseidon2_skinny::event_to_row<bb31_t>(
      *reinterpret_cast<const Poseidon2Event<bb31_t>*>(event),
      reinterpret_cast<Poseidon2<bb31_t>*>(cols));
}
extern void poseidon2_skinny_instr_to_row_babybear(
    const Poseidon2Instr<BabyBearP3>* instr, size_t i,
    Poseidon2PreprocessedColsSkinny<BabyBearP3>* cols) {
  poseidon2_skinny::instr_to_row<bb31_t>(
      *reinterpret_cast<const Poseidon2Instr<bb31_t>*>(instr), i,
      *reinterpret_cast<Poseidon2PreprocessedColsSkinny<bb31_t>*>(cols));
}

extern "C" void poseidon2_wide_event_to_row_babybear(const BabyBearP3* input,
                                                     BabyBearP3* input_row,
                                                     bool sbox_state) {
  poseidon2_wide::event_to_row<bb31_t>(reinterpret_cast<const bb31_t*>(input),
                                       reinterpret_cast<bb31_t*>(input_row), 0,
                                       1, sbox_state);
}
extern void poseidon2_wide_instr_to_row_babybear(
    const Poseidon2SkinnyInstr<BabyBearP3>* instr,
    Poseidon2PreprocessedColsWide<BabyBearP3>* cols) {
  poseidon2_wide::instr_to_row<bb31_t>(
      *reinterpret_cast<const Poseidon2SkinnyInstr<bb31_t>*>(instr),
      *reinterpret_cast<Poseidon2PreprocessedColsWide<bb31_t>*>(cols));
}
}  // namespace sp1_recursion_core_sys
