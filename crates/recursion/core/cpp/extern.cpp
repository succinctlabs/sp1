#include "babybear.hpp"
#include "alu_base.hpp"
#include "alu_ext.hpp"
#include "batch_fri.hpp"
#include "exp_reverse_bits.hpp"
#include "fri_fold.hpp"
#include "select.hpp"
#include "public_values.hpp"

using namespace sp1_core_machine_sys;

namespace sp1_recursion_core_sys {
extern void alu_base_event_to_row_babybear(const sp1_recursion_core_sys::BaseAluIo<BabyBearP3>* io, sp1_recursion_core_sys::BaseAluValueCols<BabyBearP3>* cols) {
    recursion::alu_base::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::BaseAluIo<BabyBear>*>(io),
        *reinterpret_cast<sp1_recursion_core_sys::BaseAluValueCols<BabyBear>*>(cols));
}

extern void alu_ext_event_to_row_babybear(const sp1_recursion_core_sys::ExtAluIo<sp1_recursion_core_sys::Block<BabyBearP3>>* io, sp1_recursion_core_sys::ExtAluValueCols<BabyBearP3>* cols) {
    recursion::alu_ext::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::ExtAluIo<sp1_recursion_core_sys::Block<BabyBear>>*>(io),
        *reinterpret_cast<sp1_recursion_core_sys::ExtAluValueCols<BabyBear>*>(cols));
}

extern void batch_fri_event_to_row_babybear(const sp1_recursion_core_sys::BatchFRIEvent<BabyBearP3>* io, sp1_recursion_core_sys::BatchFRICols<BabyBearP3>* cols) {
    recursion::batch_fri::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::BatchFRIEvent<BabyBear>*>(io),
        *reinterpret_cast<sp1_recursion_core_sys::BatchFRICols<BabyBear>*>(cols));
}

extern void exp_reverse_bits_event_to_row_babybear(
    const sp1_recursion_core_sys::ExpReverseBitsEventC<BabyBearP3>* io,
    size_t i,
    sp1_recursion_core_sys::ExpReverseBitsLenCols<BabyBearP3>* cols) {
    recursion::exp_reverse_bits::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::ExpReverseBitsEventC<BabyBear>*>(io),
        i,
        *reinterpret_cast<sp1_recursion_core_sys::ExpReverseBitsLenCols<BabyBear>*>(cols));
}

extern void fri_fold_event_to_row_babybear(const sp1_recursion_core_sys::FriFoldEvent<BabyBearP3>* io, sp1_recursion_core_sys::FriFoldCols<BabyBearP3>* cols) {
    recursion::fri_fold::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::FriFoldEvent<BabyBear>*>(io),
        *reinterpret_cast<sp1_recursion_core_sys::FriFoldCols<BabyBear>*>(cols));
}

extern void public_values_event_to_row_babybear(const sp1_recursion_core_sys::CommitPublicValuesEvent<BabyBearP3>* io, size_t digest_idx, sp1_recursion_core_sys::PublicValuesCols<BabyBearP3>* cols) {
    recursion::public_values::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::CommitPublicValuesEvent<BabyBear>*>(io),
        digest_idx,
        *reinterpret_cast<sp1_recursion_core_sys::PublicValuesCols<BabyBear>*>(cols));
}

extern void select_event_to_row_babybear(const sp1_recursion_core_sys::SelectEvent<BabyBearP3>* io, sp1_recursion_core_sys::SelectCols<BabyBearP3>* cols) {
    recursion::select::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::SelectEvent<BabyBear>*>(io),
        *reinterpret_cast<sp1_recursion_core_sys::SelectCols<BabyBear>*>(cols));
}
}  // namespace sp1_recursion_core_sys
