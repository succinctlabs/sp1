#include "babybear.hpp"
#include "alu_base.hpp"
#include "alu_ext.hpp"
#include "batch_fri.hpp"

using namespace sp1_core_machine_sys;

namespace sp1_recursion_core_sys {
extern "C" void alu_base_event_to_row_babybear(const sp1_recursion_core_sys::BaseAluIo<BabyBearP3>* io, sp1_recursion_core_sys::BaseAluValueCols<BabyBearP3>* cols) {
    recursion::alu_base::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::BaseAluIo<BabyBear>*>(io),
        *reinterpret_cast<sp1_recursion_core_sys::BaseAluValueCols<BabyBear>*>(cols));
}
extern "C" void alu_ext_event_to_row_babybear(const sp1_recursion_core_sys::ExtAluIo<sp1_recursion_core_sys::Block<BabyBearP3>>* io, sp1_recursion_core_sys::ExtAluValueCols<BabyBearP3>* cols) {
    recursion::alu_ext::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::ExtAluIo<sp1_recursion_core_sys::Block<BabyBear>>*>(io),
        *reinterpret_cast<sp1_recursion_core_sys::ExtAluValueCols<BabyBear>*>(cols));
}
extern "C" void batch_fri_event_to_row_babybear(const sp1_recursion_core_sys::BatchFRIEvent<BabyBearP3>* io, sp1_recursion_core_sys::BatchFRICols<BabyBearP3>* cols) {
    recursion::batch_fri::event_to_row<BabyBear>(
        *reinterpret_cast<const sp1_recursion_core_sys::BatchFRIEvent<BabyBear>*>(io),
        *reinterpret_cast<sp1_recursion_core_sys::BatchFRICols<BabyBear>*>(cols));
}
}  // namespace sp1_recursion_core_sys
