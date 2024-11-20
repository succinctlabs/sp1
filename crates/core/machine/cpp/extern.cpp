#include "bb31_t.hpp"
#include "bb31_septic_extension_t.hpp"
#include "sys.hpp"

namespace sp1_core_machine_sys {
extern void add_sub_event_to_row_babybear(
    const AluEvent* event,
    AddSubCols<BabyBearP3>* cols
) {
    AddSubCols<bb31_t>* cols_bb31 = reinterpret_cast<AddSubCols<bb31_t>*>(cols);
    add_sub::event_to_row<bb31_t>(*event, *cols_bb31);
}

extern void memory_local_event_to_row_babybear(const MemoryLocalEvent* event, SingleMemoryLocal<BabyBearP3>* cols) {
    SingleMemoryLocal<bb31_t>* cols_bb31 = reinterpret_cast<SingleMemoryLocal<bb31_t>*>(cols);
    memory_local::event_to_row<bb31_t, bb31_septic_extension_t>(*event, *cols_bb31);
}
} // namespace sp1_core_machine_sys
