#include "bb31_t.hpp"
#include "sys.hpp"

namespace sp1_core_machine_sys {
extern void add_sub_event_to_row_babybear(
    const AluEvent* event,
    AddSubCols<BabyBearP3>* cols
) {
    AddSubCols<bb31_t>* cols_bb31 = reinterpret_cast<AddSubCols<bb31_t>*>(cols);
    add_sub::event_to_row<bb31_t>(*event, *cols_bb31);
}
}  // namespace sp1_core_machine_sys