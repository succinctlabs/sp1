#include "babybear.hpp"
#include "alu_base.hpp"

using namespace sp1_core_machine_sys;

namespace recursion_generate_trace_sys {
extern void alu_base_generate_trace() {
    sp1_recursion_core_sys::BaseAluIo<BabyBear> io;
    sp1_recursion_core_sys::BaseAluCols<BabyBear> cols;
    recursion::alu_base::event_to_row<BabyBear>(io, cols);
}
}  // namespace recursion_generate_trace_sys
