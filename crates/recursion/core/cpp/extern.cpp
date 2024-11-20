#include "bb31_t.hpp"
#include "alu_base.hpp"

namespace recursion_generate_trace_sys {
extern void alu_base_generate_trace() {
    recursion::alu_base::event_to_row<bb31_t>();
}
}  // namespace sp1
