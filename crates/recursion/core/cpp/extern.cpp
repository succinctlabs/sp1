#pragma once

#include "babybear.hpp"
#include "alu_base.hpp"

using namespace sp1_core_machine_sys;

namespace recursion_generate_trace_sys {
extern void alu_base_generate_trace() {
    recursion::alu_base::event_to_row<BabyBear>();
}
}  // namespace sp1
