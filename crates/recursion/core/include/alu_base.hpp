#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::alu_base {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::BaseAluIo<F> &io, sp1_recursion_core_sys::BaseAluCols<F> &cols) {
  cols.values[0].vals = io;
  
  for (size_t i = 1; i < sp1_recursion_core_sys::NUM_BASE_ALU_ENTRIES_PER_ROW; i++) {
    cols.values[i].vals.out = F();
    cols.values[i].vals.in1 = F();
    cols.values[i].vals.in2 = F(); 
  }
}
} // namespace recursion::alu_base
