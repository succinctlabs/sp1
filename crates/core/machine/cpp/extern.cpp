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
    memory_local::event_to_row<bb31_t, bb31_septic_extension_t>(event, cols_bb31);
}

extern void memory_global_event_to_row_babybear(const MemoryInitializeFinalizeEvent* event, const bool is_receive, MemoryInitCols<BabyBearP3>* cols) {
    MemoryInitCols<bb31_t>* cols_bb31 = reinterpret_cast<MemoryInitCols<bb31_t>*>(cols);
    memory_global::event_to_row<bb31_t, bb31_septic_extension_t>(event, is_receive, cols_bb31);
}

extern void syscall_event_to_row_babybear(const SyscallEvent* event, const bool is_receive, SyscallCols<BabyBearP3>* cols) {
    SyscallCols<bb31_t>* cols_bb31 = reinterpret_cast<SyscallCols<bb31_t>*>(cols);
    syscall::event_to_row<bb31_t, bb31_septic_extension_t>(event, is_receive, cols_bb31);
}
} // namespace sp1_core_machine_sys
