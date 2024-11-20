#include "babybear.hpp"
#include "babybear_septic.hpp"
#include "sys.hpp"

namespace sp1_core_machine_sys {
extern void add_sub_event_to_row_babybear(const AluEvent* event, AddSubCols<BabyBearP3>* cols) {
    add_sub::event_to_row<BabyBear>(*event, *reinterpret_cast<AddSubCols<BabyBear>*>(cols));
}

extern void mul_event_to_row_babybear(const AluEvent* event, MulCols<BabyBearP3>* cols) {
    mul::event_to_row<BabyBear>(*event, *cols);
}

extern void bitwise_event_to_row_babybear(const AluEvent* event, BitwiseCols<BabyBearP3>* cols) {
    bitwise::event_to_row<BabyBear>(*event, *cols);
}

extern void lt_event_to_row_babybear(const AluEvent* event, LtCols<BabyBearP3>* cols) {
    lt::event_to_row<BabyBear>(*event, *cols);
}

extern void sll_event_to_row_babybear(const AluEvent* event, ShiftLeftCols<BabyBearP3>* cols) {
    sll::event_to_row<BabyBear>(*event, *cols);
}

extern void sr_event_to_row_babybear(const AluEvent* event, ShiftRightCols<BabyBearP3>* cols) {
    sr::event_to_row<BabyBear>(*event, *cols);
}

extern void cpu_event_to_row_babybear(const CpuEventFfi* event, CpuCols<BabyBearP3>* cols) {
    cpu::event_to_row<BabyBear>(*event, *cols);
}

extern void memory_local_event_to_row_babybear(const MemoryLocalEvent* event, GlobalInteractionOperation<BabyBearP3>* cols_init, GlobalInteractionOperation<BabyBearP3>* cols_final) {
    memory_local::event_to_row<BabyBear, BabyBearSeptic>(*event, *cols_init, *cols_final);
}
}  // namespace sp1