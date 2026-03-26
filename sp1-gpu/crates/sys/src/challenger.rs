use crate::runtime::KernelPtr;

extern "C" {
    pub fn grind_koala_bear() -> KernelPtr;
    pub fn grind_multi_field32() -> KernelPtr;
}
