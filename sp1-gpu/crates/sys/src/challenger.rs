use crate::runtime::KernelPtr;

extern "C" {
    pub fn grind_koala_bear() -> KernelPtr;
}
