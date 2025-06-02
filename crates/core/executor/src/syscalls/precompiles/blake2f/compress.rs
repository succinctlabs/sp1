use crate::syscalls::{Syscall, SyscallCode, SyscallContext};

pub(crate) struct Blake2fCompressSyscall;

impl Syscall for Blake2fCompressSyscall {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let base_ptr = arg1;

        // Read from memory
        // Layout defined in blake2f here: https://www.evm.codes/precompiled

        // Read the input length

        None
    }
}
