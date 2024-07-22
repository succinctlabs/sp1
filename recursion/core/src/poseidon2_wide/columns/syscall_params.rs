use std::mem::size_of;

use sp1_derive::AlignedBorrow;

const SYSCALL_PARAMS_SIZE: usize = size_of::<SyscallParams<u8>>();

/// Syscall params columns.  They are different for each opcode.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union SyscallParams<T: Copy> {
    compress: CompressParams<T>,
    absorb: AbsorbParams<T>,
    finalize: FinalizeParams<T>,
}

impl<T: Copy> SyscallParams<T> {
    pub fn compress(&self) -> &CompressParams<T> {
        assert!(size_of::<CompressParams<u8>>() == SYSCALL_PARAMS_SIZE);
        unsafe { &self.compress }
    }

    pub fn compress_mut(&mut self) -> &mut CompressParams<T> {
        unsafe { &mut self.compress }
    }

    pub fn absorb(&self) -> &AbsorbParams<T> {
        assert!(size_of::<CompressParams<u8>>() == SYSCALL_PARAMS_SIZE);
        unsafe { &self.absorb }
    }

    pub fn absorb_mut(&mut self) -> &mut AbsorbParams<T> {
        unsafe { &mut self.absorb }
    }

    pub fn finalize(&self) -> &FinalizeParams<T> {
        assert!(size_of::<CompressParams<u8>>() == SYSCALL_PARAMS_SIZE);
        unsafe { &self.finalize }
    }

    pub fn finalize_mut(&mut self) -> &mut FinalizeParams<T> {
        unsafe { &mut self.finalize }
    }

    pub fn get_raw_params(&self) -> [T; SYSCALL_PARAMS_SIZE] {
        // All of the union's fields should have the same size, so just choose one of them to return
        // the elements.
        let compress = self.compress();
        [compress.clk, compress.dst_ptr, compress.left_ptr, compress.right_ptr]
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct CompressParams<T> {
    pub clk: T,
    pub dst_ptr: T,
    pub left_ptr: T,
    pub right_ptr: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct AbsorbParams<T> {
    pub clk: T,
    pub hash_and_absorb_num: T,
    pub input_ptr: T,
    pub input_len: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct FinalizeParams<T> {
    pub clk: T,
    pub hash_num: T,
    pub output_ptr: T,
    pub pad: T,
}
