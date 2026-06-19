//! fibonacci — read a u32 `n`, compute `fib(n) % 7919`, write the result.
//!
//! Demonstrates that "normal" Rust arithmetic runs cleanly through the
//! libzkevm C ABI:
//!   * 4 bytes in via `read_input`
//!   * 4 bytes out via `write_output`
//!   * Successful termination: `main` returns 0, `__start` halts with 0

#![no_main]

zkevm::entrypoint!(main);

pub fn main() {
    let mut buf_ptr: *const u8 = core::ptr::null();
    let mut buf_size: usize = 0;
    unsafe {
        zkevm::io::read_input(&mut buf_ptr, &mut buf_size);
    }

    // Decode 4 LE bytes -> u32. Default to 0 if the host pushed less.
    let n = if buf_size >= 4 && !buf_ptr.is_null() {
        let bytes = unsafe { core::slice::from_raw_parts(buf_ptr, 4) };
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        0
    };

    // Modulus chosen to match SP1's stock `examples/fibonacci/program/`
    // so cycle counts are roughly comparable.
    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        let c = (a + b) % 7919;
        a = b;
        b = c;
    }

    let result = a.to_le_bytes();
    unsafe {
        zkevm::io::write_output(result.as_ptr(), result.len());
    }
}
