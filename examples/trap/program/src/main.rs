#![no_main]
sp1_zkvm::entrypoint!(main);

use rand::prelude::*;
use sp1_primitives::consts::{
    PAGE_SIZE, PROT_EXEC, PROT_FAILURE_EXEC, PROT_FAILURE_READ, PROT_FAILURE_WRITE, PROT_NONE,
    PROT_READ, PROT_WRITE,
};
use sp1_zkvm::{lib::mprotect::mprotect, syscalls};

// When the design of trap is complete, we would move TrapContext,
// __SUCCINCT_TRAP_CONTEXT and install_trap_handler to sp1-zkvm crate.
#[repr(C)]
pub struct TrapContext {
    handler: u64,
    code: u64,
    pc: u64,
}

#[no_mangle]
#[used]
pub static mut __SUCCINCT_TRAP_CONTEXT: TrapContext = TrapContext { handler: 1, code: 0, pc: 1 };

pub fn install_trap_handler(h: extern "C" fn()) {
    unsafe {
        __SUCCINCT_TRAP_CONTEXT.handler = h as *mut u8 as u64;
    }
}

pub static mut TRAP_COUNTER: u64 = 0;

// This is the actual trap function. It will merely return(returning
// from the function that traps, not the trap handler) with the trap code.
#[unsafe(naked)]
pub extern "C" fn sp1_trap_trap_trap() {
    // Note this is actually a trap handler, not a normal function.
    // SP1 would *jump* to the start of this function instead of calling
    // this function. All the registers will be exactly the same value
    // as they are when the trap happens. This means if we do `ret`, we
    // will effectively be returning from the function causing the trap.
    core::arch::naked_asm!(
        "la a1, {counter}",
        "ld a0, 0(a1)",
        "addi a0, a0, 1",
        "sd a0, 0(a1)",
        "la a0, {context}",
        "ld a0, 8(a0)",
        "ret",
        context = sym __SUCCINCT_TRAP_CONTEXT,
        counter = sym TRAP_COUNTER,
    )
}

// Type aliases for extern "C" function pointers
type OnePageFn = extern "C" fn(*mut u8);
type TwoPageFn = extern "C" fn(*mut u8, *mut u8);
type FourPageFn = extern "C" fn(*mut u8, *mut u8, *mut u8, *mut u8);
type FivePageFn = extern "C" fn(*mut u8, *mut u8, *mut u8, *mut u8, *mut u8);

/// Test a single-page syscall with given data and permissions.
/// Data is copied while page is writable, then permissions are restricted.
fn test_one_page(page: *mut u8, data: &[u8], perms: u8, run_fn: OnePageFn) {
    mprotect(page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), page, data.len()) };
    mprotect(page, PAGE_SIZE, perms);
    run_fn(page);
}

fn test_one_page_split(
    page1: *mut u8,
    page2: *mut u8,
    data: &[u8],
    perms1: u8,
    perms2: u8,
    run_fn: OnePageFn,
) {
    mprotect(page1, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(page2, PAGE_SIZE, PROT_READ | PROT_WRITE);
    let addr = ((page1 as u64) + (PAGE_SIZE as u64 - 16 * 8)) as *mut u8;
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), addr, data.len()) };
    mprotect(page1, PAGE_SIZE, perms1);
    mprotect(page2, PAGE_SIZE, perms2);
    run_fn(addr);
}

/// Test a two-page syscall with given data and permissions.
fn test_two_pages(
    page1: *mut u8,
    page2: *mut u8,
    data1: &[u8],
    data2: &[u8],
    perms1: u8,
    perms2: u8,
    run_fn: TwoPageFn,
) {
    mprotect(page1, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(page2, PAGE_SIZE, PROT_READ | PROT_WRITE);
    unsafe { std::ptr::copy_nonoverlapping(data1.as_ptr(), page1, data1.len()) };
    unsafe { std::ptr::copy_nonoverlapping(data2.as_ptr(), page2, data2.len()) };
    mprotect(page1, PAGE_SIZE, perms1);
    mprotect(page2, PAGE_SIZE, perms2);
    run_fn(page1, page2);
}

fn test_two_pages_split(
    page1: *mut u8,
    page2: *mut u8,
    page3: *mut u8,
    page4: *mut u8,
    data1: &[u8],
    data2: &[u8],
    perms: [u8; 4],
    run_fn: TwoPageFn,
) {
    mprotect(page1, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(page2, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(page3, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(page4, PAGE_SIZE, PROT_READ | PROT_WRITE);
    let addr1 = ((page1 as u64) + (PAGE_SIZE as u64 - 16 * 8)) as *mut u8;
    let addr2 = ((page3 as u64) + (PAGE_SIZE as u64 - 16 * 8)) as *mut u8;
    unsafe { std::ptr::copy_nonoverlapping(data1.as_ptr(), addr1, data1.len()) };
    unsafe { std::ptr::copy_nonoverlapping(data2.as_ptr(), addr2, data2.len()) };
    mprotect(page1, PAGE_SIZE, perms[0]);
    mprotect(page2, PAGE_SIZE, perms[1]);
    mprotect(page3, PAGE_SIZE, perms[2]);
    mprotect(page4, PAGE_SIZE, perms[3]);
    run_fn(addr1, addr2);
}

/// Test a four-page syscall with given data and permissions.
fn test_four_pages(pages: [*mut u8; 4], data: [&[u8]; 4], perms: [u8; 4], run_fn: FourPageFn) {
    for i in 0..4 {
        mprotect(pages[i], PAGE_SIZE, PROT_READ | PROT_WRITE);
        unsafe { std::ptr::copy_nonoverlapping(data[i].as_ptr(), pages[i], data[i].len()) };
    }
    for i in 0..4 {
        mprotect(pages[i], PAGE_SIZE, perms[i]);
    }
    run_fn(pages[0], pages[1], pages[2], pages[3]);
}

/// Test a five-page syscall with given data and permissions.
fn test_five_pages(pages: [*mut u8; 5], data: [&[u8]; 5], perms: [u8; 5], run_fn: FivePageFn) {
    for i in 0..5 {
        mprotect(pages[i], PAGE_SIZE, PROT_READ | PROT_WRITE);
        unsafe { std::ptr::copy_nonoverlapping(data[i].as_ptr(), pages[i], data[i].len()) };
    }
    for i in 0..5 {
        mprotect(pages[i], PAGE_SIZE, perms[i]);
    }
    run_fn(pages[0], pages[1], pages[2], pages[3], pages[4]);
}

mod test_inputs {
    pub const DEFAULT_64: [u8; 64] = [0u8; 64];
    pub const ONE_64: [u8; 64] = [1u8; 64];
    pub const DEFAULT_96: [u8; 96] = [0u8; 96];
    pub const ONE_96: [u8; 96] = [1u8; 96];
    pub const DEFAULT_128: [u8; 128] = [0u8; 128];
    pub const DEFAULT_200: [u8; 200] = [0u8; 200];
    pub const DEFAULT_256: [u8; 256] = [0u8; 256];
    pub const DEFAULT_512: [u8; 512] = [0u8; 512];

    pub const VALID_SECP256K1_POINT1: [u8; 64] = [
        152, 23, 248, 22, 91, 129, 242, 89, 217, 40, 206, 45, 219, 252, 155, 2, 7, 11, 135, 206,
        149, 98, 160, 85, 172, 187, 220, 249, 126, 102, 190, 121, 184, 212, 16, 251, 143, 208, 71,
        156, 25, 84, 133, 166, 72, 180, 23, 253, 168, 8, 17, 14, 252, 251, 164, 93, 101, 196, 163,
        38, 119, 218, 58, 72,
    ];
    pub const VALID_SECP256K1_POINT2: [u8; 64] = [
        229, 158, 112, 92, 185, 9, 172, 171, 167, 60, 239, 140, 75, 142, 119, 92, 216, 124, 192,
        149, 110, 64, 69, 48, 109, 125, 237, 65, 148, 127, 4, 198, 42, 229, 207, 80, 169, 49, 100,
        35, 225, 208, 102, 50, 101, 50, 246, 247, 238, 234, 108, 70, 25, 132, 197, 163, 57, 195,
        61, 166, 254, 104, 225, 26,
    ];

    pub const VALID_ED25519_Y: [u8; 32] = [1u8; 32];
}

pub fn main() {
    println!("Starting simple trap example");

    // If you comment this line out, trap will not take effect. SP1 will
    // simply terminate in case of permission violation.
    install_trap_handler(sp1_trap_trap_trap);

    // Heap allocated memory might not be page aligned, we are allocating
    // 6 pages(precompiles might need more), and find 5 aligned pages inside.
    let mut memory = vec![0u8; 6 * PAGE_SIZE];
    let mut rng = StdRng::seed_from_u64(123456);
    rng.fill(&mut memory[..]);

    // Get a pointer to the memory rounded up to the nearest page boundary
    let memory_ptr = memory.as_ptr() as *const u8;
    let aligned_ptr = (memory_ptr as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let aligned_ptr = aligned_ptr as *mut u8;

    println!("Memory aligned pointer: {:p}", aligned_ptr);
    mprotect(aligned_ptr, PAGE_SIZE, PROT_NONE);
    assert_eq!(violating_read(aligned_ptr, rand::random()), PROT_FAILURE_READ);
    mprotect(aligned_ptr, PAGE_SIZE, PROT_READ | PROT_EXEC);
    assert_eq!(violating_write(aligned_ptr, rand::random()), PROT_FAILURE_WRITE);
    mprotect(aligned_ptr, PAGE_SIZE, PROT_READ | PROT_WRITE);
    assert_eq!(violating_execute(aligned_ptr), PROT_FAILURE_EXEC);
    mprotect(aligned_ptr, PAGE_SIZE, PROT_NONE);
    assert_eq!(violating_execute(aligned_ptr), PROT_FAILURE_EXEC);

    let p1 = aligned_ptr;
    let p2 = (aligned_ptr as usize + PAGE_SIZE) as *mut u8;
    let p3 = (aligned_ptr as usize + PAGE_SIZE * 2) as *mut u8;
    let p4 = (aligned_ptr as usize + PAGE_SIZE * 3) as *mut u8;
    let p5 = (aligned_ptr as usize + PAGE_SIZE * 4) as *mut u8;

    // Base permission options
    const PERMS: [u8; 4] = [PROT_NONE, PROT_READ, PROT_READ | PROT_EXEC, PROT_READ | PROT_WRITE];

    // Generate all permission combinations for N pages
    fn all_two_page_perms() -> Vec<(u8, u8)> {
        let mut result = Vec::new();
        for &p1 in &PERMS {
            for &p2 in &PERMS {
                result.push((p1, p2));
            }
        }
        result
    }

    fn all_four_page_perms() -> Vec<[u8; 4]> {
        let mut result = Vec::new();
        for &p1 in &PERMS {
            for &p2 in &PERMS {
                for &p3 in &PERMS {
                    for &p4 in &PERMS {
                        result.push([p1, p2, p3, p4]);
                    }
                }
            }
        }
        result
    }

    fn all_five_page_perms() -> Vec<[u8; 5]> {
        let mut result = Vec::new();
        for &p1 in &PERMS {
            for &p2 in &PERMS {
                for &p3 in &PERMS {
                    for &p4 in &PERMS {
                        for &p5 in &PERMS {
                            result.push([p1, p2, p3, p4, p5]);
                        }
                    }
                }
            }
        }
        result
    }

    let one_page_perms = PERMS;
    let two_page_perms = all_two_page_perms();
    let four_page_perms = all_four_page_perms();
    let five_page_perms = all_five_page_perms();

    use test_inputs::*;

    // SHA256 Extend: input needs to be valid u32s
    for perms in one_page_perms {
        test_one_page(p1, &DEFAULT_512, perms, run_sha256_extend);
    }
    for &(perm1, perm2) in &two_page_perms {
        test_one_page_split(p1, p2, &DEFAULT_512, perm1, perm2, run_sha256_extend);
    }

    // SHA256 Compress: input needs to be valid u32s
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_512, &DEFAULT_64, perm1, perm2, run_sha256_compress);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_512, &DEFAULT_64, perms, run_sha256_compress);
    }

    // Keccak Permute
    for perms in one_page_perms {
        test_one_page(p1, &DEFAULT_200, perms, run_keccak_permute);
    }
    for &(perm1, perm2) in &two_page_perms {
        test_one_page_split(p1, p2, &DEFAULT_200, perm1, perm2, run_keccak_permute);
    }

    // Poseidon2: needs valid koalabear input
    for perms in one_page_perms {
        test_one_page(p1, &DEFAULT_64, perms, run_poseidon2);
    }
    for &(perm1, perm2) in &two_page_perms {
        test_one_page_split(p1, p2, &DEFAULT_64, perm1, perm2, run_poseidon2);
    }

    // Secp256k: input needs to be valid secp256k1 points
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(
            p1,
            p2,
            &VALID_SECP256K1_POINT1,
            &VALID_SECP256K1_POINT2,
            perm1,
            perm2,
            run_secp256k1_add,
        );
    }
    for &perms in &four_page_perms {
        test_two_pages_split(
            p1,
            p2,
            p3,
            p4,
            &VALID_SECP256K1_POINT1,
            &VALID_SECP256K1_POINT2,
            perms,
            run_secp256k1_add,
        );
    }

    for perms in one_page_perms {
        test_one_page(p1, &VALID_SECP256K1_POINT1, perms, run_secp256k1_double);
    }
    for &(perm1, perm2) in &two_page_perms {
        test_one_page_split(p1, p2, &VALID_SECP256K1_POINT1, perm1, perm2, run_secp256k1_double);
    }

    // Secp256r1 Add
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_64, &ONE_64, perm1, perm2, run_secp256r1_add);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &ONE_64, perms, run_secp256r1_add);
    }

    // Secp256r1 Double
    for perms in one_page_perms {
        test_one_page(p1, &ONE_64, perms, run_secp256r1_double);
    }
    for &(perm1, perm2) in &two_page_perms {
        test_one_page_split(p1, p2, &ONE_64, perm1, perm2, run_secp256r1_double);
    }

    // BLS12-381 Add
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_96, &ONE_96, perm1, perm2, run_bls12381_add);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_96, &ONE_96, perms, run_bls12381_add);
    }

    // BLS12-381 Double
    for perms in one_page_perms {
        test_one_page(p1, &ONE_96, perms, run_bls12381_double);
    }
    for &(perm1, perm2) in &two_page_perms {
        test_one_page_split(p1, p2, &ONE_96, perm1, perm2, run_bls12381_double);
    }

    // BN254 Add
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_64, &ONE_64, perm1, perm2, run_bn254_add);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &ONE_64, perms, run_bn254_add);
    }

    // BN254 Double
    for perms in one_page_perms {
        test_one_page(p1, &ONE_64, perms, run_bn254_double);
    }
    for &(perm1, perm2) in &two_page_perms {
        test_one_page_split(p1, p2, &ONE_64, perm1, perm2, run_bn254_double);
    }

    // Ed25519 Add
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_64, &ONE_64, perm1, perm2, run_ed_add);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &ONE_64, perms, run_ed_add);
    }

    // Ed25519 Decompress: input needs to be decompressable
    for perms in one_page_perms {
        test_one_page(p1, &VALID_ED25519_Y, perms, run_ed_decompress);
    }
    for &(perm1, perm2) in &two_page_perms {
        test_one_page_split(p1, p2, &VALID_ED25519_Y, perm1, perm2, run_ed_decompress);
    }

    // BLS12-381 Fp operations
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_bls12381_fp_addmod);
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_bls12381_fp_submod);
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_bls12381_fp_mulmod);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(
            p1,
            p2,
            p3,
            p4,
            &DEFAULT_64,
            &DEFAULT_64,
            perms,
            run_bls12381_fp_addmod,
        );
        test_two_pages_split(
            p1,
            p2,
            p3,
            p4,
            &DEFAULT_64,
            &DEFAULT_64,
            perms,
            run_bls12381_fp_submod,
        );
        test_two_pages_split(
            p1,
            p2,
            p3,
            p4,
            &DEFAULT_64,
            &DEFAULT_64,
            perms,
            run_bls12381_fp_mulmod,
        );
    }

    // BLS12-381 Fp2 operations
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_128, &DEFAULT_128, perm1, perm2, run_bls12381_fp2_addmod);
        test_two_pages(p1, p2, &DEFAULT_128, &DEFAULT_128, perm1, perm2, run_bls12381_fp2_submod);
        test_two_pages(p1, p2, &DEFAULT_128, &DEFAULT_128, perm1, perm2, run_bls12381_fp2_mulmod);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(
            p1,
            p2,
            p3,
            p4,
            &DEFAULT_128,
            &DEFAULT_128,
            perms,
            run_bls12381_fp2_addmod,
        );
        test_two_pages_split(
            p1,
            p2,
            p3,
            p4,
            &DEFAULT_128,
            &DEFAULT_128,
            perms,
            run_bls12381_fp2_submod,
        );
        test_two_pages_split(
            p1,
            p2,
            p3,
            p4,
            &DEFAULT_128,
            &DEFAULT_128,
            perms,
            run_bls12381_fp2_mulmod,
        );
    }

    // BN254 Fp operations
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_bn254_fp_addmod);
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_bn254_fp_submod);
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_bn254_fp_mulmod);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &DEFAULT_64, perms, run_bn254_fp_addmod);
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &DEFAULT_64, perms, run_bn254_fp_submod);
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &DEFAULT_64, perms, run_bn254_fp_mulmod);
    }

    // BN254 Fp2 operations
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_bn254_fp2_addmod);
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_bn254_fp2_submod);
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_bn254_fp2_mulmod);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &DEFAULT_64, perms, run_bn254_fp2_addmod);
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &DEFAULT_64, perms, run_bn254_fp2_submod);
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &DEFAULT_64, perms, run_bn254_fp2_mulmod);
    }

    // Uint256 Mulmod
    for &(perm1, perm2) in &two_page_perms {
        test_two_pages(p1, p2, &DEFAULT_64, &DEFAULT_64, perm1, perm2, run_uint256_mulmod);
    }
    for &perms in &four_page_perms {
        test_two_pages_split(p1, p2, p3, p4, &DEFAULT_64, &DEFAULT_64, perms, run_uint256_mulmod);
    }

    // Uint256 Add, Mul With Carry
    let pages5 = [p1, p2, p3, p4, p5];
    let data5: [&[u8]; 5] = [&DEFAULT_64, &DEFAULT_64, &DEFAULT_64, &DEFAULT_64, &DEFAULT_64];

    for &perms in &five_page_perms {
        test_five_pages(pages5, data5, perms, run_uint256_add_with_carry);
        test_five_pages(pages5, data5, perms, run_uint256_mul_with_carry);
    }

    println!("Terminating! We have handled all traps!");
}

// The current example is a simplified one, while we do have the capability,
// we are not in fact doing a full context switch. In case of trapping, we simply
// return from the function causing the trap. This means the function causing
// traps must be in its own function. A more sophisticated setup does not
// have this limitation.
#[inline(never)]
pub extern "C" fn violating_read(page_addr: *mut u8, default_value: u64) -> u64 {
    #[allow(unused_assignments)]
    let mut value: u64 = default_value;

    unsafe {
        core::arch::asm!(
            "ld {value}, 8({ptr})",
            ptr = in(reg) page_addr,
            value = out(reg) value,
        );
    }

    value
}

#[unsafe(naked)]
pub extern "C" fn violating_write(page_addr: *mut u8, target_value: u64) -> u64 {
    core::arch::naked_asm!("sd a1, 16(a0)", "mv a0, a1", "ret",)
}

#[unsafe(naked)]
pub extern "C" fn violating_execute(page_addr: *mut u8) -> u64 {
    core::arch::naked_asm!("addi a0, a0, 24", "jr a0",)
}

#[inline(never)]
pub extern "C" fn run_sha256_extend(first_page_addr: *mut u8) {
    syscalls::syscall_sha256_extend(first_page_addr as *mut [u64; 64]);
}

#[inline(never)]
pub extern "C" fn run_sha256_compress(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_sha256_compress(
        first_page_addr as *mut [u64; 64],
        second_page_addr as *mut [u64; 8],
    );
}

#[inline(never)]
pub extern "C" fn run_keccak_permute(first_page_addr: *mut u8) {
    syscalls::syscall_keccak_permute(first_page_addr as *mut [u64; 25]);
}

#[inline(never)]
pub extern "C" fn run_secp256k1_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_secp256k1_add(
        first_page_addr as *mut [u64; 8],
        second_page_addr as *mut [u64; 8],
    );
}

#[inline(never)]
pub extern "C" fn run_secp256k1_double(first_page_addr: *mut u8) {
    syscalls::syscall_secp256k1_double(first_page_addr as *mut [u64; 8]);
}

#[inline(never)]
pub extern "C" fn run_secp256r1_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_secp256r1_add(
        first_page_addr as *mut [u64; 8],
        second_page_addr as *mut [u64; 8],
    );
}

#[inline(never)]
pub extern "C" fn run_secp256r1_double(first_page_addr: *mut u8) {
    syscalls::syscall_secp256r1_double(first_page_addr as *mut [u64; 8]);
}

#[inline(never)]
pub extern "C" fn run_bls12381_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_add(
        first_page_addr as *mut [u64; 12],
        second_page_addr as *mut [u64; 12],
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_double(first_page_addr: *mut u8) {
    syscalls::syscall_bls12381_double(first_page_addr as *mut [u64; 12]);
}

#[inline(never)]
pub extern "C" fn run_bn254_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_add(
        first_page_addr as *mut [u64; 8],
        second_page_addr as *mut [u64; 8],
    );
}

#[inline(never)]
pub extern "C" fn run_bn254_double(first_page_addr: *mut u8) {
    syscalls::syscall_bn254_double(first_page_addr as *mut [u64; 8]);
}

#[inline(never)]
pub extern "C" fn run_ed_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_ed_add(first_page_addr as *mut [u64; 8], second_page_addr as *mut [u64; 8]);
}

#[inline(never)]
pub extern "C" fn run_ed_decompress(first_page_addr: *mut u8) {
    syscalls::syscall_ed_decompress(unsafe {
        std::mem::transmute::<*mut u8, &mut [u64; 8]>(first_page_addr)
    });
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp_addmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp_addmod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp_submod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp_submod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp_mulmod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp2_addmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp2_addmod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp2_submod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp2_submod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp2_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp2_mulmod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bn254_fp_addmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp_addmod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp_submod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp_submod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp_mulmod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp2_addmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp2_addmod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp2_submod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp2_submod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp2_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp2_mulmod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_uint256_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_uint256_mulmod(
        first_page_addr as *mut [u64; 4],
        second_page_addr as *const [u64; 4],
    );
}

#[inline(never)]
pub extern "C" fn run_uint256_add_with_carry(
    first_page_addr: *mut u8,
    second_page_addr: *mut u8,
    third_page_addr: *mut u8,
    fourth_page_addr: *mut u8,
    fifth_page_addr: *mut u8,
) {
    syscalls::syscall_uint256_add_with_carry(
        first_page_addr as *const [u64; 4],
        second_page_addr as *const [u64; 4],
        third_page_addr as *const [u64; 4],
        fourth_page_addr as *mut [u64; 4],
        fifth_page_addr as *mut [u64; 4],
    );
}

#[inline(never)]
pub extern "C" fn run_uint256_mul_with_carry(
    first_page_addr: *mut u8,
    second_page_addr: *mut u8,
    third_page_addr: *mut u8,
    fourth_page_addr: *mut u8,
    fifth_page_addr: *mut u8,
) {
    syscalls::syscall_uint256_mul_with_carry(
        first_page_addr as *const [u64; 4],
        second_page_addr as *const [u64; 4],
        third_page_addr as *const [u64; 4],
        fourth_page_addr as *mut [u64; 4],
        fifth_page_addr as *mut [u64; 4],
    );
}

#[inline(never)]
pub extern "C" fn run_poseidon2(first_page_addr: *mut u8) {
    syscalls::syscall_poseidon2(unsafe {
        std::mem::transmute::<*mut u8, &mut syscalls::Poseidon2State>(first_page_addr)
    });
}
