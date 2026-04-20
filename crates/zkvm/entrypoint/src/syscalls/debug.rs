/// Executes the insert_profile_symbols syscall.
///
/// ### Safety
///
/// `addr` must be a null-terminated JSON string
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_insert_profiler_symbols(addr: *const u8, len: u64) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") crate::syscalls::INSERT_PROFILER_SYMBOLS,
            in("a0") addr,
            in("a1") len,
        );
    }
}

/// Executes the delete_profile_symbols syscall.
///
/// ### Safety
///
/// `addr` must be a null-terminated JSON string
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_delete_profiler_symbols(addr: *const u8, len: u64) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") crate::syscalls::DELETE_PROFILER_SYMBOLS,
            in("a0") addr,
            in("a1") len,
        );
    }
}

#[cfg(all(target_os = "zkvm", feature = "may_dump_elf"))]
pub use dump_elf::syscall_dump_elf;

#[cfg(all(target_os = "zkvm", feature = "may_dump_elf"))]
mod dump_elf {
    #[no_mangle]
    pub extern "C" fn _sp1_syscall_setup_page_permissions(permissions: *const u64) {
        let permissions = unsafe {
            core::slice::from_raw_parts(
                permissions,
                sp1_primitives::consts::PERMISSION_ARRAY_LENGTH,
            )
        };
        let mut i = 0;
        while i < permissions.len() && permissions[i] != 0 {
            sp1_lib::mprotect::mprotect(
                permissions[i] as *const _,
                permissions[i + 1] as usize,
                permissions[i + 2] as u8,
            );
            i += 3;
        }
    }

    static SAVED_SP: u64 = 0;

    #[unsafe(naked)]
    #[no_mangle]
    /// Executes the dump_elf syscall
    pub extern "C" fn syscall_dump_elf() {
        core::arch::naked_asm!(
            "addi sp, sp, -16",
            "sd s0, 0(sp)",
            "li s0, {buffer_size}",
            "sub sp, sp, s0",
            "la a0, {saved_sp}",
            "mv a1, sp",
            "li t0, {syscall}",
            "li a3, {input_start}",
            "la a4, {input_ptr}",
            // For some reasons, labels do not work here, we will have to handcode
            // return address. There should not be any li or la instructions starting
            // here till `ret`. This ensures that we won't have any variable length
            // pseudo instructions disrupting the handcoded values.
            "auipc a2, 0",
            "addi a2, a2, 28",
            "ecall",
            // Normal return path after ecall
            "add sp, sp, s0",
            "ld s0, 0(sp)",
            "addi sp, sp, 16",
            "ret",
            // This might look strange. What we actually included here,
            // is a small bootloader for dumping elf feature. The `DUMP_ELF`
            // syscall would create an ELF binary, which when loaded later,
            // recreates the same machine state as when the `DUMP_ELF` syscall
            // happens. This helps us circumvent certain pre-calculated data
            // such as golang's initialization code, saving us a lot of cycles
            // from code that must be repeatedly executed.
            //
            // However, while an ELF binary can store memory states, certain
            // states in the SP1 machine are typically missing in ELF:
            // * Register states
            // * While ELF binary does allow setting memory permissions, there
            // are certain longer programs in SP1 which requires mprotect calls
            // after initial loading.
            //
            // To overcome the above issues, we use a workaround here: when
            // running `DUMP_ELF` syscalls, SP1 executor would save current
            // register states, as well as non-default page permissions into
            // machine memory provided by this function. After that, we can
            // have SP1 only serialize current machine's memory states. The
            // code below in current function, is effectively a small bootloader,
            // where we are initializing all register states and non-default
            // page permissions from saved memory states. This way we can achieve
            // what we need in the `DUMP_ELF` feature.
            //
            // SP must be in global static memory since at boot time we don't
            // really know the correct SP. The rest of registers and permissions
            // reside in stack.
            //
            // Another way of thinking the problem, is that you will only reach
            // this place, when you are booting from the dumped elf binary. This
            // is why we call it effectively a bootloader.
            "la sp, {saved_sp}",
            "ld sp, 0(sp)",
            "mv a0, sp",
            // There is no need to save / restore ra when calling external function.
            // RA is already saved in +registers+ static array.
            "call {f}",
            // Restore SP first
            "li a0, {buffer_size}",
            "add sp, sp, a0",
            // Restoring all GPR registers except SP
            "ld ra, -240(sp)",
            "ld gp, -232(sp)",
            "ld tp, -224(sp)",
            "ld t0, -216(sp)",
            "ld t1, -208(sp)",
            "ld t2, -200(sp)",
            "ld s0, -192(sp)",
            "ld s1, -184(sp)",
            "ld a0, -176(sp)",
            "ld a1, -168(sp)",
            "ld a2, -160(sp)",
            "ld a3, -152(sp)",
            "ld a4, -144(sp)",
            "ld a5, -136(sp)",
            "ld a6, -128(sp)",
            "ld a7, -120(sp)",
            "ld s2, -112(sp)",
            "ld s3, -104(sp)",
            "ld s4, -96(sp)",
            "ld s5, -88(sp)",
            "ld s6, -80(sp)",
            "ld s7, -72(sp)",
            "ld s8, -64(sp)",
            "ld s9, -56(sp)",
            "ld s10, -48(sp)",
            "ld s11, -40(sp)",
            "ld t3, -32(sp)",
            "ld t4, -24(sp)",
            "ld t5, -16(sp)",
            "ld t6, -8(sp)",
            // Restore saved s0, we have already bumped SP by buffer_size
            "ld s0, 0(sp)",
            "addi sp, sp, 16",
            "ret",
            f = sym _sp1_syscall_setup_page_permissions,
            saved_sp = sym SAVED_SP,
            syscall = const crate::syscalls::DUMP_ELF,
            buffer_size = const sp1_primitives::consts::PERMISSION_BUFFER_SIZE + 240,
            input_start = const crate::EMBEDDED_RESERVED_INPUT_START as u64,
            input_ptr = sym crate::EMBEDDED_RESERVED_INPUT_PTR,
        );
    }
}

#[no_mangle]
#[cfg(not(all(target_os = "zkvm", feature = "may_dump_elf")))]
/// Executes the dump_elf syscall
pub extern "C" fn syscall_dump_elf() {
    eprintln!(
        "WARNING: dump_elf is noop when feature may_dump_elf is not enabled, or on native target."
    );
}
