use super::TranspilerBackend;
use crate::{
    memory::AnonymousMemory, trace_capacity, ComputeInstructions, ControlFlowInstructions,
    Debuggable, JitContext, JitFunction, MemoryInstructions, MinimalTrace, RiscOperand,
    RiscRegister, RiscvTranspiler, TraceChunkRaw,
};
use memmap2::MmapMut;

macro_rules! assert_register_is {
    ($expected:expr) => {{
        extern "C" fn assert_register_is_expected(val: u64) {
            assert_eq!(val, $expected);
        }

        assert_register_is_expected
    }};
}

fn new_backend() -> TranspilerBackend {
    TranspilerBackend::new(0, 1024 * 2, 1000, 100, 100).unwrap()
}

fn run_func(func: &mut JitFunction<AnonymousMemory>) -> Option<TraceChunkRaw> {
    let mut trace_buf = MmapMut::map_anon(trace_capacity(Some(1000))).expect("create mmap buf");
    let trace_buf_ptr = trace_buf.as_mut_ptr();

    unsafe {
        func.call(trace_buf_ptr);
    }

    Some(unsafe { TraceChunkRaw::new(trace_buf) })
}

/// Finalize the function and call it.
fn run_test(assembler: TranspilerBackend) {
    let mut func = assembler.finalize().expect("Failed to finalize function");

    run_func(&mut func);
}

mod alu {
    use super::*;

    #[test]
    fn test_add_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.add(RiscRegister::X5, RiscOperand::Immediate(5), RiscOperand::Immediate(10));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(15));

        run_test(backend);
    }

    #[test]
    fn test_multiple_adds() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.add(RiscRegister::X5, RiscOperand::Immediate(5), RiscOperand::Immediate(10));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(15));

        backend.add(RiscRegister::X6, RiscOperand::Immediate(10), RiscOperand::Immediate(10));
        backend.inspect_register(RiscRegister::X6, assert_register_is!(20));

        backend.add(RiscRegister::X7, RiscOperand::Immediate(20), RiscOperand::Immediate(5));
        backend.inspect_register(RiscRegister::X7, assert_register_is!(25));

        run_test(backend);
    }

    #[test]
    fn test_add_handles_overflow_64bit() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.add(
            RiscRegister::X5,
            RiscOperand::Immediate((u64::MAX - 1) as i32),
            RiscOperand::Immediate((u64::MAX - 1) as i32),
        );

        backend.inspect_register(
            RiscRegister::X5,
            assert_register_is!((u64::MAX - 1).wrapping_add(u64::MAX - 1)),
        );

        run_test(backend);
    }

    #[test]
    fn test_mul_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.mul(RiscRegister::X5, RiscOperand::Immediate(5), RiscOperand::Immediate(4));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(20));

        run_test(backend);
    }

    #[test]
    fn test_mul_handles_overflow_64bit() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.mul(
            RiscRegister::X5,
            RiscOperand::Immediate((u64::MAX - 1) as i32),
            RiscOperand::Immediate((u64::MAX - 1) as i32),
        );

        backend.inspect_register(
            RiscRegister::X5,
            assert_register_is!((u64::MAX - 1).wrapping_mul(u64::MAX - 1)),
        );

        run_test(backend);
    }

    #[test]
    fn test_div_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.div(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(2));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(5));

        backend.div(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(0));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFFFFFFFFFFFFFF));

        backend.div(RiscRegister::X5, RiscOperand::Immediate(-10), RiscOperand::Immediate(2));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(-5_i64 as u64));

        run_test(backend);
    }

    #[test]
    fn test_mulh_immediate_correct() {
        let mut backend = new_backend();
        backend.start_instr();

        // 0x7FFF_FFFF * 2  → 0x0000_0000_FFFF_FFFE  → high=0
        backend.mulh(
            RiscRegister::X5,
            RiscOperand::Immediate(0x7FFF_FFFF), // +2 147 483 647
            RiscOperand::Immediate(2),
        );
        backend.inspect_register(
            RiscRegister::X5,
            assert_register_is!(((0x7FFF_FFFF_i64 * 2) >> 32) as u64),
        );

        // -1 * 3 → 0xFFFF_FFFF_FFFF_FFFD  → high=0xFFFF_FFFF
        backend.mulh(
            RiscRegister::X5,
            RiscOperand::Immediate(-1), // 0xFFFF_FFFF
            RiscOperand::Immediate(3),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!((-3_i64 >> 32) as u64));

        run_test(backend);
    }

    #[test]
    fn test_mulhu_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();

        // 0xFFFF_FFFF_FFFF_FFFF * 0xFFFF_FFFF_FFFF_FFFF → high 64 bits
        backend.mulhu(
            RiscRegister::X5,
            RiscOperand::Immediate(-1), // 0xFFFF_FFFF_FFFF_FFFF as unsigned
            RiscOperand::Immediate(-1),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFF_FFFF_FFFF_FFFE));

        // 0x8000_0000 * 2 → for 64-bit system, this becomes larger multiplication
        backend.mulhu(
            RiscRegister::X5,
            RiscOperand::Immediate(0x8000_0000u32 as i32), // 2^31
            RiscOperand::Immediate(2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0x0000_0001));

        run_test(backend);
    }

    #[test]
    fn test_mulhsu_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();

        // -1 * 3 in 64-bit: high 64 bits of 128-bit result
        backend.mulhsu(
            RiscRegister::X5,
            RiscOperand::Immediate(-1), // signed -1 (0xFFFF_FFFF_FFFF_FFFF)
            RiscOperand::Immediate(3),  // unsigned 3
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFF_FFFF_FFFF_FFFF));

        // 0x7FFF_FFFF * 0xFFFF_FFFF for 64-bit
        backend.mulhsu(
            RiscRegister::X5,
            RiscOperand::Immediate(0x7FFF_FFFF), // positive value
            RiscOperand::Immediate(-1),          // 0xFFFF_FFFF_FFFF_FFFF as unsigned
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0x7FFF_FFFE));

        run_test(backend);
    }

    #[test]
    fn test_rem_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.rem(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(1));

        backend.rem(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(0));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(10));

        backend.rem(RiscRegister::X5, RiscOperand::Immediate(-10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(-1_i32 as u64));

        run_test(backend);
    }

    #[test]
    fn test_remu_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.remu(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(1));

        backend.remu(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(0));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(10));

        backend.remu(RiscRegister::X5, RiscOperand::Immediate(-10), RiscOperand::Immediate(3));
        backend
            .inspect_register(RiscRegister::X5, assert_register_is!(((-10_i32 as u32) % 3) as u64));

        run_test(backend);
    }

    #[test]
    fn test_sll_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.sll(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(10 << 3));

        backend.sll(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(500));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(10_u64.wrapping_shl(500)));

        run_test(backend);
    }

    #[test]
    fn test_srl_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.srl(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(10 >> 3));

        backend.srl(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(500));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0));

        run_test(backend);
    }

    #[test]
    fn test_sra_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.sra(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(10 >> 3));

        backend.sra(RiscRegister::X5, RiscOperand::Immediate(-10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!((-10 >> 3) as u64));

        run_test(backend);
    }

    #[test]
    fn test_slt_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.slt(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0));

        backend.slt(RiscRegister::X5, RiscOperand::Immediate(-10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(1));

        run_test(backend);
    }

    #[test]
    fn test_sltu_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.sltu(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0));

        backend.sltu(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(10));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0));

        backend.sltu(RiscRegister::X5, RiscOperand::Immediate(-10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0));

        backend.sltu(RiscRegister::X5, RiscOperand::Immediate(3), RiscOperand::Immediate(10));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(1));

        run_test(backend);
    }

    #[test]
    fn test_sub_immediate_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.sub(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(10 - 3));

        backend.sub(RiscRegister::X5, RiscOperand::Immediate(10), RiscOperand::Immediate(10));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0));

        backend.sub(RiscRegister::X5, RiscOperand::Immediate(-10), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!((-10_i64 - 3) as u64));

        run_test(backend);
    }
}

mod rv64i {
    use super::*;

    // RV64I Word Operations Tests (32-bit operations on 64-bit system)

    #[test]
    fn test_addw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        // ADDW sign-extends the 32-bit result to 64 bits
        backend.addw(
            RiscRegister::X5,
            RiscOperand::Immediate(0x7FFFFFFF),
            RiscOperand::Immediate(1),
        );
        // 0x7FFFFFFF + 1 = 0x80000000, sign-extended to 0xFFFFFFFF80000000
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFFFFFF80000000));

        backend.addw(RiscRegister::X6, RiscOperand::Immediate(10), RiscOperand::Immediate(20));
        backend.inspect_register(RiscRegister::X6, assert_register_is!(30));

        run_test(backend);
    }

    #[test]
    fn test_addw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers with values
        backend.add(
            RiscRegister::X1,
            RiscOperand::Immediate(0x7FFFFFFF),
            RiscOperand::Immediate(0),
        );
        backend.add(RiscRegister::X2, RiscOperand::Immediate(1), RiscOperand::Immediate(0));

        // Test register + register
        backend.addw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFFFFFF80000000));

        // Test register + immediate
        backend.addw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Immediate(2),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(0xFFFFFFFF80000001));

        run_test(backend);
    }

    #[test]
    fn test_subw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        // SUBW sign-extends the 32-bit result to 64 bits
        backend.subw(RiscRegister::X5, RiscOperand::Immediate(0), RiscOperand::Immediate(1));
        // 0 - 1 = -1 (0xFFFFFFFF in 32-bit), sign-extended to 0xFFFFFFFFFFFFFFFF
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFFFFFFFFFFFFFF));

        backend.subw(RiscRegister::X6, RiscOperand::Immediate(30), RiscOperand::Immediate(10));
        backend.inspect_register(RiscRegister::X6, assert_register_is!(20));

        run_test(backend);
    }

    #[test]
    fn test_subw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers
        backend.add(RiscRegister::X1, RiscOperand::Immediate(0), RiscOperand::Immediate(0));
        backend.add(RiscRegister::X2, RiscOperand::Immediate(1), RiscOperand::Immediate(0));

        // Test register - register
        backend.subw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFFFFFFFFFFFFFF));

        // Test register - immediate
        backend.add(RiscRegister::X3, RiscOperand::Immediate(100), RiscOperand::Immediate(0));
        backend.subw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X3),
            RiscOperand::Immediate(50),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(50));

        run_test(backend);
    }

    #[test]
    fn test_mulw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        // MULW takes lower 32 bits and sign-extends
        backend.mulw(
            RiscRegister::X5,
            RiscOperand::Immediate(0x10000),
            RiscOperand::Immediate(0x10000),
        );
        // 0x10000 * 0x10000 = 0x100000000, truncated to 0 in 32-bit, sign-extended to 0
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0));

        backend.mulw(RiscRegister::X6, RiscOperand::Immediate(-5), RiscOperand::Immediate(3));
        // -5 * 3 = -15 (0xFFFFFFF1 in 32-bit), sign-extended to 0xFFFFFFFFFFFFFFF1
        backend.inspect_register(RiscRegister::X6, assert_register_is!(0xFFFFFFFFFFFFFFF1));

        run_test(backend);
    }

    #[test]
    fn test_mulw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers
        backend.add(RiscRegister::X1, RiscOperand::Immediate(0x10000), RiscOperand::Immediate(0));
        backend.add(RiscRegister::X2, RiscOperand::Immediate(0x10000), RiscOperand::Immediate(0));

        // Test register * register
        backend.mulw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0));

        // Test register * immediate
        backend.add(RiscRegister::X3, RiscOperand::Immediate(-5), RiscOperand::Immediate(0));
        backend.mulw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X3),
            RiscOperand::Immediate(4),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(0xFFFFFFFFFFFFFFEC)); // -20 sign-extended

        run_test(backend);
    }

    #[test]
    fn test_divw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.divw(RiscRegister::X5, RiscOperand::Immediate(100), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(33));

        backend.divw(RiscRegister::X6, RiscOperand::Immediate(-100), RiscOperand::Immediate(3));
        // -100 / 3 = -33 (0xFFFFFFDF in 32-bit), sign-extended
        backend.inspect_register(RiscRegister::X6, assert_register_is!(0xFFFFFFFFFFFFFFDF));

        run_test(backend);
    }

    #[test]
    fn test_divw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers
        backend.add(RiscRegister::X1, RiscOperand::Immediate(100), RiscOperand::Immediate(0));
        backend.add(RiscRegister::X2, RiscOperand::Immediate(3), RiscOperand::Immediate(0));

        // Test register / register
        backend.divw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(33));

        // Test register / immediate
        backend.add(RiscRegister::X3, RiscOperand::Immediate(-100), RiscOperand::Immediate(0));
        backend.divw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X3),
            RiscOperand::Immediate(7),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(0xFFFFFFFFFFFFFFF2)); // -14 sign-extended

        run_test(backend);
    }

    #[test]
    fn test_divuw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        // DIVUW treats operands as unsigned 32-bit values
        backend.divuw(RiscRegister::X5, RiscOperand::Immediate(-1), RiscOperand::Immediate(2));
        // 0xFFFFFFFF / 2 = 0x7FFFFFFF (unsigned), sign-extended to 0x000000007FFFFFFF
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0x7FFFFFFF));

        backend.divuw(RiscRegister::X6, RiscOperand::Immediate(100), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X6, assert_register_is!(33));

        run_test(backend);
    }

    #[test]
    fn test_divuw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers
        backend.add(RiscRegister::X1, RiscOperand::Immediate(-1), RiscOperand::Immediate(0));
        backend.add(RiscRegister::X2, RiscOperand::Immediate(2), RiscOperand::Immediate(0));

        // Test register / register (unsigned)
        backend.divuw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0x7FFFFFFF));

        // Test register / immediate
        backend.add(RiscRegister::X3, RiscOperand::Immediate(100), RiscOperand::Immediate(0));
        backend.divuw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X3),
            RiscOperand::Immediate(7),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(14));

        run_test(backend);
    }

    #[test]
    fn test_remw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.remw(RiscRegister::X5, RiscOperand::Immediate(100), RiscOperand::Immediate(7));
        backend.inspect_register(RiscRegister::X5, assert_register_is!(2));

        backend.remw(RiscRegister::X6, RiscOperand::Immediate(-100), RiscOperand::Immediate(7));
        // -100 % 7 = -2 (0xFFFFFFFE in 32-bit), sign-extended
        backend.inspect_register(RiscRegister::X6, assert_register_is!(0xFFFFFFFFFFFFFFFE));

        run_test(backend);
    }

    #[test]
    fn test_remw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers
        backend.add(RiscRegister::X1, RiscOperand::Immediate(100), RiscOperand::Immediate(0));
        backend.add(RiscRegister::X2, RiscOperand::Immediate(7), RiscOperand::Immediate(0));

        // Test register % register
        backend.remw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(2));

        // Test register % immediate
        backend.add(RiscRegister::X3, RiscOperand::Immediate(-100), RiscOperand::Immediate(0));
        backend.remw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X3),
            RiscOperand::Immediate(9),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(0xFFFFFFFFFFFFFFFF)); // -1 sign-extended (-100 % 9 = -1)

        run_test(backend);
    }

    #[test]
    fn test_remuw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        // REMUW treats operands as unsigned 32-bit values
        backend.remuw(RiscRegister::X5, RiscOperand::Immediate(-1), RiscOperand::Immediate(10));
        // 0xFFFFFFFF % 10 = 5 (unsigned), sign-extended to 0x0000000000000005
        backend.inspect_register(RiscRegister::X5, assert_register_is!(5));

        backend.remuw(RiscRegister::X6, RiscOperand::Immediate(100), RiscOperand::Immediate(7));
        backend.inspect_register(RiscRegister::X6, assert_register_is!(2));

        run_test(backend);
    }

    #[test]
    fn test_remuw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers
        backend.add(RiscRegister::X1, RiscOperand::Immediate(-1), RiscOperand::Immediate(0));
        backend.add(RiscRegister::X2, RiscOperand::Immediate(10), RiscOperand::Immediate(0));

        // Test register % register (unsigned)
        backend.remuw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(5));

        // Test register % immediate
        backend.add(RiscRegister::X3, RiscOperand::Immediate(100), RiscOperand::Immediate(0));
        backend.remuw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X3),
            RiscOperand::Immediate(9),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(1));

        run_test(backend);
    }

    #[test]
    fn test_sllw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        // SLLW performs 32-bit shift and sign-extends result
        backend.sllw(
            RiscRegister::X5,
            RiscOperand::Immediate(0x40000000),
            RiscOperand::Immediate(1),
        );
        // 0x40000000 << 1 = 0x80000000, sign-extended to 0xFFFFFFFF80000000
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFFFFFF80000000));

        backend.sllw(RiscRegister::X6, RiscOperand::Immediate(5), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X6, assert_register_is!(40));

        run_test(backend);
    }

    #[test]
    fn test_sllw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers
        backend.add(
            RiscRegister::X1,
            RiscOperand::Immediate(0x40000000),
            RiscOperand::Immediate(0),
        );
        backend.add(RiscRegister::X2, RiscOperand::Immediate(1), RiscOperand::Immediate(0));

        // Test register << register
        backend.sllw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFFFFFF80000000));

        // Test register << immediate
        backend.add(RiscRegister::X3, RiscOperand::Immediate(7), RiscOperand::Immediate(0));
        backend.sllw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X3),
            RiscOperand::Immediate(4),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(112));

        run_test(backend);
    }

    #[test]
    fn test_srlw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        // SRLW performs logical (unsigned) 32-bit shift and sign-extends result
        backend.srlw(
            RiscRegister::X5,
            RiscOperand::Immediate(0x80000000u32 as i32),
            RiscOperand::Immediate(1),
        );
        // 0x80000000 >> 1 = 0x40000000 (logical), sign-extended to 0x0000000040000000
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0x40000000));

        backend.srlw(RiscRegister::X6, RiscOperand::Immediate(40), RiscOperand::Immediate(3));
        backend.inspect_register(RiscRegister::X6, assert_register_is!(5));

        run_test(backend);
    }

    #[test]
    fn test_srlw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers
        backend.add(
            RiscRegister::X1,
            RiscOperand::Immediate(0x80000000u32 as i32),
            RiscOperand::Immediate(0),
        );
        backend.add(RiscRegister::X2, RiscOperand::Immediate(1), RiscOperand::Immediate(0));

        // Test register >> register (logical)
        backend.srlw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0x40000000));

        // Test register >> immediate
        backend.add(RiscRegister::X3, RiscOperand::Immediate(80), RiscOperand::Immediate(0));
        backend.srlw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X3),
            RiscOperand::Immediate(4),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(5));

        run_test(backend);
    }

    #[test]
    fn test_sraw_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        // SRAW performs arithmetic 32-bit shift and sign-extends result
        backend.sraw(
            RiscRegister::X5,
            RiscOperand::Immediate(0x80000000u32 as i32),
            RiscOperand::Immediate(1),
        );
        // 0x80000000 >> 1 = 0xC0000000 (arithmetic), sign-extended to 0xFFFFFFFFC0000000
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFFFFFFC0000000));

        backend.sraw(RiscRegister::X6, RiscOperand::Immediate(-40), RiscOperand::Immediate(3));
        // -40 (0xFFFFFFD8 in 32-bit) >> 3 = 0xFFFFFFFB, sign-extended
        backend.inspect_register(RiscRegister::X6, assert_register_is!(0xFFFFFFFFFFFFFFFB));

        run_test(backend);
    }

    #[test]
    fn test_sraw_register() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set up registers
        backend.add(
            RiscRegister::X1,
            RiscOperand::Immediate(0x80000000u32 as i32),
            RiscOperand::Immediate(0),
        );
        backend.add(RiscRegister::X2, RiscOperand::Immediate(1), RiscOperand::Immediate(0));

        // Test register >> register (arithmetic)
        backend.sraw(
            RiscRegister::X5,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Register(RiscRegister::X2),
        );
        backend.inspect_register(RiscRegister::X5, assert_register_is!(0xFFFFFFFFC0000000));

        // Test register >> immediate
        backend.add(RiscRegister::X3, RiscOperand::Immediate(-80), RiscOperand::Immediate(0));
        backend.sraw(
            RiscRegister::X6,
            RiscOperand::Register(RiscRegister::X3),
            RiscOperand::Immediate(4),
        );
        backend.inspect_register(RiscRegister::X6, assert_register_is!(0xFFFFFFFFFFFFFFFB)); // -5 sign-extended

        run_test(backend);
    }
}

mod control_flow {
    use super::*;

    #[test]
    fn test_set_pc() {
        let mut backend = new_backend();

        extern "C" fn assert_pc_is_199(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };

            assert_eq!(ctx.pc, 199);
        }

        extern "C" fn assert_pc_is_599(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };

            assert_eq!(ctx.pc, 599);
        }

        backend.start_instr();
        backend.bump_pc(99);
        backend.call_extern_fn(assert_pc_is_199);
        backend.bump_pc(400);
        backend.call_extern_fn(assert_pc_is_599);

        run_test(backend);
    }

    #[test]
    fn test_bump_clk_does_not_touch_per_shard_clk() {
        // Per-shard clk (r15 / ctx.clk) is no longer maintained by the JIT
        // since the no-clk MinimalExecutor change. bump_clk only defers a
        // contribution to global_clk; ctx.clk should stay at its initial value.
        let mut backend = new_backend();

        extern "C" fn assert_clk_is_1(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            assert_eq!(ctx.clk, 1);
        }

        backend.start_instr();
        backend.bump_clk();
        backend.flush_clk();
        backend.call_extern_fn(assert_clk_is_1);
        backend.bump_clk();
        backend.flush_clk();
        backend.call_extern_fn(assert_clk_is_1);

        run_test(backend);
    }

    #[test]
    fn test_bump_global_clk_unconstrained() {
        let mut backend = new_backend();

        extern "C" fn assert_global_clk_is_1(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };

            assert_eq!(ctx.global_clk, 1);
        }

        extern "C" fn assert_global_clk_is_2(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };

            assert_eq!(ctx.global_clk, 2);
        }

        extern "C" fn enter_unconstrained(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };

            ctx.is_constrained = 0;
        }

        extern "C" fn exit_unconstrained(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };

            ctx.is_constrained = 1;
        }

        // bump_clk defers; we explicitly flush_clk before each assertion so
        // the global_clk update is visible at the call_extern_fn boundary.
        backend.start_instr();
        backend.bump_clk();
        backend.flush_clk();
        backend.call_extern_fn(assert_global_clk_is_1);

        backend.call_extern_fn(enter_unconstrained);
        backend.bump_clk();
        backend.flush_clk();
        backend.call_extern_fn(assert_global_clk_is_1);

        backend.call_extern_fn(exit_unconstrained);
        backend.bump_clk();
        backend.flush_clk();
        backend.call_extern_fn(assert_global_clk_is_2);
        run_test(backend)
    }

    // #[test]
    // fn test_exit_if_trace_exceeds() {
    //     // Test now checks memory reads-based cut point with 90% threshold
    //     let max_mem_reads = 10;
    //     let trace_size = max_mem_reads * std::mem::size_of::<crate::MemValue>() as u64;
    //     // 90% threshold: (10 * 9) / 10 = 9
    //     let threshold_reads = 9;

    //     let mut backend = crate::backends::x86::TranspilerBackend::new(
    //         0,
    //         1024 * 2,
    //         trace_size as usize,
    //         100,
    //         100,
    //     )
    //     .unwrap();

    //     extern "C" fn assert_false(_: *mut JitContext) {
    //         unreachable!("Should have exited before reaching here");
    //     }

    //     backend.start_instr();

    //     // Test: Should NOT exit when num_mem_reads is 0 (beginning)
    //     backend.exit_if_trace_exceeds(trace_size);
    //     // Should continue since num_mem_reads == 0

    //     // Do memory operations up to just below the 90% threshold
    //     for i in 0..8 {
    //         backend.lw(RiscRegister::X1, RiscRegister::X0, i * 4);
    //         backend.trace_mem_value(RiscRegister::X0, i * 4);
    //         backend.exit_if_trace_exceeds(trace_size);
    //         // Should continue since we're still below 90% threshold (9 reads)
    //     }

    //     // Now add the 9th memory read - this should trigger the exit at 90% threshold
    //     backend.lw(RiscRegister::X3, RiscRegister::X0, 32);
    //     backend.trace_mem_value(RiscRegister::X0, 32); // num_mem_reads = 9
    //     backend.exit_if_trace_exceeds(trace_size);
    //     // Should exit here since 9 >= 9 (90% of 10)

    //     // This should be unreachable
    //     backend.call_extern_fn(assert_false);

    //     let mut func = backend.finalize().expect("Failed to finalize function");
    //     let chunk = unsafe { func.call() };

    //     // Verify we got a chunk back at the 90% threshold
    //     assert!(chunk.is_some(), "Expected execution to be cut at 90% threshold");
    //     if let Some(chunk) = chunk {
    //         assert_eq!(
    //             chunk.num_mem_reads(),
    //             threshold_reads,
    //             "Expected {} memory reads (90% threshold), got {}",
    //             threshold_reads,
    //             chunk.num_mem_reads()
    //         );
    //     }
    // }

    #[test]
    fn test_jump_skips_instruction() {
        let mut backend = new_backend();

        // PC = 0
        backend.start_instr();
        backend.add(RiscRegister::X1, RiscOperand::Immediate(1), RiscOperand::Immediate(1)); // 1 + 1 = 2
        backend.end_instr();

        // // PC = 1
        backend.start_instr();
        backend.add(RiscRegister::X2, RiscOperand::Immediate(2), RiscOperand::Immediate(2)); // 2 + 2 = 4
        backend.end_instr();

        backend.print_ctx();

        // PC = 2
        backend.start_instr();
        backend.jal(RiscRegister::X0, 8); // jump to PC = 4
        backend.end_instr();

        backend.print_ctx();

        // // PC = 3 (also skipped due to jump of 3)
        backend.start_instr();
        backend.add(RiscRegister::X3, RiscOperand::Immediate(100), RiscOperand::Immediate(23));
        backend.end_instr();

        backend.print_ctx();

        // // // PC = 4
        backend.start_instr();
        backend.add(RiscRegister::X4, RiscOperand::Immediate(42), RiscOperand::Immediate(1)); // 42 + 1 = 43
        backend.end_instr();

        backend.print_ctx();

        backend.inspect_register(RiscRegister::X1, assert_register_is!(2));
        backend.inspect_register(RiscRegister::X2, assert_register_is!(4));
        backend.inspect_register(RiscRegister::X3, assert_register_is!(0)); // skipped
        backend.inspect_register(RiscRegister::X4, assert_register_is!(43));

        run_test(backend);
    }

    #[test]
    fn test_branch_neq() {
        let mut backend = new_backend();

        // PC = 0
        backend.start_instr();
        backend.add(RiscRegister::X1, RiscOperand::Immediate(5), RiscOperand::Immediate(0));
        backend.end_instr();

        // PC = 1
        backend.start_instr();
        backend.add(RiscRegister::X2, RiscRegister::X2.into(), RiscOperand::Immediate(1));
        backend.end_instr();

        // PC = 2
        // Branch to PC = 1 if X1 != X2
        backend.start_instr();
        backend.bne(RiscRegister::X1, RiscRegister::X2, u64::MAX);
        backend.end_instr();
        backend.inspect_register(RiscRegister::X2, assert_register_is!(5));

        // dummy
        backend.start_instr();
        backend.add(RiscRegister::X0, RiscRegister::X0.into(), RiscOperand::Immediate(0));

        run_test(backend);
    }
}

mod memory {
    use super::*;

    fn run_test_with_memory(assembler: TranspilerBackend, memory: &[(u32, u32)]) {
        let mut func =
            assembler.finalize::<AnonymousMemory>().expect("Failed to finalize function");

        for (addr, val) in memory {
            assert!(*addr < func.memory.len() as u32, "Addr out of bounds");
            assert!(*addr % 4 == 0, "Addr must be 4 byte aligned");

            let addr = *addr as usize;
            let bytes = val.to_le_bytes();
            func.memory[addr] = bytes[0];
            func.memory[addr + 1] = bytes[1];
            func.memory[addr + 2] = bytes[2];
            func.memory[addr + 3] = bytes[3];
        }

        run_func(&mut func);
    }

    fn run_test_and_check_memory(assembler: TranspilerBackend, check: impl Fn(&[u64])) {
        let mut func = assembler.finalize().expect("Failed to finalize function");

        run_func(&mut func);

        unsafe fn caster(input: &[u8]) -> &[u64] {
            let word_count = input.len() / std::mem::size_of::<u64>();
            std::slice::from_raw_parts(input.as_ptr() as *const u64, word_count)
        }

        check(unsafe { caster(&func.memory) });
    }

    #[test]
    fn test_load_word_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lw(RiscRegister::X1, RiscRegister::X1, 0);
        backend.inspect_register(RiscRegister::X1, assert_register_is!(5));

        run_test_with_memory(backend, &[(0, 5)]);
    }

    #[test]
    fn test_load_byte_signed_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lb(RiscRegister::X1, RiscRegister::X1, 0); // LB x1, 0(x1)
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0xFFFFFFFFFFFFFF80)); // −128 sign-extended

        // memory[0] = 0x80  (remaining three bytes are 0)
        run_test_with_memory(backend, &[(0, 0x0000_0080)]);
    }

    #[test]
    fn test_load_byte_unsigned_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lbu(RiscRegister::X1, RiscRegister::X1, 0); // LBU x1, 0(x1)
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0x00000080)); // 128 zero-extended

        run_test_with_memory(backend, &[(0, 0x0000_0080)]);
    }

    #[test]
    fn test_load_half_signed_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lh(RiscRegister::X1, RiscRegister::X1, 0); // LH x1, 0(x1)
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0xFFFFFFFFFFFF8000)); // −32768 sign-extended

        // memory[0..2] = 0x00,0x80  (i.e., little-endian 0x8000)
        run_test_with_memory(backend, &[(0, 0x0000_8000)]);
    }

    #[test]
    fn test_load_half_unsigned_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lhu(RiscRegister::X1, RiscRegister::X1, 0); // LHU x1, 0(x1)
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0x00008000)); // 32768 zero-extended

        run_test_with_memory(backend, &[(0, 0x0000_8000)]);
    }

    #[test]
    fn test_store_word_correct() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.add(RiscRegister::X1, RiscOperand::Immediate(5), RiscOperand::Immediate(0));
        backend.end_instr();

        // Store 5 into memory[0]
        backend.start_instr();
        backend.sw(RiscRegister::X0, RiscRegister::X1, 0); // SW: m(rs1 + imm) = rs2

        run_test_and_check_memory(backend, |memory| {
            assert_eq!(memory[0], 5);
        });
    }

    #[test]
    fn test_store_halfword_correct() {
        let mut backend = new_backend();

        // Put 0x01F2 (little-endian bytes F2 01) into x1
        backend.start_instr();
        backend.add(RiscRegister::X1, RiscOperand::Immediate(0x01F2), RiscOperand::Immediate(0));
        backend.end_instr();

        // SH: store 16-bit value at address 0
        backend.start_instr();
        backend.sh(RiscRegister::X0, RiscRegister::X1, 0);

        run_test_and_check_memory(backend, |memory| {
            assert_eq!(memory[0], 0x01F2); // low byte
        });
    }

    #[test]
    fn test_store_byte_correct() {
        let mut backend = new_backend();

        // Put 0xAB into x1
        backend.start_instr();
        backend.add(RiscRegister::X1, RiscOperand::Immediate(0xAB), RiscOperand::Immediate(0));
        backend.end_instr();

        // SB: store 8-bit value at address 0
        backend.start_instr();
        backend.sb(RiscRegister::X0, RiscRegister::X1, 0);

        run_test_and_check_memory(backend, |memory| {
            assert_eq!(memory[0], 0xAB);

            // confirm surrounding bytes remain zero
            assert_eq!(memory[1], 0x00);
        });
    }

    /// 0x1234 lives in the *low* half-word (bytes 0–1)
    #[test]
    fn test_lhu_low_halfword() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lhu(RiscRegister::X2, RiscRegister::X1, 0); // X1 == 0 by default
        backend.inspect_register(RiscRegister::X2, assert_register_is!(0x00001234));

        // Memory word: 0xABCD_1234  ->  [34 12 CD AB] (little-endian)
        run_test_with_memory(backend, &[(0, 0xABCD_1234)]);
    }

    #[test]
    /// 0xABCD lives in the *high* half-word (bytes 2–3) of that same word
    fn test_lhu_high_halfword() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lhu(RiscRegister::X3, RiscRegister::X1, 2); // imm = 2 => second half-word
        backend.inspect_register(RiscRegister::X3, assert_register_is!(0x0000ABCD));

        run_test_with_memory(backend, &[(0, 0xABCD_1234)]);
    }

    /// Value with the top bit set (0x8000) to verify *zero* extension
    #[test]
    fn test_lhu_zero_extension() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lhu(RiscRegister::X1, RiscRegister::X1, 0);
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0x00008000));

        run_test_with_memory(backend, &[(0, 0x0000_8000)]);
    }

    /// Low half-word is 0xF234 → −3564 after sign-extension
    #[test]
    fn test_lh_sign_negative_low() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lh(RiscRegister::X2, RiscRegister::X1, 0);
        backend.inspect_register(RiscRegister::X2, assert_register_is!(0xFFFFFFFFFFFFF234));

        run_test_with_memory(backend, &[(0, 0xABCD_F234)]);
    }

    /// High half-word is 0x8000 → −32768 after sign-extension
    #[test]
    fn test_lh_sign_negative_high() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.lh(RiscRegister::X3, RiscRegister::X1, 2);
        backend.inspect_register(RiscRegister::X3, assert_register_is!(0xFFFFFFFFFFFF8000));

        run_test_with_memory(backend, &[(0, 0x8000_1234)]);
    }

    // Helper function for 64-bit memory operations
    fn run_test_with_memory_64(assembler: TranspilerBackend, memory: &[(u32, u64)]) {
        let mut func =
            assembler.finalize::<AnonymousMemory>().expect("Failed to finalize function");

        for (addr, val) in memory {
            assert!(*addr < func.memory.len() as u32, "Addr out of bounds");
            assert!(*addr % 8 == 0, "Addr must be 8 byte aligned");

            let bytes = val.to_le_bytes();
            let actual_addr = *addr as usize;
            for (i, byte) in bytes.iter().enumerate() {
                func.memory[actual_addr + i] = *byte;
            }
        }

        run_func(&mut func);
    }

    // RV64I Memory Operation Tests

    #[test]
    fn test_ld_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.ld(RiscRegister::X1, RiscRegister::X0, 0);
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0xDEADBEEFCAFEBABE));

        run_test_with_memory_64(backend, &[(0, 0xDEADBEEFCAFEBABE)]);
    }

    #[test]
    fn test_ld_with_offset() {
        let mut backend = new_backend();

        backend.start_instr();
        // Load base address 8 into X2
        backend.add(RiscRegister::X2, RiscOperand::Immediate(8), RiscOperand::Immediate(0));
        // Load doubleword from address X2 + 8 (= 16)
        backend.ld(RiscRegister::X1, RiscRegister::X2, 8);
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0x1234567890ABCDEF));

        run_test_with_memory_64(backend, &[(16, 0x1234567890ABCDEF)]);
    }

    #[test]
    fn test_sd_immediate() {
        let mut backend = new_backend();

        backend.start_instr();
        // Store value 0xFEDCBA9876543210 to address 0
        backend.add(
            RiscRegister::X1,
            RiscOperand::Immediate(0xFEDCBA98u32 as i32),
            RiscOperand::Immediate(0),
        );
        backend.sll(
            RiscRegister::X1,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Immediate(32),
        );
        backend.add(
            RiscRegister::X1,
            RiscOperand::Register(RiscRegister::X1),
            RiscOperand::Immediate(0x76543210u32 as i32),
        );
        backend.sd(RiscRegister::X0, RiscRegister::X1, 0);

        run_test_and_check_memory(backend, |memory| {
            let val = memory[0];
            assert_eq!(val, 0xFEDCBA9876543210);
        });
    }

    #[test]
    fn test_sd_with_offset() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set base address to 8
        backend.add(RiscRegister::X2, RiscOperand::Immediate(8), RiscOperand::Immediate(0));
        // Store value to address X2 + 16 (= 24)
        backend.add(
            RiscRegister::X1,
            RiscOperand::Immediate(0x12345678),
            RiscOperand::Immediate(0x12345678),
        );
        backend.sd(RiscRegister::X2, RiscRegister::X1, 16);

        run_test_and_check_memory(backend, |memory| {
            let val = memory[3];
            assert_eq!(val, 0x12345678 + 0x12345678);
        });
    }

    #[test]
    fn test_lwu_zero_extension() {
        let mut backend = new_backend();

        backend.start_instr();
        // LWU loads 32-bit value and zero-extends to 64 bits
        backend.lwu(RiscRegister::X1, RiscRegister::X0, 0);
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0x00000000FFFFFFFF));

        run_test_with_memory(backend, &[(0, 0xFFFFFFFF)]);
    }

    #[test]
    fn test_lwu_with_offset() {
        let mut backend = new_backend();

        backend.start_instr();
        // Set base address
        backend.add(RiscRegister::X2, RiscOperand::Immediate(4), RiscOperand::Immediate(0));
        // Load unsigned word from X2 + 4 (= 8)
        backend.lwu(RiscRegister::X1, RiscRegister::X2, 4);
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0x0000000080000000));

        run_test_with_memory(backend, &[(8, 0x80000000)]);
    }

    #[test]
    fn test_lwu_vs_lw_sign_extension() {
        let mut backend = new_backend();

        backend.start_instr();
        // LW sign-extends negative values
        backend.lw(RiscRegister::X1, RiscRegister::X0, 0);
        backend.inspect_register(RiscRegister::X1, assert_register_is!(0xFFFFFFFF80000000));

        // LWU zero-extends the same value
        backend.lwu(RiscRegister::X2, RiscRegister::X0, 0);
        backend.inspect_register(RiscRegister::X2, assert_register_is!(0x0000000080000000));

        run_test_with_memory(backend, &[(0, 0x80000000)]);
    }
}

mod dirty_pages {
    use crate::{
        memory::AnonymousMemory, trace_capacity, ComputeInstructions, MemoryInstructions,
        RiscOperand, RiscRegister, RiscvTranspiler, TranspilerBackend, MERKLE_PAGE_WORDS,
    };
    use memmap2::MmapMut;

    /// Byte size of one merkle page (B × 8).
    const PAGE_BYTES: u64 = (MERKLE_PAGE_WORDS * 8) as u64;

    /// The JIT lays out memory as `[u64]` (8 bytes per RISC-V word), so the raw buffer
    /// size is `num_pages × PAGE_BYTES + slack`.
    fn new_backend_multipage(num_pages: usize) -> TranspilerBackend {
        let memory_size = num_pages * MERKLE_PAGE_WORDS * 8 + 16;
        TranspilerBackend::new(0, memory_size, 10_000, 100, 100).unwrap()
    }

    fn finalize_and_run(assembler: TranspilerBackend) -> crate::JitFunction<AnonymousMemory> {
        let mut func = assembler.finalize::<AnonymousMemory>().expect("finalize");
        let mut trace_buf = MmapMut::map_anon(trace_capacity(Some(10_000))).expect("trace buf");
        let ptr = trace_buf.as_mut_ptr();
        unsafe { func.call(ptr) };
        func
    }

    /// Read back the 32-bit little-endian word that the JIT wrote at RISC-V byte address
    /// `byte_addr`. Layout: the JIT memory buffer holds one `u64` per RISC-V word, so
    /// the raw byte offset equals `byte_addr`.
    fn read_mem_u32(func: &crate::JitFunction<AnonymousMemory>, byte_addr: u64) -> u32 {
        assert!(byte_addr.is_multiple_of(4));
        let raw = &*func.memory;
        let off = byte_addr as usize;
        u32::from_le_bytes(raw[off..off + 4].try_into().unwrap())
    }

    /// Load `value` into register `reg` in a single standalone instruction.
    fn load_imm(backend: &mut TranspilerBackend, reg: RiscRegister, value: i32) {
        backend.start_instr();
        backend.add(reg, RiscOperand::Immediate(value), RiscOperand::Immediate(0));
        backend.end_instr();
    }

    /// Emit a `sw rs2, imm(rs1)` as a standalone instruction.
    fn emit_sw(backend: &mut TranspilerBackend, rs1: RiscRegister, rs2: RiscRegister, imm: u64) {
        backend.start_instr();
        backend.sw(rs1, rs2, imm);
        backend.end_instr();
    }

    /// Writes to two distinct pages with duplicates in between should record exactly those
    /// two page_ids in first-touch order; the value written must also land in memory.
    #[test]
    fn sw_records_first_write_per_page() {
        let mut backend = new_backend_multipage(4);
        load_imm(&mut backend, RiscRegister::X1, 0x42);

        emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, 0); // page 0
        emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, 8); // page 0 again
        emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, PAGE_BYTES); // page 1
        backend.start_instr();
        backend.sw(RiscRegister::X0, RiscRegister::X1, 16); // page 0, third time

        let func = finalize_and_run(backend);

        assert_eq!(func.dirty.list_slice(), vec![0, 1]);
        assert_eq!(read_mem_u32(&func, 0), 0x42);
        assert_eq!(read_mem_u32(&func, 8), 0x42);
        assert_eq!(read_mem_u32(&func, 16), 0x42);
        assert_eq!(read_mem_u32(&func, PAGE_BYTES), 0x42);
    }

    /// Many distinct pages, touched in sequential order. Verifies the tracker scales past
    /// a handful of entries and that the JIT store preserves enough register state that
    /// every write lands correctly.
    #[test]
    fn sw_eight_distinct_pages_in_order() {
        let num_pages = 8;
        let mut backend = new_backend_multipage(num_pages);

        // Use a different sentinel per page to confirm the right value hits the right page.
        for page in 0..num_pages {
            let reg = match page {
                0 => RiscRegister::X1,
                1 => RiscRegister::X2,
                2 => RiscRegister::X3,
                3 => RiscRegister::X4,
                4 => RiscRegister::X5,
                5 => RiscRegister::X6,
                6 => RiscRegister::X7,
                _ => RiscRegister::X8,
            };
            load_imm(&mut backend, reg, 0x1000 + page as i32);
            emit_sw(&mut backend, RiscRegister::X0, reg, page as u64 * PAGE_BYTES);
        }

        let func = finalize_and_run(backend);

        let expected: Vec<u32> = (0..num_pages as u32).collect();
        assert_eq!(func.dirty.list_slice(), expected);
        for page in 0..num_pages {
            assert_eq!(
                read_mem_u32(&func, page as u64 * PAGE_BYTES),
                0x1000 + page as u32,
                "wrong value at page {page}",
            );
        }
    }

    /// Many writes fully within a single page at various offsets. The dirty list should
    /// have exactly one entry; every write must land.
    #[test]
    fn sw_many_offsets_within_one_page() {
        let mut backend = new_backend_multipage(1);
        load_imm(&mut backend, RiscRegister::X1, 0xAAAA);

        // Hit every 8-byte slot in page 0: 0, 8, 16, ..., PAGE_BYTES - 8.
        let offsets: Vec<u64> = (0..(PAGE_BYTES / 8)).map(|i| i * 8).collect();
        for &off in &offsets {
            emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, off);
        }

        let func = finalize_and_run(backend);

        assert_eq!(func.dirty.list_slice(), vec![0]);
        for off in offsets {
            assert_eq!(read_mem_u32(&func, off), 0xAAAA, "miss at offset {off}");
        }
    }

    /// Interleaved writes: visit pages in a non-monotonic order with repeats. The list must
    /// be first-touch-order and deduped (except across forced hash collisions, which this
    /// test avoids by keeping page_ids small).
    #[test]
    fn sw_interleaved_pages_ordered_by_first_touch() {
        let mut backend = new_backend_multipage(5);
        load_imm(&mut backend, RiscRegister::X1, 0x5555);

        // Sequence: page 3, page 1, page 3 (dup), page 4, page 0, page 1 (dup), page 2,
        //           page 0 (dup), page 4 (dup).
        let sequence: &[u64] = &[3, 1, 3, 4, 0, 1, 2, 0, 4];
        for &page in sequence {
            emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, page * PAGE_BYTES);
        }

        let func = finalize_and_run(backend);
        assert_eq!(func.dirty.list_slice(), vec![3, 1, 4, 0, 2]);

        // All final contents must be 0x5555 even though each page was visited multiple times.
        for page in [0u64, 1, 2, 3, 4] {
            assert_eq!(read_mem_u32(&func, page * PAGE_BYTES), 0x5555);
        }
    }

    /// The direct-mapped hash table resolves collisions by overwriting the slot and
    /// pushing the new page_id. To exercise that path without needing >256 MB of memory,
    /// pre-populate the slot that page 0 hashes to with a spurious page_id. The JIT must
    /// detect the mismatch, treat the write as a fresh dirty, and update the slot.
    /// With a bitset there are no hash-table collisions — a page's bit is definitive.
    /// This test verifies the hot path fires when the bit is already set (simulating an
    /// earlier touch without having to engineer a specific page-id hash).
    #[test]
    fn hot_path_fires_when_bit_already_set() {
        let mut backend = new_backend_multipage(1);
        load_imm(&mut backend, RiscRegister::X1, 0x1234);
        emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, 0);

        let mut func = backend.finalize::<AnonymousMemory>().expect("finalize");

        // Pre-set page 0's bit. The JIT hot path should see bit set, skip the cold path
        // (so page 0 does NOT appear in the list), and the store itself still lands.
        func.dirty.bitset[0] |= 1u64;

        let mut trace_buf = MmapMut::map_anon(trace_capacity(Some(10_000))).expect("trace buf");
        unsafe { func.call(trace_buf.as_mut_ptr()) };

        assert_eq!(func.dirty.list_len, 0);
        assert_eq!(read_mem_u32(&func, 0), 0x1234);
    }

    /// After writing and then resetting, the tracker must look as if brand-new.
    #[test]
    fn tracker_reset_between_chunks() {
        let mut backend = new_backend_multipage(2);
        load_imm(&mut backend, RiscRegister::X1, 0xCAFE);
        emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, 0);

        let mut func = finalize_and_run(backend);
        assert_eq!(func.dirty.list_slice(), vec![0]);

        func.dirty.reset();
        assert!(func.dirty.list_len == 0);
        assert!(func.dirty.bitset.iter().all(|&w| w == 0));
    }

    /// Seed the 8-byte value at `byte_addr` in the JIT's raw memory before execution.
    fn seed_u64(func: &mut crate::JitFunction<AnonymousMemory>, byte_addr: u64, val: u64) {
        assert!(byte_addr.is_multiple_of(8));
        let off = byte_addr as usize;
        func.memory[off..off + 8].copy_from_slice(&val.to_le_bytes());
    }

    /// `emit_dirty_pages` must return the chunk-END contents of each touched page by
    /// reading them directly from JIT memory at emit time.
    #[test]
    fn emit_captures_final_contents() {
        let mut backend = new_backend_multipage(1);
        load_imm(&mut backend, RiscRegister::X1, 0x999);

        // Store 0x999 (32-bit) at address 0. Only the low 32 bits of word 0 are affected.
        backend.start_instr();
        backend.sw(RiscRegister::X0, RiscRegister::X1, 0);

        let mut func = backend.finalize::<AnonymousMemory>().expect("finalize");

        // Seed page 0 with distinct values per word so we can tell which word is which.
        for i in 0..MERKLE_PAGE_WORDS {
            seed_u64(&mut func, (i * 8) as u64, 0x1_0000 + i as u64);
        }

        let mut trace_buf = MmapMut::map_anon(trace_capacity(Some(10_000))).expect("trace buf");
        unsafe { func.call(trace_buf.as_mut_ptr()) };

        let dirty = func.emit_dirty_pages();
        assert_eq!(dirty.pages.len(), 1);
        let page = &dirty.pages[0];
        assert_eq!(page.page_id, 0);

        // Final contents: word 0's low 32 bits = 0x999, high 32 bits untouched (= high 32
        // bits of the seed, which is 0). All other words unchanged.
        assert_eq!(page.final_contents[0], 0x999);
        for i in 1..MERKLE_PAGE_WORDS {
            assert_eq!(page.final_contents[i], 0x1_0000 + i as u64, "final[{i}]",);
        }
    }

    /// `emit_dirty_pages` must leave the tracker in the post-`reset` state so the next
    /// chunk starts clean.
    #[test]
    fn emit_dirty_pages_resets_tracker() {
        let mut backend = new_backend_multipage(1);
        load_imm(&mut backend, RiscRegister::X1, 0x1234);
        emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, 0);

        let mut func = finalize_and_run(backend);
        assert_eq!(func.dirty.list_slice(), vec![0]);

        let dirty = func.emit_dirty_pages();
        assert_eq!(dirty.pages.len(), 1);

        assert!(func.dirty.list_len == 0);
        assert!(func.dirty.bitset.iter().all(|&w| w == 0));
    }

    /// Read-only pages (`lw` without any corresponding `sw`) must appear in the output,
    /// with final contents matching the seeded value (unchanged by the read).
    #[test]
    fn read_only_page_final_contents_equal_seed() {
        let mut backend = new_backend_multipage(1);

        backend.start_instr();
        backend.lw(RiscRegister::X1, RiscRegister::X0, 0);

        let mut func = backend.finalize::<AnonymousMemory>().expect("finalize");
        for i in 0..MERKLE_PAGE_WORDS {
            seed_u64(&mut func, (i * 8) as u64, 0x2_0000 + i as u64);
        }

        let mut trace_buf = MmapMut::map_anon(trace_capacity(Some(10_000))).expect("buf");
        unsafe { func.call(trace_buf.as_mut_ptr()) };

        let dirty = func.emit_dirty_pages();
        assert_eq!(dirty.pages.len(), 1);
        let page = &dirty.pages[0];

        for i in 0..MERKLE_PAGE_WORDS {
            assert_eq!(page.final_contents[i], 0x2_0000 + i as u64);
        }
    }

    /// A load (`lw`) from a fresh page must also record it as touched, since the prover
    /// needs the page's initial contents to verify the read against its merkle leaf.
    #[test]
    fn lw_records_touched_page() {
        let mut backend = new_backend_multipage(2);

        // Seed memory: RISC-V word at address 0 = 0xDEADBEEF, word at PAGE_BYTES = 0x12345.
        // (run_test_with_memory style: write into the raw buffer before execution.)
        backend.start_instr();
        backend.lw(RiscRegister::X1, RiscRegister::X0, 0);
        backend.end_instr();

        backend.start_instr();
        backend.lw(RiscRegister::X2, RiscRegister::X0, PAGE_BYTES);

        let mut func = backend.finalize::<AnonymousMemory>().expect("finalize");
        // Seed non-zero values into the two pages we'll load from.
        let seed = |func: &mut crate::JitFunction<AnonymousMemory>, byte_addr: u64, val: u32| {
            let off = byte_addr as usize;
            func.memory[off..off + 4].copy_from_slice(&val.to_le_bytes());
        };
        seed(&mut func, 0, 0xDEADBEEF);
        seed(&mut func, PAGE_BYTES, 0x12345);

        let mut trace_buf = MmapMut::map_anon(trace_capacity(Some(10_000))).expect("trace buf");
        let ptr = trace_buf.as_mut_ptr();
        unsafe { func.call(ptr) };

        assert_eq!(func.dirty.list_slice(), vec![0, 1]);
    }

    /// `sd` (aligned 8-byte store) must also mark the page — it uses a different code path
    /// than the misaligned stores (no `rax` intra-word offset).
    #[test]
    fn sd_records_touched_page() {
        let mut backend = new_backend_multipage(2);
        load_imm(&mut backend, RiscRegister::X1, 0x1234);

        backend.start_instr();
        backend.sd(RiscRegister::X0, RiscRegister::X1, 0);
        backend.end_instr();

        backend.start_instr();
        backend.sd(RiscRegister::X0, RiscRegister::X1, PAGE_BYTES);

        let func = finalize_and_run(backend);
        assert_eq!(func.dirty.list_slice(), vec![0, 1]);
    }

    /// `sb` and `sh` touch a specific intra-word position; the dirty-page check must
    /// preserve `rax` (intra-word offset) so the store itself still lands correctly.
    #[test]
    fn sb_and_sh_still_land_correctly_with_dirty_check() {
        let mut backend = new_backend_multipage(1);
        load_imm(&mut backend, RiscRegister::X1, 0xAB);
        load_imm(&mut backend, RiscRegister::X2, 0x1234);

        // sb at byte offset 3 of word 0 → touches page 0 at intra-word offset 3.
        backend.start_instr();
        backend.sb(RiscRegister::X0, RiscRegister::X1, 3);
        backend.end_instr();

        // sh at byte offset 8 (word 1) → touches page 0 at aligned offset.
        backend.start_instr();
        backend.sh(RiscRegister::X0, RiscRegister::X2, 8);

        let func = finalize_and_run(backend);

        assert_eq!(func.dirty.list_slice(), vec![0]);

        // Verify the byte store landed at offset 3 of word 0.
        let mem = &*func.memory;
        let word0_off = 0;
        assert_eq!(mem[word0_off + 3], 0xAB, "sb value at byte offset 3");

        // Verify the halfword store landed at the start of word 1.
        let word1_off = 8;
        assert_eq!(
            u16::from_le_bytes(mem[word1_off..word1_off + 2].try_into().unwrap()),
            0x1234,
            "sh value at word 1",
        );
    }

    /// After `emit_dirty_pages` + `JitFunction::reset`, a second run of the same program
    /// on the same `JitFunction` must produce a fresh, independent dirty set — no
    /// carry-over from the first run's tracking state.
    #[test]
    fn second_run_after_reset_has_fresh_tracking() {
        let mut backend = new_backend_multipage(2);
        load_imm(&mut backend, RiscRegister::X1, 0x1234);
        load_imm(&mut backend, RiscRegister::X2, 0x5678);
        emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, 0);
        backend.start_instr();
        backend.sw(RiscRegister::X0, RiscRegister::X2, PAGE_BYTES);

        let mut func = backend.finalize::<AnonymousMemory>().expect("finalize");

        // --- Run 1 ---
        let mut buf1 = MmapMut::map_anon(trace_capacity(Some(10_000))).expect("buf1");
        unsafe { func.call(buf1.as_mut_ptr()) };
        let d1 = func.emit_dirty_pages();

        assert_eq!(d1.pages.len(), 2);
        let pages1: std::collections::HashSet<u32> = d1.pages.iter().map(|p| p.page_id).collect();
        assert!(pages1.contains(&0));
        assert!(pages1.contains(&1));

        // --- Reset memory + state. Tracker was already reset by emit_dirty_pages. ---
        func.reset();
        assert!(func.dirty.list_len == 0);
        assert!(func.dirty.bitset.iter().all(|&w| w == 0));

        // --- Run 2 ---
        let mut buf2 = MmapMut::map_anon(trace_capacity(Some(10_000))).expect("buf2");
        unsafe { func.call(buf2.as_mut_ptr()) };
        let d2 = func.emit_dirty_pages();

        assert_eq!(d2.pages.len(), 2);
        let pages2: std::collections::HashSet<u32> = d2.pages.iter().map(|p| p.page_id).collect();
        assert!(pages2.contains(&0));
        assert!(pages2.contains(&1));
    }

    /// For every page_id in the list, its bit in the bitset must be set. Conversely, no
    /// bit should be set for a page_id that isn't in the list.
    #[test]
    fn bitset_matches_list() {
        let mut backend = new_backend_multipage(6);
        load_imm(&mut backend, RiscRegister::X1, 0);

        for page in [0u64, 2, 5, 3] {
            emit_sw(&mut backend, RiscRegister::X0, RiscRegister::X1, page * PAGE_BYTES);
        }

        let func = finalize_and_run(backend);

        let in_list: std::collections::HashSet<u32> =
            func.dirty.list_slice().iter().copied().collect();

        // Forward: every list entry has its bit set.
        for &page_id in func.dirty.list_slice() {
            let qword = (page_id / 64) as usize;
            let bit = 1u64 << (page_id % 64);
            assert_eq!(
                func.dirty.bitset[qword] & bit,
                bit,
                "list had page_id {page_id} but its bit is not set",
            );
        }

        // Reverse: iterate the low part of the bitset that could cover our pages and
        // verify any set bit corresponds to a list entry. (Pages 0..6 means qword 0 only.)
        let word0 = func.dirty.bitset[0];
        for bit in 0..64u32 {
            if word0 & (1u64 << bit) != 0 {
                assert!(
                    in_list.contains(&bit),
                    "bit {bit} is set but page_id {bit} isn't in the list",
                );
            }
        }
    }
}

mod infra {
    use super::*;

    #[test]
    fn test_assert_base_registrs_are_loaded() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.inspect_register(RiscRegister::X5, assert_register_is!(5));

        let mut func = backend.finalize().expect("Failed to finalize function");
        func.registers[5] = 5;

        run_func(&mut func);
    }

    #[test]
    fn test_assert_registers_are_persisted_on_exit() {
        let mut backend = new_backend();

        backend.start_instr();
        backend.add(RiscRegister::X1, RiscOperand::Immediate(5), RiscOperand::Immediate(0));

        let mut func = backend.finalize().expect("Failed to finalize function");
        run_func(&mut func);

        assert_eq!(func.registers[1], 5);
    }
}

mod trace {
    use crate::{MemValue, TraceCollector};

    use super::*;

    #[test]
    fn test_basic_trace() {
        let mut backend = new_backend();

        extern "C" fn some_precompile(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            unsafe {
                ctx.trace_mem_access(&[
                    MemValue { clk: 5, value: 15 },
                    MemValue { clk: 10, value: 20 },
                ])
            };
        }

        backend.start_instr();

        // Do a store into addr = 0, and trace it.
        backend.add(RiscRegister::X1, RiscOperand::Immediate(5), RiscOperand::Immediate(0));
        backend.sw(RiscRegister::X0, RiscRegister::X1, 0);
        backend.trace_mem_value(RiscRegister::X0, 0);

        // Do a store into addr = 8, and trace it.
        backend.add(RiscRegister::X2, RiscOperand::Immediate(10), RiscOperand::Immediate(0));
        backend.sw(RiscRegister::X0, RiscRegister::X2, 8);

        // Bump the clk by 8.
        backend.bump_clk();
        backend.trace_mem_value(RiscRegister::X0, 8);
        // The last trace call should have bumped the clk by 8.
        backend.trace_mem_value(RiscRegister::X0, 8);

        backend.call_extern_fn(some_precompile);

        backend.bump_pc(3);
        backend.trace_registers();
        backend.trace_pc_start();

        let mut func = backend.finalize().expect("Failed to finalize function");
        let trace = run_func(&mut func).expect("No trace returned");

        let registers = trace.start_registers();
        let pc = trace.pc_start();
        let mem_reads = trace.num_mem_reads();

        // let trace = TraceChunk::copy_from_bytes(&trace);
        assert_eq!(registers[1], 5);
        assert_eq!(registers[2], 10);
        assert_eq!(pc, 103);
        assert_eq!(mem_reads, 5);

        let mem_reads = trace.mem_reads().collect::<Vec<_>>();

        // Check the values.
        assert_eq!(mem_reads[0].value, 5);
        assert_eq!(mem_reads[1].value, 10);
        assert_eq!(mem_reads[2].value, 10);
        assert_eq!(mem_reads[3].value, 15);
        assert_eq!(mem_reads[4].value, 20);

        // Check the clks. No-clk MinimalExecutor leaves the clk slot of
        // `trace_mem_value`-written entries untouched (initial zero on a fresh
        // trace mmap); SplicingVM is expected to backfill it per-chunk.
        // Precompile-emitted entries still carry their explicit clk values.
        assert_eq!(mem_reads[0].clk, 0);
        assert_eq!(mem_reads[1].clk, 0);
        assert_eq!(mem_reads[2].clk, 0);
        assert_eq!(mem_reads[3].clk, 5);
        assert_eq!(mem_reads[4].clk, 10);
    }
}
