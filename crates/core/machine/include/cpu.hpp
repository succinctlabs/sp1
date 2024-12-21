#pragma once

#include <cassert>
#include <cstdlib>

#include "memory.hpp"
#include "prelude.hpp"
#include "utils.hpp"

// namespace sp1_core_machine_sys::cpu {

// template<class F>
// __SP1_HOSTDEV__ void populate_shard_clk(const CpuEventFfi& event, CpuCols<decltype(F::val)>& cols) {
//     // cols.shard = F::from_canonical_u32(event.shard).val;
//     // cols.clk = F::from_canonical_u32(event.clk).val;

//     // const uint16_t clk_16bit_limb = (uint16_t)event.clk;
//     // const uint8_t clk_8bit_limb = (uint8_t)(event.clk >> 16);
//     // cols.clk_16bit_limb = F::from_canonical_u16(clk_16bit_limb).val;
//     // cols.clk_8bit_limb = F::from_canonical_u8(clk_8bit_limb).val;

//     // blu_events.add_byte_lookup_event(ByteLookupEvent::new(
//     //     event.shard,
//     //     U16Range,
//     //     event.shard as u16,
//     //     0,
//     //     0,
//     //     0,
//     // ));
//     // blu_events.add_byte_lookup_event(ByteLookupEvent::new(
//     //     event.shard,
//     //     U16Range,
//     //     clk_16bit_limb,
//     //     0,
//     //     0,
//     //     0,
//     // ));
//     // blu_events.add_byte_lookup_event(ByteLookupEvent::new(
//     //     event.shard,
//     //     ByteOpcode::U8Range,
//     //     0,
//     //     0,
//     //     0,
//     //     clk_8bit_limb as u8,
//     // ));
// }

// // template<class F>
// // __SP1_HOSTDEV__ void
// // instruction_populate(InstructionCols<decltype(F::val)>& self, const Instruction& instruction) {
// //     self.opcode = F::from_canonical_u32((uint32_t)instruction.opcode).val;
// //     write_word_from_u32<F>(self.op_a, instruction.op_a);
// //     write_word_from_u32<F>(self.op_b, instruction.op_b);
// //     write_word_from_u32<F>(self.op_c, instruction.op_c);

// //     self.op_a_0 = F::from_bool(instruction.op_a == 0).val;  // 0 = Register::X0
// // }

// // template<class F>
// // __SP1_HOSTDEV__ void
// // selectors_populate(OpcodeSelectorCols<decltype(F::val)>& self, const Instruction& instruction) {
// //     self.imm_b = F::from_bool(instruction.imm_b).val;
// //     self.imm_c = F::from_bool(instruction.imm_c).val;

// //     switch (instruction.opcode) {
// //         // Corresponds to `instruction.is_alu_instruction()` in Rust.
// //         case Opcode::ADD:
// //         case Opcode::SUB:
// //         case Opcode::XOR:
// //         case Opcode::OR:
// //         case Opcode::AND:
// //         case Opcode::SLL:
// //         case Opcode::SRL:
// //         case Opcode::SRA:
// //         case Opcode::SLT:
// //         case Opcode::SLTU:
// //         case Opcode::MUL:
// //         case Opcode::MULH:
// //         case Opcode::MULHU:
// //         case Opcode::MULHSU:
// //         case Opcode::DIV:
// //         case Opcode::DIVU:
// //         case Opcode::REM:
// //         case Opcode::REMU:
// //             self.is_alu = F::one().val;
// //             break;
// //         // Corresponds to `instruction.is_ecall_instruction()` in Rust.
// //         case Opcode::ECALL:
// //             self.is_ecall = F::one().val;
// //             break;
// //         // Cleaner version of the `instruction.is_memory_instruction()` branch from Rust.
// //         case Opcode::LB:
// //             self.is_lb = F::one().val;
// //             break;
// //         case Opcode::LBU:
// //             self.is_lbu = F::one().val;
// //             break;
// //         case Opcode::LHU:
// //             self.is_lhu = F::one().val;
// //             break;
// //         case Opcode::LH:
// //             self.is_lh = F::one().val;
// //             break;
// //         case Opcode::LW:
// //             self.is_lw = F::one().val;
// //             break;
// //         case Opcode::SB:
// //             self.is_sb = F::one().val;
// //             break;
// //         case Opcode::SH:
// //             self.is_sh = F::one().val;
// //             break;
// //         case Opcode::SW:
// //             self.is_sw = F::one().val;
// //             break;
// //         // Cleaner version of the `instruction.is_branch_instruction()` branch from Rust.
// //         case Opcode::BEQ:
// //             self.is_beq = F::one().val;
// //             break;
// //         case Opcode::BNE:
// //             self.is_bne = F::one().val;
// //             break;
// //         case Opcode::BLT:
// //             self.is_blt = F::one().val;
// //             break;
// //         case Opcode::BGE:
// //             self.is_bge = F::one().val;
// //             break;
// //         case Opcode::BLTU:
// //             self.is_bltu = F::one().val;
// //             break;
// //         case Opcode::BGEU:
// //             self.is_bgeu = F::one().val;
// //             break;
// //         // Opcodes which each have their own branch in the original Rust function.
// //         case Opcode::JAL:
// //             self.is_jal = F::one().val;
// //             break;
// //         case Opcode::JALR:
// //             self.is_jalr = F::one().val;
// //             break;
// //         case Opcode::AUIPC:
// //             self.is_auipc = F::one().val;
// //             break;
// //         case Opcode::UNIMP:
// //             self.is_unimpl = F::one().val;
// //             break;
// //         default:
// //             break;
// //     }
// // }

// // template<class F>
// // __SP1_HOSTDEV__ void
// // babybear_word_populate(BabyBearWordRangeChecker<decltype(F::val)>& self, uint32_t value) {
// //     for (uintptr_t i = 0; i < BYTE_SIZE; ++i) {
// //         self.most_sig_byte_decomp[i] = F::from_bool((value & (1 << (i + 24))) != 0).val;
// //     }
// //     self.and_most_sig_byte_decomp_3_to_5 =
// //         F::from_bool(self.most_sig_byte_decomp[3] != 0 && self.most_sig_byte_decomp[4] != 0).val;
// //     self.and_most_sig_byte_decomp_3_to_6 =
// //         F::from_bool(self.and_most_sig_byte_decomp_3_to_5 != 0 && self.most_sig_byte_decomp[5] != 0)
// //             .val;
// //     self.and_most_sig_byte_decomp_3_to_7 =
// //         F::from_bool(self.and_most_sig_byte_decomp_3_to_6 != 0 && self.most_sig_byte_decomp[6] != 0)
// //             .val;
// // }

// // template<class F>
// // __SP1_HOSTDEV__ void populate_memory(CpuCols<decltype(F::val)>& cols, const CpuEventFfi& event) {
// //     // Populate addr_word and addr_aligned columns.
// //     MemoryColumns<decltype(F::val)>& memory_columns = cols.opcode_specific_columns.memory;
// //     // Wraps because the types involved are unsigned integers.
// //     const uint32_t memory_addr = event.b + event.c;
// //     const uint32_t aligned_addr = memory_addr - (memory_addr % (uint32_t)WORD_SIZE);
// //     write_word_from_u32<F>(memory_columns.addr_word, memory_addr);
// //     babybear_word_populate<F>(memory_columns.addr_word_range_checker, memory_addr);
// //     memory_columns.addr_aligned = F::from_canonical_u32(aligned_addr).val;

// //     // Populate the aa_least_sig_byte_decomp columns.
// //     // assert(aligned_addr % 4 == 0);
// //     const uint8_t aligned_addr_ls_byte = (uint8_t)aligned_addr;
// //     for (uintptr_t i = 0; i < 6; ++i) {
// //         memory_columns.aa_least_sig_byte_decomp[i] =
// //             F::from_bool((aligned_addr_ls_byte & (1 << (i + 2))) != 0).val;
// //     }
// //     memory_columns.addr_word_nonce = F::from_canonical_u32(event.memory_add_nonce).val;

// //     // // Populate memory offsets.
// //     const uint8_t addr_offset = (uint8_t)(memory_addr % (uint32_t)WORD_SIZE);
// //     memory_columns.addr_offset = F::from_canonical_u8(addr_offset).val;
// //     memory_columns.offset_is_one = F::from_bool(addr_offset == 1).val;
// //     memory_columns.offset_is_two = F::from_bool(addr_offset == 2).val;
// //     memory_columns.offset_is_three = F::from_bool(addr_offset == 3).val;

// //     // If it is a load instruction, set the unsigned_mem_val column.
// //     const uint32_t mem_value = memory::unwrap_value(event.memory_record);

// //     // // Add event to byte lookup for byte range checking each byte in the memory addr
// //     // let addr_bytes = memory_addr.to_le_bytes();
// //     // for byte_pair in addr_bytes.chunks_exact(2) {
// //     //     blu_events.add_byte_lookup_event(ByteLookupEvent {
// //     //         shard: event.shard,
// //     //         opcode: ByteOpcode::U8Range,
// //     //         a1: 0,
// //     //         a2: 0,
// //     //         b: byte_pair[0],
// //     //         c: byte_pair[1],
// //     //     });
// //     // }

// //     uint32_t unsigned_mem_val = mem_value;
// //     switch (event.instruction.opcode) {
// //         case Opcode::LB:
// //         case Opcode::LBU:
// //             unsigned_mem_val = (uint32_t)(uint8_t)(mem_value >> 8 * addr_offset);
// //             break;
// //         case Opcode::LH:
// //         case Opcode::LHU:
// //             unsigned_mem_val = ((addr_offset >> 1) & 0x1) == 0 ? (mem_value & 0x0000FFFF)
// //                                                                : (mem_value & 0xFFFF0000) >> 16;
// //             break;
// //         case Opcode::LW:
// //             // The value assigned at declaration is correct.
// //             break;
// //         default:
// //             return;
// //     }
// //     // Guard above ensures instruction is a load.
// //     write_word_from_u32<F>(cols.unsigned_mem_val, unsigned_mem_val);

// //     uint8_t most_sig_mem_value_byte;
// //     switch (event.instruction.opcode) {
// //         case Opcode::LB:

// //             most_sig_mem_value_byte = (uint8_t)unsigned_mem_val;
// //             break;
// //         case Opcode::LH:
// //             most_sig_mem_value_byte = (uint8_t)(unsigned_mem_val >> 8);
// //             break;
// //         default:
// //             // The load instruction is unsigned.
// //             // Set the `mem_value_is_pos_not_x0` composite flag.
// //             cols.mem_value_is_pos_not_x0 =
// //                 F::from_bool(event.instruction.op_a != 0).val;  // 0 = Register::X0
// //             return;
// //     }
// //     // Guard above ensures the load instruction is signed.
// //     for (intptr_t i = BYTE_SIZE - 1; i >= 0; --i) {
// //         memory_columns.most_sig_byte_decomp[i] =
// //             F::from_canonical_u32(most_sig_mem_value_byte >> i & 0x1).val;
// //     }
// //     bool mem_value_is_pos_not_x0 = memory_columns.most_sig_byte_decomp[7] == F::zero().val;
// //     if (!mem_value_is_pos_not_x0) {
// //         cols.mem_value_is_neg_not_x0 =
// //             F::from_bool(event.instruction.op_a != 0).val;  // 0 = Register::X0
// //         cols.unsigned_mem_val_nonce = F::from_canonical_u32(event.memory_sub_nonce).val;
// //     }
// //     // Set the `mem_value_is_pos_not_x0` composite flag.
// //     cols.mem_value_is_pos_not_x0 = F::from_bool(mem_value_is_pos_not_x0).val;
// // }

// // template<class F>
// // __SP1_HOSTDEV__ void populate_branch(CpuCols<decltype(F::val)>& cols, const CpuEventFfi& event) {
// //     // let branch_columns = cols.opcode_specific_columns.branch_mut();
// //     BranchCols<decltype(F::val)>& branch_columns = cols.opcode_specific_columns.branch;

// //     Opcode opcode = event.instruction.opcode;
// //     const bool use_signed_comparison = opcode == Opcode::BLT || opcode == Opcode::BGE;

// //     const bool a_eq_b = event.a == event.b;
// //     const bool a_lt_b =
// //         use_signed_comparison ? ((int32_t)event.a < (int32_t)event.b) : (event.a < event.b);
// //     const bool a_gt_b =
// //         use_signed_comparison ? ((int32_t)event.a > (int32_t)event.b) : (event.a > event.b);

// //     branch_columns.a_lt_b_nonce = F::from_canonical_u32(event.branch_lt_nonce).val;
// //     branch_columns.a_gt_b_nonce = F::from_canonical_u32(event.branch_gt_nonce).val;

// //     branch_columns.a_eq_b = F::from_bool(a_eq_b).val;
// //     branch_columns.a_lt_b = F::from_bool(a_lt_b).val;
// //     branch_columns.a_gt_b = F::from_bool(a_gt_b).val;

// //     bool branching;
// //     switch (opcode) {
// //         case Opcode::BEQ:
// //             branching = a_eq_b;
// //             break;
// //         case Opcode::BNE:
// //             branching = !a_eq_b;
// //             break;
// //         case Opcode::BLT:
// //         case Opcode::BLTU:
// //             branching = a_lt_b;
// //             break;
// //         case Opcode::BGE:
// //         case Opcode::BGEU:
// //             branching = a_eq_b || a_gt_b;
// //             break;
// //         default:
// //             // Precondition violated.
// //             assert(false);
// //             break;
// //     }

// //     // Unsigned arithmetic wraps.
// //     const uint32_t next_pc = event.pc + event.c;
// //     write_word_from_u32<F>(branch_columns.pc, event.pc);
// //     write_word_from_u32<F>(branch_columns.next_pc, next_pc);
// //     babybear_word_populate<F>(branch_columns.pc_range_checker, event.pc);
// //     babybear_word_populate<F>(branch_columns.next_pc_range_checker, next_pc);

// //     if (branching) {
// //         cols.branching = F::one().val;
// //         branch_columns.next_pc_nonce = F::from_canonical_u32(event.branch_add_nonce).val;
// //     } else {
// //         cols.not_branching = F::one().val;
// //     }
// // }

// // template<class F>
// // __SP1_HOSTDEV__ void populate_jump(CpuCols<decltype(F::val)>& cols, const CpuEventFfi& event) {
// //     // let jump_columns = cols.opcode_specific_columns.jump_mut();
// //     JumpCols<decltype(F::val)>& jump_columns = cols.opcode_specific_columns.jump;

// //     switch (event.instruction.opcode) {
// //         case Opcode::JAL: {
// //             // Unsigned arithmetic wraps.
// //             uint32_t next_pc = event.pc + event.b;
// //             babybear_word_populate<F>(jump_columns.op_a_range_checker, event.a);
// //             write_word_from_u32<F>(jump_columns.pc, event.pc);
// //             babybear_word_populate<F>(jump_columns.pc_range_checker, event.pc);
// //             write_word_from_u32<F>(jump_columns.next_pc, next_pc);
// //             babybear_word_populate<F>(jump_columns.next_pc_range_checker, next_pc);
// //             jump_columns.jal_nonce = F::from_canonical_u32(event.jump_jal_nonce).val;
// //             break;
// //         }
// //         case Opcode::JALR: {
// //             // Unsigned arithmetic wraps.
// //             uint32_t next_pc = event.b + event.c;
// //             babybear_word_populate<F>(jump_columns.op_a_range_checker, event.a);
// //             write_word_from_u32<F>(jump_columns.next_pc, next_pc);
// //             babybear_word_populate<F>(jump_columns.next_pc_range_checker, next_pc);
// //             jump_columns.jalr_nonce = F::from_canonical_u32(event.jump_jalr_nonce).val;
// //             break;
// //         }
// //         default:
// //             // Precondition violated.
// //             assert(false);
// //             break;
// //     }
// // }

// // template<class F>
// // __SP1_HOSTDEV__ void populate_auipc(CpuCols<decltype(F::val)>& cols, const CpuEventFfi& event) {
// //     AuipcCols<decltype(F::val)>& auipc_columns = cols.opcode_specific_columns.auipc;

// //     write_word_from_u32<F>(auipc_columns.pc, event.pc);
// //     babybear_word_populate<F>(auipc_columns.pc_range_checker, event.pc);
// //     auipc_columns.auipc_nonce = F::from_canonical_u32(event.auipc_nonce).val;
// // }

// // template<class F>
// // __SP1_HOSTDEV__ void
// // is_zero_operation_populate_from_field_element(IsZeroOperation<decltype(F::val)>& self, F a) {
// //     if (a == F::zero()) {
// //         self.inverse = F::zero().val;
// //         self.result = F::one().val;
// //     } else {
// //         self.inverse = a.reciprocal().val;
// //         self.result = F::zero().val;
// //     }
// //     // F is_zero = F::one() - F(self.inverse) * a;
// //     // assert(is_zero == F(self.result));
// //     // let is_zero = one.clone() - cols.inverse * a.clone();
// //     // builder.when(is_real.clone()).assert_eq(is_zero, cols.result);

// //     // let prod = self.inverse * a;
// //     // debug_assert!(prod == F::one() || prod == F::zero());
// //     // (a == F::zero()) as u32
// // }

// // template<class F>
// // __SP1_HOSTDEV__ bool populate_ecall(CpuCols<decltype(F::val)>& cols, const CpuEventFfi& event) {
// //     bool is_halt = false;

// //     // The send_to_table column is the 1st entry of the op_a_access column prev_value field.
// //     // Look at `ecall_eval` in cpu/air/mod.rs for the corresponding constraint and
// //     // explanation.
// //     EcallCols<decltype(F::val)>& ecall_cols = cols.opcode_specific_columns.ecall;

// //     cols.ecall_mul_send_to_table = cols.op_a_access.prev_value._0[1];

// //     F syscall_id = F(cols.op_a_access.prev_value._0[0]);

// //     // In the following statements, truncating to `uint8_t` is the equivalent of the
// //     // `SyscallCode::get_syscall_id` calls from the Rust code.

// //     // Populate `is_enter_unconstrained`.
// //     is_zero_operation_populate_from_field_element(
// //         ecall_cols.is_enter_unconstrained,
// //         syscall_id - F::from_canonical_u8((uint8_t)SyscallCode::ENTER_UNCONSTRAINED)
// //     );

// //     // Populate `is_hint_len`.
// //     is_zero_operation_populate_from_field_element(
// //         ecall_cols.is_hint_len,
// //         syscall_id - F::from_canonical_u8((uint8_t)SyscallCode::HINT_LEN)
// //     );

// //     // Populate `is_halt`.
// //     is_zero_operation_populate_from_field_element(
// //         ecall_cols.is_halt,
// //         syscall_id - F::from_canonical_u8((uint8_t)SyscallCode::HALT)
// //     );

// //     // Populate `is_commit`.
// //     is_zero_operation_populate_from_field_element(
// //         ecall_cols.is_commit,
// //         syscall_id - F::from_canonical_u8((uint8_t)SyscallCode::COMMIT)
// //     );

// //     // Populate `is_commit_deferred_proofs`.
// //     is_zero_operation_populate_from_field_element(
// //         ecall_cols.is_commit_deferred_proofs,
// //         syscall_id - F::from_canonical_u8((uint8_t)SyscallCode::COMMIT_DEFERRED_PROOFS)
// //     );

// //     // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and
// //     // digest word.
// //     if (syscall_id
// //             == F::from_canonical_u8((uint8_t)SyscallCode::COMMIT
// //             )  // Comment to make my editor format nicely...
// //         || syscall_id == F::from_canonical_u8((uint8_t)SyscallCode::COMMIT_DEFERRED_PROOFS)) {
// //         uint32_t digest_idx = word_to_u32<F>(cols.op_b_access.access.value);
// //         ecall_cols.index_bitmap[digest_idx] = F::one().val;
// //     }

// //     // Write the syscall nonce.
// //     ecall_cols.syscall_nonce = F::from_canonical_u32(event.syscall_nonce).val;

// //     is_halt = syscall_id == F::from_canonical_u32((uint8_t)SyscallCode::HALT);

// //     // For halt and commit deferred proofs syscalls, we need to baby bear range check one of
// //     // it's operands.
// //     if (is_halt) {
// //         write_word_from_u32<F>(ecall_cols.operand_to_check, event.b);
// //         babybear_word_populate<F>(ecall_cols.operand_range_check_cols, event.b);
// //         cols.ecall_range_check_operand = F::one().val;
// //     }

// //     if (syscall_id == F::from_canonical_u32((uint8_t)SyscallCode::COMMIT_DEFERRED_PROOFS)) {
// //         write_word_from_u32<F>(ecall_cols.operand_to_check, event.c);
// //         babybear_word_populate<F>(ecall_cols.operand_range_check_cols, event.c);
// //         cols.ecall_range_check_operand = F::one().val;
// //     }

// //     return is_halt;
// // }

// template<class F>
// __SP1_HOSTDEV__ void event_to_row(const CpuEventFfi& event, CpuCols<decltype(F::val)>& cols) {
//     // // Populate shard and clk columns.
//     // populate_shard_clk<F>(event, cols);

//     // // Populate the nonce.
//     // cols.nonce = F::from_canonical_u32(event.alu_nonce).val;

//     // // Populate basic fields.
//     // cols.pc = F::from_canonical_u32(event.pc).val;
//     // cols.next_pc = F::from_canonical_u32(event.next_pc).val;
//     // instruction_populate<F>(cols.instruction, event.instruction);
//     // // cols.instruction.populate(event.instruction);
//     // selectors_populate<F>(cols.selectors, event.instruction);
//     // // cols.selectors.populate(event.instruction);
//     // write_word_from_u32<F>(cols.op_a_access.access.value, event.a);
//     // write_word_from_u32<F>(cols.op_b_access.access.value, event.b);
//     // write_word_from_u32<F>(cols.op_c_access.access.value, event.c);

//     // // // Populate memory accesses for a, b, and c.
//     // // The function guards against the record being `None`.
//     // memory::populate_read_write<F>(cols.op_a_access, event.a_record);
//     // if (event.b_record.tag == OptionMemoryRecordEnum::Tag::Read) {
//     //     memory::populate_read<F>(cols.op_b_access, event.b_record.read._0);
//     // }
//     // if (event.c_record.tag == OptionMemoryRecordEnum::Tag::Read) {
//     //     memory::populate_read<F>(cols.op_c_access, event.c_record.read._0);
//     // }

//     // // // Populate range checks for a.
//     // // let a_bytes = cols
//     // //     .op_a_access
//     // //     .access
//     // //     .val
//     // //     .0
//     // //     .iter()
//     // //     .map(|x| x.as_canonical_u32())
//     // //     .collect::<Vec<_>>();
//     // // blu_events.add_byte_lookup_event(ByteLookupEvent {
//     // //     shard: event.shard,
//     // //     opcode: ByteOpcode::U8Range,
//     // //     a1: 0,
//     // //     a2: 0,
//     // //     b: a_bytes[0] as u8,
//     // //     c: a_bytes[1] as u8,
//     // // });
//     // // blu_events.add_byte_lookup_event(ByteLookupEvent {
//     // //     shard: event.shard,
//     // //     opcode: ByteOpcode::U8Range,
//     // //     a1: 0,
//     // //     a2: 0,
//     // //     b: a_bytes[2] as u8,
//     // //     c: a_bytes[3] as u8,
//     // // });

//     // // Populate memory accesses for reading from memory.
//     // // `event.memory` appears to be vestigial.
//     // // assert_eq!(event.memory_record.is_some(), event.memory.is_some());
//     // // The function guards against the record being `None`.
//     // memory::populate_read_write<F>(
//     //     cols.opcode_specific_columns.memory.memory_access,
//     //     event.memory_record
//     // );

//     // // Populate memory, branch, jump, and auipc specific fields.
//     // const bool is_memory = opcode_utils::is_memory(event.instruction.opcode);
//     // const bool is_branch = opcode_utils::is_branch(event.instruction.opcode);
//     // const bool is_jump = opcode_utils::is_jump(event.instruction.opcode);
//     // const bool is_auipc = event.instruction.opcode == Opcode::AUIPC;
//     // const bool is_ecall = event.instruction.opcode == Opcode::ECALL;
//     // // Calculated by `populate_ecall`, if called.
//     // bool is_halt = false;
//     // // Unlike the Rust code, we guard outside the function bodies so we can reuse the booleans.
//     // if (is_memory) {
//     //     populate_memory<F>(cols, event);
//     // }
//     // if (is_branch) {
//     //     populate_branch<F>(cols, event);
//     // }
//     // if (is_jump) {
//     //     populate_jump<F>(cols, event);
//     // }
//     // if (is_auipc) {
//     //     populate_auipc<F>(cols, event);
//     // }
//     // if (is_ecall) {
//     //     is_halt = populate_ecall<F>(cols, event);
//     // }

//     // cols.is_sequential_instr = F::from_bool(!(is_branch || is_jump || is_halt)).val;

//     // // Assert that the instruction is not a no-op.
//     // cols.is_real = F::one().val;
// }
// }  // namespace sp1::cpu