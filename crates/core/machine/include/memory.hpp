#pragma once

#include <cstdlib>

#include "prelude.hpp"
#include "utils.hpp"

// namespace sp1_core_machine_sys::memory {
// __SP1_HOSTDEV__ __SP1_INLINE__ uint32_t unwrap_value(const OptionMemoryRecordEnum& record) {
//     switch (record.tag) {
//         case OptionMemoryRecordEnum::Tag::Read:
//             return record.read._0.value;
//         case OptionMemoryRecordEnum::Tag::Write:
//             return record.write._0.value;
//         default:
//             // Either the tag is `None` or it is an invalid value.
//             assert(false);
//     }
//     // Unreachable.
//     return 0;
// }

// template<class F>
// __SP1_HOSTDEV__ void populate_access(
//     MemoryAccessCols<decltype(F::val)>& self,
//     const MemoryRecord& current_record,
//     const MemoryRecord& prev_record
// ) {
//     write_word_from_u32<F>(self.value, current_record.value);

//     self.prev_shard = F::from_canonical_u32(prev_record.shard).val;
//     self.prev_clk = F::from_canonical_u32(prev_record.timestamp).val;

//     // Fill columns used for verifying current memory access time value is greater than
//     // previous's.
//     const bool use_clk_comparison = prev_record.shard == current_record.shard;
//     self.compare_clk = F::from_bool(use_clk_comparison).val;
//     const uint32_t prev_time_value = use_clk_comparison ? prev_record.timestamp : prev_record.shard;
//     const uint32_t current_time_value =
//         use_clk_comparison ? current_record.timestamp : current_record.shard;

//     const uint32_t diff_minus_one = current_time_value - prev_time_value - 1;
//     const uint16_t diff_16bit_limb = (uint16_t)(diff_minus_one);
//     self.diff_16bit_limb = F::from_canonical_u16(diff_16bit_limb).val;
//     const uint8_t diff_8bit_limb = (uint8_t)(diff_minus_one >> 16);
//     self.diff_8bit_limb = F::from_canonical_u8(diff_8bit_limb).val;

//     // let shard = current_record.shard;

//     // // Add a byte table lookup with the 16Range op.
//     // output.add_u16_range_check(shard, diff_16bit_limb);

//     // // Add a byte table lookup with the U8Range op.
//     // output.add_u8_range_check(shard, 0, diff_8bit_limb as u8);
// }

// template<class F>
// __SP1_HOSTDEV__ void
// populate_read(MemoryReadCols<F>& self, const MemoryReadRecord& record) {
//     const MemoryRecord current_record = {
//         .shard = record.shard,
//         .timestamp = record.timestamp,
//         .value = record.value,
//     };
//     const MemoryRecord prev_record = {
//         .shard = record.prev_shard,
//         .timestamp = record.prev_timestamp,
//         .value = record.value,
//     };
//     populate_access<F>(self.access, current_record, prev_record);
// }

// template<class F>
// __SP1_HOSTDEV__ void populate_read_write(
//     MemoryReadWriteCols<decltype(F::val)>& self,
//     const OptionMemoryRecordEnum& record
// ) {
//     if (record.tag == OptionMemoryRecordEnum::Tag::None) {
//         return;
//     }
//     MemoryRecord current_record;
//     MemoryRecord prev_record;
//     switch (record.tag) {
//         case OptionMemoryRecordEnum::Tag::Read:
//             current_record = {
//                 .shard = record.read._0.shard,
//                 .timestamp = record.read._0.timestamp,
//                 .value = record.read._0.value,
//             };
//             prev_record = {
//                 .shard = record.read._0.prev_shard,
//                 .timestamp = record.read._0.prev_timestamp,
//                 .value = record.read._0.value,
//             };
//             break;
//         case OptionMemoryRecordEnum::Tag::Write:
//             current_record = {
//                 .shard = record.write._0.shard,
//                 .timestamp = record.write._0.timestamp,
//                 .value = record.write._0.value,
//             };
//             prev_record = {
//                 .shard = record.write._0.prev_shard,
//                 .timestamp = record.write._0.prev_timestamp,
//                 .value = record.write._0.prev_value,
//             };
//             break;
//         default:
//             // Unreachable. `None` case guarded above.
//             assert(false);
//             break;
//     }
//     write_word_from_u32<F>(self.prev_value, prev_record.value);
//     populate_access<F>(self.access, current_record, prev_record);
// }
// }  // namespace sp1::memory