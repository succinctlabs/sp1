use crate::field::event::FieldEvent;
use p3_field::Field;

use super::{
    MemoryAccessCols, MemoryReadCols, MemoryReadRecord, MemoryReadWriteCols, MemoryRecord,
    MemoryWriteCols, MemoryWriteRecord,
};

impl<F: Field> MemoryWriteCols<F> {
    pub fn populate(&mut self, record: MemoryWriteRecord, new_field_events: &mut Vec<FieldEvent>) {
        self.prev_value = record.prev_value.into();
        self.access
            .populate_access(MemoryRecord::Write(record), new_field_events);
    }
}

impl<F: Field> MemoryReadCols<F> {
    pub fn populate(&mut self, record: MemoryReadRecord, new_field_events: &mut Vec<FieldEvent>) {
        self.access
            .populate_access(MemoryRecord::Read(record), new_field_events);
    }
}

impl<F: Field> MemoryReadWriteCols<F> {
    pub fn populate(&mut self, record: MemoryRecord, new_field_events: &mut Vec<FieldEvent>) {
        self.prev_value = record.prev_value().into();
        self.access.populate_access(record, new_field_events);
    }

    pub fn populate_write(
        &mut self,
        record: MemoryWriteRecord,
        new_field_events: &mut Vec<FieldEvent>,
    ) {
        self.populate(MemoryRecord::Write(record), new_field_events)
    }

    pub fn populate_read(
        &mut self,
        record: MemoryReadRecord,
        new_field_events: &mut Vec<FieldEvent>,
    ) {
        self.populate(MemoryRecord::Read(record), new_field_events)
    }
}

impl<F: Field> MemoryAccessCols<F> {
    pub(crate) fn populate_access(
        &mut self,
        record: MemoryRecord,
        new_field_events: &mut Vec<FieldEvent>,
    ) {
        self.value = record.value().into();

        self.prev_segment = F::from_canonical_u32(record.prev_segment());
        self.prev_clk = F::from_canonical_u32(record.prev_timestamp());

        // Fill columns used for verifying current memory access time value is greater than previous's.
        let use_clk_comparison = record.prev_segment() == record.segment();
        self.use_clk_comparison = F::from_bool(use_clk_comparison);
        let prev_time_value = if use_clk_comparison {
            record.prev_timestamp()
        } else {
            record.segment()
        };
        self.prev_time_value = F::from_canonical_u32(prev_time_value);
        let current_time_value = if use_clk_comparison {
            record.timestamp()
        } else {
            record.segment()
        };
        self.current_time_value = F::from_canonical_u32(current_time_value);

        // Add a field op event for the prev_time_value < current_time_value constraint.
        let field_event = FieldEvent::new(true, prev_time_value, current_time_value);
        new_field_events.push(field_event);
    }
}
