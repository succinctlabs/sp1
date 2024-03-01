use p3_field::PrimeField32;

use crate::runtime::{Syscall, SyscallContext, A0, A1};

use super::{BinaryOpcode, NativeChip, NativeEvent};

impl<F: PrimeField32> Syscall<F> for NativeChip {
    fn num_extra_cycles(&self) -> u32 {
        4
    }

    fn execute(&self, ctx: &mut SyscallContext<F>) -> u32 {
        let start_clk = ctx.clk;

        let a0 = ctx.register_unsafe(A0);
        let (b_record, a1) = ctx.mr(A1 as u32);

        let a_0 = F::from_canonical_u32(a0);
        let a_1 = F::from_canonical_u32(a1);

        let result = match self.op {
            BinaryOpcode::Add => a_0 + a_1,
            BinaryOpcode::Mul => a_0 * a_1,
            BinaryOpcode::Sub => a_0 - a_1,
            BinaryOpcode::Div => a_0 / a_1,
        }
        .as_canonical_u32();

        let a_record = ctx.mw(A0 as u32, result);

        let native_event = NativeEvent {
            clk: start_clk,
            shard: ctx.current_shard(),
            a_record,
            b_record,
        };

        ctx.clk += 4;

        self.op.events_mut(ctx.record_mut()).push(native_event);

        result
    }
}
