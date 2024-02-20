use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomialExtensionField, AbstractExtensionField};

use crate::{
    runtime::{Register, Syscall},
    syscall::precompiles::SyscallContext,
};

use super::{FriFoldChip, FriFoldEvent};

impl Syscall for FriFoldChip {
    fn num_extra_cycles(&self) -> u32 {
        8
    }

    fn execute(&self, rt: &mut SyscallContext) -> u32 {
        // TODO: these will have to be be constrained, but can do it later.
        // Read `input_mem_ptr` from register a0.
        let input_mem_ptr = rt.register_unsafe(Register::X10);
        if input_mem_ptr % 4 != 0 {
            panic!();
        }
        // Read `output_mem_ptr` from register a1.
        let output_mem_ptr = rt.register_unsafe(Register::X11);
        if output_mem_ptr % 4 != 0 {
            panic!();
        }

        let saved_clk = rt.clk;

        let (input_read_records, input_values) = rt.mr_slice(input_mem_ptr, 14);

        let x = BabyBear::from_monty(input_values[0]);
        let alpha = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            input_values[1..5]
                .iter()
                .map(|x| BabyBear::from_monty(*x))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let z = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            input_values[5..9]
                .iter()
                .map(|x| BabyBear::from_monty(*x))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let p_at_z = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            input_values[9..13]
                .iter()
                .map(|x| BabyBear::from_monty(*x))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let p_at_x = BabyBear::from_monty(input_values[13]);

        // Read ro[log_height] and alpha_pow[log_height] address
        let (output_read_records, output_addresses) = rt.mr_slice(output_mem_ptr, 2);
        let ro_addr = output_addresses[0];
        let alpha_pow_addr = output_addresses[1];

        let (ro_read_records, ro_values) = rt.mr_slice(ro_addr, 4);

        let ro_input = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            ro_values
                .iter()
                .map(|&x| BabyBear::from_monty(x))
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let (alpha_pow_read_records, alpha_values) = rt.mr_slice(alpha_pow_addr, 4);
        let alpha_pow_input = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            alpha_values
                .iter()
                .map(|&x| BabyBear::from_monty(x))
                .collect::<Vec<_>>()
                .as_slice(),
        );

        rt.clk += 4;

        let quotient = (-p_at_z + p_at_x) / (-z + x);

        let ro_output = ro_input + (alpha_pow_input * quotient);
        let alpha_pow_output = alpha_pow_input * alpha;

        let ro_write_records = rt.mw_slice(
            ro_addr,
            ro_output
                .as_base_slice()
                .iter()
                .map(|x: &BabyBear| x.as_monty())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let alpha_pow_write_records = rt.mw_slice(
            alpha_pow_addr,
            alpha_pow_output
                .as_base_slice()
                .iter()
                .map(|x: &BabyBear| x.as_monty())
                .collect::<Vec<_>>()
                .as_slice(),
        );

        rt.clk += 4;

        let shard = rt.current_shard();

        // Push the fri fold event.
        rt.record_mut().fri_fold_events.push(FriFoldEvent {
            clk: saved_clk,
            shard,
            x,
            alpha,
            z,
            p_at_z,
            p_at_x,
            ro_input,
            alpha_pow_input,
            ro_output,
            alpha_pow_output,
            input_read_records,
            input_mem_ptr,
            output_read_records,
            output_mem_ptr,
            ro_read_records,
            ro_write_records,
            ro_addr,
            alpha_pow_read_records,
            alpha_pow_write_records,
            alpha_pow_addr,
        });

        input_mem_ptr
    }
}
