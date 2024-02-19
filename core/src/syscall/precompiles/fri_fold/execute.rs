use p3_baby_bear::BabyBear;
use p3_field::{
    extension::BinomialExtensionField, AbstractExtensionField, AbstractField, PrimeField32,
};

use crate::{
    runtime::{Register, Syscall},
    syscall::precompiles::SyscallContext,
};

use super::FriFoldChip;

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
        let (input_read_records, input_values) = rt.mr_slice(input_mem_ptr, 14);

        let x = BabyBear::from_canonical_u32(input_values[0]);
        let alpha = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            input_values[1..5]
                .iter()
                .map(|x| BabyBear::from_canonical_u32(*x))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let z = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            input_values[5..9]
                .iter()
                .map(|x| BabyBear::from_canonical_u32(*x))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let p_at_z = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            input_values[9..13]
                .iter()
                .map(|x| BabyBear::from_canonical_u32(*x))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let p_at_x = BabyBear::from_canonical_u32(input_values[13]);

        // Read ro[log_height] and alpha_pow[log_height] address
        let (output_read_records, output_addresses) = rt.mr_slice(output_mem_ptr, 2);
        let ro_address = output_addresses[0];
        let alpha_pow_address = output_addresses[1];

        let (ro_read_records, ro_values) = rt.mr_slice(ro_address, 4);
        let mut ro = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            ro_values
                .iter()
                .map(|&x| BabyBear::from_canonical_u32(x))
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let (alpha_read_records, alpha_values) = rt.mr_slice(alpha_pow_address, 4);
        let mut alpha_pow = BinomialExtensionField::<BabyBear, 4>::from_base_slice(
            alpha_values
                .iter()
                .map(|&x| BabyBear::from_canonical_u32(x))
                .collect::<Vec<_>>()
                .as_slice(),
        );

        rt.clk += 4;

        let quotient = (-p_at_z + p_at_x) / (-z + x);
        ro += alpha_pow * quotient;
        alpha_pow *= alpha;

        let ro_write_records = rt.mw_slice(
            ro_address,
            ro.as_base_slice()
                .iter()
                .map(|x: &BabyBear| x.as_canonical_u32())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let alpha_pow_write_records = rt.mw_slice(
            alpha_pow_address,
            alpha_pow
                .as_base_slice()
                .iter()
                .map(|x: &BabyBear| x.as_canonical_u32())
                .collect::<Vec<_>>()
                .as_slice(),
        );

        rt.clk += 4;

        // TODO. Push the fri fold event.

        input_mem_ptr
    }
}
