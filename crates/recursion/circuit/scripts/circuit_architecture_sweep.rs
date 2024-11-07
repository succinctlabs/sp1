//! Sweeps end-to-end prover performance across a wide range of parameters for the Plonk circuit builder.

use p3_baby_bear::BabyBear;

use sp1_core::{stark::StarkMachine, utils::log2_strict_usize};
use sp1_recursion_circuit::build_wrap_v2::{machine_with_all_chips, test_machine};
use sp1_recursion_core::machine::RecursionAir;
use sp1_recursion_core::stark::config::BabyBearPoseidon2Outer;

type SC = BabyBearPoseidon2Outer;

fn machine_with_dummy<const DEGREE: usize, const COL_PADDING: usize>(
    log_height: usize,
) -> StarkMachine<BabyBearPoseidon2Outer, RecursionAir<BabyBear, DEGREE, COL_PADDING>> {
    let config = SC::new_with_log_blowup(log2_strict_usize(DEGREE - 1));
    RecursionAir::<BabyBear, DEGREE, COL_PADDING>::dummy_machine(config, log_height)
}

fn main() {
    // Test the performance of the full architecture with different degrees.
    let machine_maker_3 = || machine_with_all_chips::<3>(16, 16, 16);
    let machine_maker_5 = || machine_with_all_chips::<5>(16, 16, 16);
    let machine_maker_9 = || machine_with_all_chips::<9>(16, 16, 16);
    let machine_maker_17 = || machine_with_all_chips::<17>(16, 16, 16);
    test_machine(machine_maker_3);
    test_machine(machine_maker_5);
    test_machine(machine_maker_9);
    test_machine(machine_maker_17);

    // Test the performance of the machine with the full architecture for different numbers of rows
    // in the precompiles. Degree is set to 9.
    let machine_maker = |i| machine_with_all_chips::<9>(i, i, i);
    for i in 1..=5 {
        test_machine(|| machine_maker(i));
    }

    // Test the performance of the dummy machine for different numbers of columns in the dummy table.
    // Degree is kept fixed at 9.
    test_machine(|| machine_with_dummy::<9, 1>(16));
    test_machine(|| machine_with_dummy::<9, 50>(16));
    test_machine(|| machine_with_dummy::<9, 100>(16));
    test_machine(|| machine_with_dummy::<9, 150>(16));
    test_machine(|| machine_with_dummy::<9, 200>(16));
    test_machine(|| machine_with_dummy::<9, 250>(16));
    test_machine(|| machine_with_dummy::<9, 300>(16));
    test_machine(|| machine_with_dummy::<9, 350>(16));
    test_machine(|| machine_with_dummy::<9, 400>(16));
    test_machine(|| machine_with_dummy::<9, 450>(16));
    test_machine(|| machine_with_dummy::<9, 500>(16));
    test_machine(|| machine_with_dummy::<9, 550>(16));
    test_machine(|| machine_with_dummy::<9, 600>(16));
    test_machine(|| machine_with_dummy::<9, 650>(16));
    test_machine(|| machine_with_dummy::<9, 700>(16));
    test_machine(|| machine_with_dummy::<9, 750>(16));

    // Test the performance of the dummy machine for different heights of the dummy table.
    for i in 4..=7 {
        test_machine(|| machine_with_dummy::<9, 1>(i));
    }

    // Change the degree for the dummy table, keeping other parameters fixed.
    test_machine(|| machine_with_dummy::<3, 500>(16));
    test_machine(|| machine_with_dummy::<5, 500>(16));
    test_machine(|| machine_with_dummy::<9, 500>(16));
    test_machine(|| machine_with_dummy::<17, 500>(16));
}
