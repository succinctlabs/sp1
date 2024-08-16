use sysinfo::System;

/// The minimum amount of RAM required to generate a plonk proof.
const PLONK_MEMORY_GB_REQUIREMENT: u64 = 64;

/// Checks if there is enough RAM to generate a plonk proof.
fn enough_ram_for_plonk() -> bool {
    let total_ram_gb = System::new_all().total_memory() / 1_000_000_000;
    total_ram_gb >= (PLONK_MEMORY_GB_REQUIREMENT - 4)
}
