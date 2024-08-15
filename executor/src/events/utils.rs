use rand::{thread_rng, Rng};

/// Creates a new ALU lookup id.
#[must_use]
pub fn create_alu_lookup_id() -> u128 {
    let mut rng = thread_rng();
    rng.gen()
}

/// Creates a new ALU lookup ids.
#[must_use]
pub fn create_alu_lookups() -> [u128; 6] {
    let mut rng = thread_rng();
    [
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
    ]
}
