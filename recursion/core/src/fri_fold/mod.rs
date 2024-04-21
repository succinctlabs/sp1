/// A chip that implements the Fri Fold precompile.
#[derive(Default)]
pub struct FriFoldChip;

#[derive(Debug, Clone)]
pub struct FriFoldEvent<F: PrimeField32, EF: ExtensionField<F>> {
    pub z: EF,
    pub alpha: EF,
    pub x: F,
    pub log_height: usize,
    pub mat_opening_ptr: usize,
    pub ps_at_x_ptr: usize,
    pub alpha_pow_ptr: usize,
    pub ro_ptr: usize,

    pub p_at_x: EF,
    pub p_at_z: EF,

    pub alpha_pow_at_log_height: EF,
    pub ro_at_log_height: EF,
}
