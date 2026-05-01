/// Execution mode trait for compile-time specialization of page protection behavior.
pub trait ExecutionMode: Sized + Send + Sync + Clone + Copy + Default + 'static {
    /// Whether page protection checks are enabled for this execution mode.
    ///
    /// When `false`, all page protection code is eliminated at compile time.
    const PAGE_PROTECTION_ENABLED: bool;
}

/// Supervisor execution mode - no page protection checks.
#[derive(Clone, Copy, Debug, Default)]
pub struct SupervisorMode;

impl ExecutionMode for SupervisorMode {
    const PAGE_PROTECTION_ENABLED: bool = false;
}

/// User execution mode - page protection checks enabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct UserMode;

impl ExecutionMode for UserMode {
    const PAGE_PROTECTION_ENABLED: bool = true;
}
