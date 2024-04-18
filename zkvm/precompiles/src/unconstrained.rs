/// Executes a block of code unconstrained by the VM. This macro is useful for running code that
/// helps provide information to the program but does not need to be constrained by the VM. For
/// example, running `ecrecover` is expensive in the VM but verifying a signature when you know the
/// public key is not. `unconstrained` can be used to provide the public key without spending VM CPU
/// cycles.
///
/// Any changes to the VM state will be reset at the end of the block. To provide data to the VM,
/// use `io::hint` or `io::hint_slice`, and read it using `io::read` or `io::read_vec`.
#[macro_export]
macro_rules! unconstrained {
    (  $($block:tt)* ) => {
        use $crate::{syscall_enter_unconstrained, syscall_exit_unconstrained};

        let continue_unconstrained: bool;
        unsafe {
            continue_unconstrained = syscall_enter_unconstrained();
        }

        // If continue_unconstrained is true (only possible in the runtime), execute
        // the inner code. Otherwise, nothing happens.
        if continue_unconstrained {
            // Declare an immutable closure to ensure at compile time that no memory is changed
            let _unconstrained_closure = || -> () {
                $($block)*
            };

            _unconstrained_closure();

            unsafe {
                syscall_exit_unconstrained();
            }
        }

    };
}
