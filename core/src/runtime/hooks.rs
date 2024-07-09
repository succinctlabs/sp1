use core::fmt::Debug;

use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockWriteGuard};

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::ops::Invert;

use super::Runtime;

/// A runtime hook, wrapped in a smart pointer.
pub type BoxedHook<'a> = Arc<RwLock<dyn Hook + Send + Sync + 'a>>;

/// The file descriptor through which to access `hook_ecrecover`.
pub const FD_ECRECOVER_HOOK: u32 = 5;

/// A runtime hook. May be called during execution by writing to a specified file descriptor,
/// accepting and returning arbitrary data.
pub trait Hook {
    /// Invoke the runtime hook with a standard environment and arbitrary data.
    /// Returns the computed data.
    fn invoke_hook(&mut self, env: HookEnv, buf: &[u8]) -> Vec<Vec<u8>>;
}

impl<F: FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>>> Hook for F {
    /// Invokes the function `self` as a hook.
    fn invoke_hook(&mut self, env: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        self(env, buf)
    }
}

/// Wrap a function in a smart pointer so it may be placed in a `HookRegistry`.
///
/// Note: the Send + Sync requirement may be logically extraneous. Requires further investigation.
pub fn hookify<'a>(
    f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
) -> BoxedHook<'a> {
    Arc::new(RwLock::new(f))
}

/// A registry of hooks to call, indexed by the file descriptors through which they are accessed.
#[derive(Clone)]
pub struct HookRegistry<'a> {
    /// Table of registered hooks. Prefer using `Runtime::hook`, ` Runtime::hook_env`,
    /// and `HookRegistry::get` over interacting with this field directly.
    pub(crate) table: HashMap<u32, BoxedHook<'a>>,
}

impl<'a> HookRegistry<'a> {
    /// Create a registry with the default hooks.
    pub fn new() -> Self {
        Default::default()
    }

    /// Create an empty registry.
    pub fn empty() -> Self {
        Self {
            table: Default::default(),
        }
    }

    /// Get a hook with exclusive write access, if it exists.
    /// Should not be called in async contexts, unless you know what you are doing.
    pub fn get(&self, fd: &u32) -> Option<RwLockWriteGuard<dyn Hook + Send + Sync + 'a>> {
        // Calling `.unwrap()` panics on a poisoned lock. Should never happen normally.
        self.table.get(fd).map(|x| x.write().unwrap())
    }
}

impl<'a> Default for HookRegistry<'a> {
    fn default() -> Self {
        // When `LazyCell` gets stabilized (1.81.0), we can use it to avoid unnecessary allocations.
        let table = HashMap::from([
            // Note: To ensure any `fd` value is synced with `zkvm/precompiles/src/io.rs`,
            // add an assertion to the test `hook_fds_match` below.
            (FD_ECRECOVER_HOOK, hookify(hook_ecrecover)),
        ]);

        Self { table }
    }
}

impl<'a> Debug for HookRegistry<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys = self.table.keys().collect::<Vec<_>>();
        keys.sort_unstable();
        f.debug_struct("HookRegistry")
            .field(
                "table",
                &format_args!("{{{} hooks registered at {:?}}}", self.table.len(), keys),
            )
            .finish()
    }
}

/// Environment that a hook may read from.
pub struct HookEnv<'a, 'b: 'a> {
    pub runtime: &'a Runtime<'b>,
}

pub fn hook_ecrecover(_env: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(
        buf.len(),
        65 + 32,
        "ecrecover input should have length 65 + 32"
    );
    let (sig, msg_hash) = buf.split_at(65);
    let sig: &[u8; 65] = sig.try_into().unwrap();
    let msg_hash: &[u8; 32] = msg_hash.try_into().unwrap();

    let mut recovery_id = sig[64];
    let mut sig = Signature::from_slice(&sig[..64]).unwrap();

    if let Some(sig_normalized) = sig.normalize_s() {
        sig = sig_normalized;
        recovery_id ^= 1
    };
    let recid = RecoveryId::from_byte(recovery_id).expect("Recovery ID is valid");

    let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash[..], &sig, recid).unwrap();
    let bytes = recovered_key.to_sec1_bytes();

    let (_, s) = sig.split_scalars();
    let s_inverse = s.invert();

    vec![bytes.to_vec(), s_inverse.to_bytes().to_vec()]
}

#[cfg(test)]
pub mod tests {
    use crate::{
        runtime::Program,
        stark::DefaultProver,
        utils::{self, tests::ECRECOVER_ELF},
    };

    use super::*;

    #[test]
    pub fn hook_fds_match() {
        use sp1_zkvm::lib::io;
        assert_eq!(FD_ECRECOVER_HOOK, io::FD_ECRECOVER_HOOK)
    }

    #[test]
    pub fn registry_new_is_inhabited() {
        assert_ne!(HookRegistry::new().table.len(), 0);
        println!("{:?}", HookRegistry::new());
    }

    #[test]
    pub fn registry_empty_is_empty() {
        assert_eq!(HookRegistry::empty().table.len(), 0);
    }

    #[test]
    fn test_ecrecover_program_prove() {
        utils::setup_logger();
        let program = Program::from(ECRECOVER_ELF);
        utils::run_test::<DefaultProver<_, _>>(program).unwrap();
    }
}
