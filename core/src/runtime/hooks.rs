use core::convert::TryInto;
use std::collections::HashMap;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::ops::Invert;

use super::Runtime;

type HookId = u32;
type BoxedHook<'a> = Box<dyn Fn(HookEnv, &[u8]) -> Vec<Vec<u8>> + 'a>;

// Ensure this value is synced with the values in `zkvm/precompiles/src/io.rs`
/// The file descriptor through which to access `hook_ecrecover`.
pub const FD_ECRECOVER_HOOK: HookId = 5;

/// A registry of hooks to call, indexed by the file descriptors through which they are accessed.
pub struct HookRegistry<'a> {
    /// Table of registered hooks. Prefer using `Runtime::invoke_hook` and
    /// `HookRegistry::register` over interacting with this field directly.
    pub table: HashMap<HookId, BoxedHook<'a>>,
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

    /// Register a hook under a given name.
    pub fn register(&mut self, name: HookId, hook: BoxedHook<'a>) {
        self.table.insert(name, hook);
    }
}

impl<'a> Default for HookRegistry<'a> {
    fn default() -> Self {
        // When `LazyCell` gets stabilized (1.81.0), we can use it to avoid unnecessary allocations.
        let table = {
            let entries: Vec<(HookId, BoxedHook)> =
                vec![(FD_ECRECOVER_HOOK, Box::new(hook_ecrecover))];
            HashMap::from_iter(entries)
        };

        Self { table }
    }
}

/// Environment that a hook may read from.
pub struct HookEnv<'a, 'b: 'a> {
    pub runtime: &'a Runtime<'b>,
}

pub fn hook_ecrecover(_env: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
    tracing::info!("hook_ecrecover buf.len()={}", buf.len());
    let (sig, msg_hash) = buf.split_at(65);
    let sig: &[u8; 65] = sig
        .try_into()
        .expect("buf should have correct size and offset of bytes for sig");
    let msg_hash: &[u8; 32] = msg_hash
        .try_into()
        .expect("buf should have correct size and offset of bytes for msg_hash");

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
    use super::*;

    #[test]
    pub fn registry_new_is_inhabited() {
        assert_ne!(HookRegistry::new().table.len(), 0);
    }

    #[test]
    pub fn registry_empty_is_empty() {
        assert_eq!(HookRegistry::empty().table.len(), 0);
    }
}
