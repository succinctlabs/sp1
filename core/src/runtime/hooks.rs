use core::convert::TryInto;
use std::borrow::Cow;
use std::collections::HashMap;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::ops::Invert;

use super::Runtime;

type HookName<'a> = Cow<'a, str>;
type BoxedHook<'a> = Box<dyn Fn(HookEnv<'_>, &[u8]) -> Vec<Vec<u8>> + 'a>;

/// TODO docs
pub struct HookRegistry<'a> {
    /// Table of registered hooks. Prefer using `Runtime::invoke_hook` and
    /// `HookRegistry::register` over interacting with this field directly.
    pub table: HashMap<HookName<'a>, BoxedHook<'a>>,
}

impl<'a> HookRegistry<'a> {
    /// Create a registry with default hooks.
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
    pub fn register(&mut self, name: HookName<'a>, hook: BoxedHook<'a>) {
        self.table.insert(name, hook);
    }
}

impl<'a> Default for HookRegistry<'a> {
    fn default() -> Self {
        // When `LazyCell` gets stabilized (1.81.0), we can use it to avoid unnecessary allocations.
        let table = {
            let entries: Vec<(HookName, BoxedHook)> = vec![
                // ("noop".into(), Box::new(|_, _| vec![])),
                // ("echo".into(), Box::new(|_, args| vec![args.to_owned()])),
                // (
                //     "hello_world".into(),
                //     Box::new(|_, args| {
                //         tracing::info!("hello world! {args:?}");
                //         vec![]
                //     }),
                // ),
                ("ecrecover".into(), Box::new(hook_ecrecover)),
            ];
            HashMap::from_iter(entries)
        };

        Self { table }
    }
}

pub struct HookEnv<'a> {
    pub runtime: &'a Runtime,
}

pub fn hook_ecrecover(_env: HookEnv<'_>, buf: &[u8]) -> Vec<Vec<u8>> {
    tracing::info!("hook_ecrecover buf.len()={}", buf.len());
    let (sig, msg_hash): ([u8; 65], [u8; 32]) = bincode::deserialize(buf)
        .ok()
        .and_then(|(sig, msg_hash): (Vec<u8>, Vec<u8>)| {
            Some((sig.try_into().ok()?, msg_hash.try_into().ok()?))
        })
        .expect("hook_ecrecover args should deserialize");

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
    fn empty_is_empty() {
        assert_eq!(HookRegistry::empty().table.len(), 0);
    }
}
