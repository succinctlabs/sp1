use core::convert::TryInto;
use std::collections::HashMap;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::ops::Invert;

pub type HookName = String;
pub type BoxedHook = Box<dyn Fn(&[u8]) -> Vec<Vec<u8>>>;

pub struct HookInvocation<'a> {
    pub name: HookName,
    pub args: &'a [u8],
}

pub fn default_hooks() -> HashMap<HookName, BoxedHook> {
    // Necessary to annotate types here to get the closures to comply with the type.
    let entries: Vec<(String, Box<dyn Fn(&[u8]) -> Vec<Vec<u8>>>)> = vec![
        ("noop".to_owned(), Box::new(|_| vec![])),
        ("echo".to_owned(), Box::new(|args| vec![args.to_owned()])),
        (
            "hello_world".to_owned(),
            Box::new(|args| {
                tracing::info!("hello world! {args:?}");
                vec![]
            }),
        ),
        ("ecrecover".to_owned(), Box::new(hook_ecrecover)),
    ];
    HashMap::from_iter(entries)
}

pub fn hook_ecrecover(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut res = Vec::new();

    tracing::info!("hook_ecrecover buf={:?}", buf);
    // Sizes: ([u8; 65], [u8; 32])
    let (sig, msg_hash): (Vec<u8>, Vec<u8>) =
        bincode::deserialize(buf).expect("failed to deserialize");
    assert_eq!(sig.len(), 65, "failed to deserialize");
    assert_eq!(msg_hash.len(), 32, "failed to deserialize");

    let mut recovery_id = sig[64];
    let mut sig = Signature::from_slice(&sig[..64]).unwrap();

    if let Some(sig_normalized) = sig.normalize_s() {
        sig = sig_normalized;
        recovery_id ^= 1
    };
    let recid = RecoveryId::from_byte(recovery_id).expect("Recovery ID is valid");

    let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash[..], &sig, recid).unwrap();
    let bytes = recovered_key.to_sec1_bytes();
    res.push(Vec::from(bytes));

    let (_, s) = sig.split_scalars();
    let s_inverse = s.invert();
    res.push(s_inverse.to_bytes().to_vec());

    res
}
