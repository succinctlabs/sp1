use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    Error, Message, PublicKey, Secp256k1,
};

type Case = (i32, [u8; 32], Vec<u8>, Vec<u8>);

fn main() {
    let mode = std::env::args().nth(1).unwrap();
    let cases: Vec<Case> = bincode::deserialize_from(std::io::stdin()).unwrap();
    let secp = Secp256k1::new();
    let results: Vec<Result<Vec<u8>, u8>> = cases
        .into_iter()
        .map(|(id, digest, compact, key)| {
            let message = Message::from_digest_slice(&digest).unwrap();
            let result = match mode.as_str() {
                "verify" => {
                    let signature = Signature::from_compact(&compact).unwrap();
                    let key = PublicKey::from_slice(&key).unwrap();
                    secp.verify_ecdsa(&message, &signature, &key).map(|()| Vec::new())
                }
                "recover" => {
                    #[cfg(feature = "v030")]
                    let id = RecoveryId::try_from(id).unwrap();
                    #[cfg(not(feature = "v030"))]
                    let id = RecoveryId::from_i32(id).unwrap();
                    let signature = RecoverableSignature::from_compact(&compact, id).unwrap();
                    secp.recover_ecdsa(&message, &signature).map(|key| key.serialize().to_vec())
                }
                _ => panic!("unknown operation"),
            };
            result.map_err(|error| match error {
                Error::IncorrectSignature => 1,
                Error::InvalidSignature => 2,
                other => panic!("unexpected error {other:?}"),
            })
        })
        .collect();
    bincode::serialize_into(std::io::stdout(), &results).unwrap();
}
