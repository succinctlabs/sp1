#[cfg(test)]
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    sha2::Sha256,
    signature::{SignatureEncoding, Verifier},
    RsaPublicKey,
};

#[sp1_test::sp1_test("rsa_test_verify_pkcs", syscalls = [U256XU2048_MUL], gpu, prove)]
pub fn test_pkcs_verify_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    let times: u8 = 100;

    stdin.write(&times);

    for _ in 0..times {
        let (signature, verifying_key, data) = sign_inner();

        // Check that the original crate also validates this signature.
        assert!(verifying_key.verify(&data, &signature).is_ok());

        stdin.write(&signature.to_bytes());
        stdin.write(&RsaPublicKey::from(verifying_key));
        stdin.write(&data);
    }

    |_| {}
}

#[sp1_test::sp1_test("rsa_test_email", gpu, prove)]
pub fn test_pkcs_verify_email(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    const RSA_3072_PRIV_PEM: &str = include_str!("../assets/rsa3072-priv.pem");
    const EMAIL: &str = include_str!("../assets/email.eml");

    stdin.write(&RSA_3072_PRIV_PEM.to_string());
    stdin.write(&EMAIL.to_string());

    |_| {}
}

#[cfg(test)]
fn sign_inner() -> (Signature, VerifyingKey<Sha256>, Vec<u8>) {
    use rsa::pkcs1v15::SigningKey;
    use rsa::sha2::Sha256;
    use rsa::signature::{Keypair, RandomizedSigner};
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let verifying_key = signing_key.verifying_key();

    let data_len = rand::random::<usize>() % 1024;
    let data: Vec<u8> = (0..data_len).map(|_| rand::random::<u8>()).collect();

    let signature = signing_key.sign_with_rng(&mut rng, &data);

    (signature, verifying_key, data)
}
