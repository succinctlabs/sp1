# Generating Proofs: Prover Network

In the case that you do not want to prove locally, you can use the Succinct prover network to generate proofs.

**Note:** The network is still in development and should be only used for testing purposes.

## Sending a proof request

To use the prover network to generate a proof, you can run your program as you would normally but with additional environment variables set:

```sh
SP1_PROVER=network SP1_PRIVATE_KEY=... cargo run --release
```

- `SP1_PROVER` should be set to `network` when using the prover network.

- `SP1_PRIVATE_KEY`should be set to your [private key](#key-setup). You will need
  to be using a [whitelisted](#getting-whitelisted) key to use the network.

Once a request is sent, a prover will claim the request and start generating a proof. After some
time, it will be fulfilled.

## Key Setup

The prover network uses secp256k1 signatures for authentication. You may generate a new keypair
explicitly for use with the prover network, or used an existing keypair.

Prover network keypair credentials can be generated using the [cast](https://book.getfoundry.sh/cast/) CLI tool:

```sh
cast wallet new
```

or retieve your address from an existing key:

```sh
cast wallet address --private-key $SP1_PRIVATE_KEY
```

You should keep your private key safe and secure. Only your address can be shared publically.

## Getting Whitelisted

After you have completed the [key setup](#key-setup), you can submit your address in this [form](https://docs.google.com/forms/d/e/1FAIpQLSd-X9uH7G0bvXH_kjptnQtNil8L4dumrVPpFE4t8Ci1XT1GaQ/viewform?vc=0&c=0&w=1&flr=0&usp=mail_form_link).
