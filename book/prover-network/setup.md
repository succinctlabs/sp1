# Prover Network: Setup

So far we've explored how to generate proofs locally, but this can actually be inconvenient on local machines due to high memory / CPU requirements, especially for very large programs.

Succinct [has been building](https://blog.succinct.xyz/succinct-network/) the Succinct Network, a distributed network of provers that can generate proofs of any size quickly and reliably. It's currently in private beta, but you can get access by following the steps below.

## Get access

Currently the network is permissioned, so you need to gain access through Succinct. After you have completed the key setup below, you can submit your address in this [form](https://docs.google.com/forms/d/e/1FAIpQLSd-X9uH7G0bvXH_kjptnQtNil8L4dumrVPpFE4t8Ci1XT1GaQ/viewform) and we'll contact you shortly.

### Key Setup

The prover network uses secp256k1 keypairs for authentication, like Ethereum wallets. You may generate a new keypair explicitly for use with the prover network, or use an existing keypair. Currently you do not need to hold any funds in this account, it is used solely for access control.

Prover network keypair credentials can be generated using the [cast](https://book.getfoundry.sh/cast/) CLI tool:

[Install](https://book.getfoundry.sh/getting-started/installation#using-foundryup):

```sh
curl -L https://foundry.paradigm.xyz | bash
```

Generate a new keypair:

```sh
cast wallet new
```

Or, retrieve your address from an existing key:

```sh
cast wallet address --private-key $PRIVATE_KEY
```

Make sure to keep your private key somewhere safe and secure, you'll need it to interact with the prover network.
