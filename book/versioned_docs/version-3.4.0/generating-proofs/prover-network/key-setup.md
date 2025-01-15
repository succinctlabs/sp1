# Prover Network: Key Setup

The prover network uses Secp256k1 keypairs for authentication, similar to Ethereum wallets. You may generate a new keypair explicitly for use with the prover network, or use an existing keypair.

> **You do not need to hold any funds in this account, it is used solely for access control.**

### Generate a Public Key

Prover network keypair credentials can be generated using the
[cast](https://book.getfoundry.sh/cast/) CLI tool.

First install [Foundry](https://book.getfoundry.sh/getting-started/installation#using-foundryup):

```sh
curl -L https://foundry.paradigm.xyz | bash
```

Upon running this command, you will be prompted to source your shell profile and run `foundryup`. Afterwards you should have access to the `cast` command.

Use `cast` to generate a new keypair:

```sh
cast wallet new
```

which will give you an output similar to this:

![Screenshot from running 'cast wallet new' to generate an SP1_PRIVATE_KEY.](../prover-network/key.png)

The "Address" what you should submit in the [form](https://forms.gle/rTUvhstS8PFfv9B3A), in the example above this is `0x552f0FC6D736ed965CE07a3D71aA639De15B627b`. The "Private key" should be kept safe and
secure. When interacting with the network, you will set your `SP1_PRIVATE_KEY` environment variable
to this value.

### Retrieve an Existing Key

If you already have an existing key you would like to use, you can also use `cast` retrieve your address:

```sh
cast wallet address --private-key $PRIVATE_KEY
```
