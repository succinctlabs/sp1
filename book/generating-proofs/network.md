# Generating Proofs: Prover Network

In the case that you do not want to prove locally, you can use the Succinct prover network to generate proofs.

**Note:** The network is still in development and should be only used for testing purposes.

## Sending a proof request

To use the prover network to generate a proof, you can run your program as you would normally but with additional environment variables set:

```sh
SP1_PROVER=network SP1_PRIVATE_KEY=... cargo run --release
```

- `SP1_PROVER` should be set to `network` when using the prover network.

- `SP1_PRIVATE_KEY` is your secp256k1 private key for signing messages on the network. The balance of
  the address corresponding to this private key will be used to pay for the proof request.

Once a request is sent, a prover will claim the request and start generating a proof. After some
time, it will be returned.

## Network balance

Before sending requests, you must ensure you have enough balance on the network. You can add to your
balance by sending ETH to the canonical `NetworkFeeVault` contract on Base, which has the address
[0x66ea36fDBdDD09E3aCAB7B9f654220B00e537574](https://basescan.org/address/0x66ea36fdbddd09e3acab7b9f654220b00e537574#code).

Adding to your balance can be done in [Etherscan](https://basescan.org/address/0x66ea36fdbddd09e3acab7b9f654220b00e537574#writeContract) by
connecting your wallet, or by using the [cast](https://book.getfoundry.sh/cast/) CLI tool.

This can be done either by calling the `addBalance()` function:

```sh
# The sender will send 1000 wei and the $OWNER will have their balance increased by 1000
OWNER=(your address)
AMOUNT=1000
cast send 0x66ea36fDBdDD09E3aCAB7B9f654220B00e537574 "addBalance(address)" $OWNER --value $AMOUNT --private-key $PRIVATE_KEY --chain-id 8453 --rpc-url https://developer-access-mainnet.base.org
```

or by sending ETH directly:

```sh
# The sender will send 1000 wei and have their balance increased by 1000
AMOUNT=1000
cast send 0x66ea36fDBdDD09E3aCAB7B9f654220B00e537574 --value $AMOUNT --private-key $PRIVATE_KEY --chain-id 8453 --rpc-url https://developer-access-mainnet.base.org
```
