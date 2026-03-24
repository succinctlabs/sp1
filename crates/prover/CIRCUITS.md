# BN254 Wrapping Circuits

## Generating circuits

From this crate, run 

```bash
make build-circuits
```

## Trusted setup

The groth16 pk and vk were generated with a trusted setup ceremony. To learn more about how the ceremony was organized and how to verify contributions, refer to the the following resources.

- The [github repo](https://github.com/succinctlabs/semaphore-gnark-11/commit/6d6ebc3608e609ec879e9ba99abee6b6b97d937d) for coordinating setup. Also includes verification instructions. This exact commit was used to generate v6.0.0 circuits.

- [SP1 docs](https://docs.succinct.xyz/docs/sp1/security/security-model#trusted-setup) to see the exact contributors. 

## Publishing (for SP1 maintainers)

Run

```bash
make release-circuits
```

If you're publishing with trusted setup, make sure that the contents of the `build` directory are up to date with the correct contracts, pks, and vks. Upload the trusted setup artifacts separately. 

Also note that the published version will reference the repo `SP1_CIRCUIT_VERSION` file. 
