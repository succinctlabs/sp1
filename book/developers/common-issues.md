# Alloy Errors

If you are using a library that depends on `alloy_sol_types`, and encounter an error like this:

```
perhaps two different versions of crate `alloy_sol_types` are being used?
```

This is likely due to two different versions of `alloy_sol_types` being used. To fix this, you can set `default-features` to `false` for the `sp1-sdk` dependency in your `Cargo.toml`.

```toml
[dependencies]
sp1-sdk = { version = "0.1.0", default-features = false }
```

This will configure out the `network` feature which will remove the dependency on `alloy_sol_types` 
and configure out the `NetworkProver`.

