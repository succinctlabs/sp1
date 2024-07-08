# Build Script

> WARNING: This may not generate a reproducible ELF which is necessary for verifying that your binary corresponds to given source code.
>
> When building a ELF that will be used in production, make sure to use the [reproduction build system](../writing-programs/setup.md#build-with-docker-production).

If you want your program crate to be built automatically whenever you build/run your script crate, you can add a `build.rs` file inside of `script/` (at the same level as `Cargo.toml`):

```rust,noplayground
{{#include ../../examples/fibonacci/script/build.rs}}
```

Make sure to also add `sp1-helper` as a build dependency in `script/Cargo.toml`:

```toml
[build-dependencies]
sp1-helper = { git = "https://github.com/succinctlabs/sp1.git" }
```

If you run `RUST_LOG=info cargo run --release -vv`, you will see the following output from the build script if the program has changed, indicating that the program was rebuilt:

````
[fibonacci-script 0.1.0] cargo:rerun-if-changed=../program/src
[fibonacci-script 0.1.0] cargo:rerun-if-changed=../program/Cargo.toml
[fibonacci-script 0.1.0] cargo:rerun-if-changed=../program/Cargo.lock
[fibonacci-script 0.1.0] cargo:warning=fibonacci-program built at 2024-03-02 22:01:26
[fibonacci-script 0.1.0] [sp1]    Compiling fibonacci-program v0.1.0 (/Users/umaroy/Documents/fibonacci/program)
[fibonacci-script 0.1.0] [sp1]     Finished release [optimized] target(s) in 0.15s
warning: fibonacci-script@0.1.0: fibonacci-program built at 2024-03-02 22:01:26```
````
