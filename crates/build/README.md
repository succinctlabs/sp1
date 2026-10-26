# sp1-build
Lightweight crate used to build SP1 programs. Internal crate that is exposed to users via `sp1-cli`.

Exposes `build_program`, which builds an SP1 program in the local environment or in a docker container with the specified parameters from `BuildArgs`.

## Usage

```rust
use sp1_build::build_program;

build_program(&BuildArgs::default(), Some(program_dir));
```

## Potential Issues

If you attempt to build a program with Docker that depends on a local crate, and the crate is not in
the current workspace, you may run into issues with the docker build not being able to find the crate, as only the workspace root is mounted.

```
error: failed to load manifest for dependency `...`
```

To fix this, you can either:
1. Move the program into the workspace that contains the crate.
2. Build the crate locally instead.

Adding a new file directly beside an excluded `target/` directory may not trigger a guest rebuild, leaving the previous ELF in use.
Changes within watched directories such as `src/` are still detected.
To force a rebuild, run `cargo clean -p <host-package>` for the package whose build script invokes `sp1-build`, then repeat your build.
